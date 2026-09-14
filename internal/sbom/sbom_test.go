package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBOMHortSPDX(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "bomhort-0.6.1.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != FormatSPDX {
		t.Fatalf("format = %q", doc.Format)
	}
	if len(doc.Components) != 118 {
		t.Fatalf("components = %d, want 118", len(doc.Components))
	}
	byPURL := doc.ByPURL()
	xnet, ok := byPURL["pkg:golang/golang.org/x/net@v0.56.0"]
	if !ok {
		t.Fatal("x/net purl missing")
	}
	if xnet.Name != "golang.org/x/net" || xnet.Version != "v0.56.0" {
		t.Errorf("x/net = %+v", xnet)
	}
	if !strings.Contains(xnet.SourceInfo, "go.mod") {
		t.Errorf("sourceInfo = %q", xnet.SourceInfo)
	}
	// syft dir: scans describe a directory root; the main module is versionless.
	var main Component
	for _, c := range doc.Components {
		if c.Name == "github.com/seebom-labs/bomhort/backend" {
			main = c
		}
	}
	if main.Name == "" || main.Version != "" {
		t.Fatalf("main module = %+v", main)
	}
	if len(doc.RepoHints) == 0 || doc.RepoHints[0] != "https://github.com/seebom-labs/bomhort" {
		t.Fatalf("repo hints = %v", doc.RepoHints)
	}
	if len(doc.PURLs()) < 100 {
		t.Errorf("PURLs = %d", len(doc.PURLs()))
	}
}

func TestParseSPDXDirectDeps(t *testing.T) {
	data := []byte(`{
	  "spdxVersion":"SPDX-2.3","name":"app",
	  "packages":[
	    {"name":"app","SPDXID":"SPDXRef-app","versionInfo":"1.0.0","downloadLocation":"git+https://github.com/acme/app.git",
	     "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/github.com/acme/app@v1.0.0"}]},
	    {"name":"lib","SPDXID":"SPDXRef-lib","versionInfo":"2.0.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/example.com/lib@v2.0.0"}]},
	    {"name":"trans","SPDXID":"SPDXRef-trans","versionInfo":"NOASSERTION","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:golang/example.com/trans@v0.1.0"}]}
	  ],
	  "relationships":[
	    {"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-app","relationshipType":"DESCRIBES"},
	    {"spdxElementId":"SPDXRef-app","relatedSpdxElement":"SPDXRef-lib","relationshipType":"DEPENDS_ON"},
	    {"spdxElementId":"SPDXRef-trans","relatedSpdxElement":"SPDXRef-lib","relationshipType":"DEPENDENCY_OF"}
	  ]}`)
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	m := doc.ByPURL()
	if !m["pkg:golang/github.com/acme/app@v1.0.0"].Root {
		t.Error("app should be root")
	}
	if !m["pkg:golang/example.com/lib@v2.0.0"].Direct {
		t.Error("lib should be direct")
	}
	if m["pkg:golang/example.com/trans@v0.1.0"].Direct {
		t.Error("trans should be transitive")
	}
	if m["pkg:golang/example.com/trans@v0.1.0"].Version != "" {
		t.Error("NOASSERTION version should be cleared")
	}
	if len(doc.RepoHints) != 1 || doc.RepoHints[0] != "https://github.com/acme/app" {
		t.Errorf("hints = %v", doc.RepoHints)
	}
}

func TestParseCycloneDX(t *testing.T) {
	data := []byte(`{
	  "bomFormat":"CycloneDX","specVersion":"1.5",
	  "metadata":{"component":{"bom-ref":"root","name":"svc","version":"3.1.0","purl":"pkg:golang/github.com/acme/svc@v3.1.0",
	    "externalReferences":[{"type":"vcs","url":"git@github.com:acme/svc-mirror.git"}]}},
	  "components":[
	    {"bom-ref":"a","group":"org.example","name":"a","version":"1","purl":"pkg:maven/org.example/a@1"},
	    {"bom-ref":"b","name":"b","version":"2","purl":"pkg:npm/b@2","components":[{"bom-ref":"c","name":"c","version":"3","purl":"pkg:npm/c@3"}]}
	  ],
	  "dependencies":[{"ref":"root","dependsOn":["a"]},{"ref":"a","dependsOn":["b"]}]}`)
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Format != FormatCycloneDX || doc.Name != "svc" {
		t.Fatalf("doc = %+v", doc)
	}
	m := doc.ByPURL()
	if !m["pkg:golang/github.com/acme/svc@v3.1.0"].Root {
		t.Error("root missing")
	}
	if a := m["pkg:maven/org.example/a@1"]; !a.Direct || a.Name != "org.example/a" {
		t.Errorf("a = %+v", a)
	}
	if m["pkg:npm/b@2"].Direct {
		t.Error("b should be transitive")
	}
	if _, ok := m["pkg:npm/c@3"]; !ok {
		t.Error("nested component c missing")
	}
	want := []string{"https://github.com/acme/svc-mirror", "https://github.com/acme/svc"}
	if strings.Join(doc.RepoHints, ",") != strings.Join(want, ",") {
		t.Errorf("hints = %v", doc.RepoHints)
	}
}

func TestParseErrors(t *testing.T) {
	for name, in := range map[string]string{
		"garbage": "not json",
		"unknown": `{"hello":"world"}`,
		"array":   `[1,2]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRepoURLFrom(t *testing.T) {
	cases := map[string]string{
		"https://github.com/acme/app":           "https://github.com/acme/app",
		"git+https://github.com/acme/app.git":   "https://github.com/acme/app",
		"git://github.com/acme/app.git":         "https://github.com/acme/app",
		"git@github.com:acme/app.git":           "https://github.com/acme/app",
		"github.com/acme/app/sub/dir":           "https://github.com/acme/app",
		"https://gitlab.com/grp/proj/-/tree/x":  "https://gitlab.com/grp/proj",
		"https://registry.npmjs.org/x/-/x.tgz":  "",
		"NOASSERTION":                           "",
		"":                                      "",
		"https://github.com/onlyowner":          "",
		"https://github.com/acme/app@v1.2.3":    "https://github.com/acme/app",
		"pkg:golang/github.com/acme/app@v1.0.0": "",
	}
	for in, want := range cases {
		if got := repoURLFrom(in); got != want {
			t.Errorf("repoURLFrom(%q) = %q, want %q", in, got, want)
		}
	}
	if got := repoURLFromPURL("pkg:golang/github.com/acme/app/v2@v2.0.0?x=y#sub"); got != "https://github.com/acme/app" {
		t.Errorf("purl → %q", got)
	}
	if got := repoURLFromPURL("pkg:github/acme/app@abc"); got != "https://github.com/acme/app" {
		t.Errorf("github purl → %q", got)
	}
	if got := repoURLFromPURL("pkg:npm/x@1"); got != "" {
		t.Errorf("npm purl → %q", got)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"a","SPDXID":"x"}]}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX","components":[{"name":"a","purl":"pkg:npm/a@1"}]}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX","metadata":{"component":{"bom-ref":"r"}},"dependencies":[{"ref":"r","dependsOn":["a"]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := Parse(data)
		if err != nil {
			return
		}
		_ = doc.ByPURL()
		_ = doc.PURLs()
	})
}

func TestMainModuleHintsGenericRoot(t *testing.T) {
	raw := `{"spdxVersion":"SPDX-2.3","name":"kubelb",
	"packages":[
	 {"SPDXID":"SPDXRef-Root","name":"kubelb","versionInfo":"1.4.2","downloadLocation":"NOASSERTION","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:generic/kubelb@1.4.2"}]},
	 {"SPDXID":"SPDXRef-A","name":"github.com/kubermatic/kubelb","versionInfo":"v1.4.2","downloadLocation":"NOASSERTION","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:golang/github.com/kubermatic/kubelb@v1.4.2"}]},
	 {"SPDXID":"SPDXRef-B","name":"github.com/other/KubeLB-fork","versionInfo":"v0.1.0","downloadLocation":"NOASSERTION","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:golang/github.com/other/KubeLB-fork@v0.1.0"}]},
	 {"SPDXID":"SPDXRef-C","name":"golang.org/x/net","versionInfo":"v0.1.0","downloadLocation":"NOASSERTION","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:golang/golang.org/x/net@v0.1.0"}]}
	],
	"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-Root","relationshipType":"DESCRIBES"},
	 {"spdxElementId":"SPDXRef-Root","relatedSpdxElement":"SPDXRef-A","relationshipType":"DEPENDS_ON"}]}`
	doc, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.RepoHints) != 1 || doc.RepoHints[0] != "https://github.com/kubermatic/kubelb" {
		t.Fatalf("RepoHints = %v", doc.RepoHints)
	}
	if !doc.ByPURL()["pkg:golang/github.com/kubermatic/kubelb@v1.4.2"].Direct {
		t.Fatal("kubelb module should be direct")
	}
}
