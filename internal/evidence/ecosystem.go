package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/seebom-labs/vexviper/internal/source"
)

// Non-Go ecosystems have no govulncheck. What can still be established
// deterministically from the product checkout:
//
//   - is the package declared in a manifest (direct) or only in a lockfile
//     (transitive), and is it a development-only dependency?
//   - does product source code import/require the package at all?
//
// None of this proves reachability of the vulnerable code, so the resulting
// evidence is never Strong; it narrows the question for the model and the
// reviewer instead of leaving every npm/pypi finding at "insufficient evidence".

// Additional evidence kinds produced by the ecosystem scan.
const (
	KindDevDependency    Kind = "dev_dependency"     // declared only under dev/test dependencies
	KindPackageImported  Kind = "package_imported"   // product source imports/requires the package
	KindManifestNotFound Kind = "manifest_not_found" // package appears in no manifest or lockfile of the checkout
)

// ecosystemSpec describes how to find a package in one ecosystem's checkout.
type ecosystemSpec struct {
	// manifests declare direct dependencies; devKey/devSection mark dev-only.
	manifests []string
	// lockfiles list the full dependency closure.
	lockfiles []string
	// sourceExts are scanned for imports.
	sourceExts []string
	// importPatterns builds regexes matching an import of the package name.
	importPatterns func(name string) []*regexp.Regexp
	// manifestDecl reports whether name is declared in the manifest content and
	// whether it is dev-only.
	manifestDecl func(content []byte, name string) (declared, devOnly bool)
}

var ecosystems = map[string]ecosystemSpec{
	"npm": {
		manifests:  []string{"package.json"},
		lockfiles:  []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"},
		sourceExts: []string{".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".vue", ".svelte"},
		importPatterns: func(name string) []*regexp.Regexp {
			q := regexp.QuoteMeta(name)
			// import x from 'name' | import 'name/sub' | require("name") | import("name")
			return []*regexp.Regexp{
				regexp.MustCompile(`(?m)\bfrom\s+['"]` + q + `(/[^'"]*)?['"]`),
				regexp.MustCompile(`(?m)\bimport\s*\(?\s*['"]` + q + `(/[^'"]*)?['"]`),
				regexp.MustCompile(`(?m)\brequire\s*\(\s*['"]` + q + `(/[^'"]*)?['"]`),
			}
		},
		manifestDecl: npmManifestDecl,
	},
	"pypi": {
		manifests:  []string{"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "dev-requirements.txt", "requirements/base.txt", "requirements/dev.txt", "requirements/test.txt", "Pipfile"},
		lockfiles:  []string{"poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.lock"},
		sourceExts: []string{".py", ".pyi"},
		importPatterns: func(name string) []*regexp.Regexp {
			var res []*regexp.Regexp
			for _, mod := range pythonModules(name) {
				q := regexp.QuoteMeta(mod)
				res = append(res,
					regexp.MustCompile(`(?m)^\s*import\s+`+q+`\b`),
					regexp.MustCompile(`(?m)^\s*from\s+`+q+`(\.|\s)`),
				)
			}
			return res
		},
		manifestDecl: pypiManifestDecl,
	},
	"cargo": {
		manifests:  []string{"Cargo.toml"},
		lockfiles:  []string{"Cargo.lock"},
		sourceExts: []string{".rs"},
		importPatterns: func(name string) []*regexp.Regexp {
			q := regexp.QuoteMeta(strings.ReplaceAll(name, "-", "_"))
			return []*regexp.Regexp{
				regexp.MustCompile(`(?m)\buse\s+` + q + `(::|;|\s)`),
				regexp.MustCompile(`(?m)\bextern\s+crate\s+` + q + `\b`),
				regexp.MustCompile(`(?m)\b` + q + `::`),
			}
		},
		manifestDecl: tomlDepDecl,
	},
	"gem": {
		manifests:  []string{"Gemfile"},
		lockfiles:  []string{"Gemfile.lock"},
		sourceExts: []string{".rb"},
		importPatterns: func(name string) []*regexp.Regexp {
			q := regexp.QuoteMeta(name)
			return []*regexp.Regexp{regexp.MustCompile(`(?m)\brequire\s+['"]` + q + `(/[^'"]*)?['"]`)}
		},
		manifestDecl: func(content []byte, name string) (bool, bool) {
			re := regexp.MustCompile(`(?m)^\s*gem\s+['"]` + regexp.QuoteMeta(name) + `['"]`)
			return re.Match(content), false
		},
	},
	"composer": {
		manifests:  []string{"composer.json"},
		lockfiles:  []string{"composer.lock"},
		sourceExts: nil, // PHP namespaces do not map to package names
		manifestDecl: func(content []byte, name string) (bool, bool) {
			var m struct {
				Require    map[string]string `json:"require"`
				RequireDev map[string]string `json:"require-dev"`
			}
			if json.Unmarshal(content, &m) != nil {
				return bytes.Contains(content, []byte(`"`+name+`"`)), false
			}
			_, prod := m.Require[name]
			_, dev := m.RequireDev[name]
			return prod || dev, dev && !prod
		},
	},
	"maven": {
		manifests: []string{"pom.xml", "build.gradle", "build.gradle.kts"},
		lockfiles: []string{"gradle.lockfile"},
		manifestDecl: func(content []byte, name string) (bool, bool) {
			// name is groupId/artifactId; pom uses separate elements, gradle "group:artifact".
			group, artifact, _ := strings.Cut(name, "/")
			if artifact == "" {
				artifact = group
			}
			return bytes.Contains(content, []byte("<artifactId>"+artifact+"</artifactId>")) ||
				bytes.Contains(content, []byte(group+":"+artifact)), false
		},
	},
}

// ecosystemEvidence scans repoDir for how the finding's package is declared
// and used. It returns nil for ecosystems it does not know.
func (c *Collector) ecosystemEvidence(repoDir string, f source.Finding) []Item {
	if repoDir == "" {
		return nil
	}
	eco := ecosystem(f.PURL)
	spec, ok := ecosystems[eco]
	if !ok {
		return nil
	}
	name := purlName(f.PURL)
	if name == "" {
		return nil
	}
	maxFiles := c.MaxGrepFiles
	if maxFiles <= 0 {
		maxFiles = 5000
	}

	var (
		declaredIn, devIn, lockedIn []string
		importHits                  = map[string][]string{}
		importCount                 int
		patterns                    []*regexp.Regexp
		exts                        = map[string]bool{}
		files                       int
	)
	if spec.importPatterns != nil {
		patterns = spec.importPatterns(name)
	}
	for _, e := range spec.sourceExts {
		exts[e] = true
	}
	manifests := map[string]bool{}
	for _, m := range spec.manifests {
		manifests[filepath.Base(m)] = true
	}
	lockfiles := map[string]bool{}
	for _, l := range spec.lockfiles {
		lockfiles[l] = true
	}

	_ = filepath.WalkDir(repoDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata", "dist", "build", ".venv", "venv", "site-packages", "target", "__pycache__":
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(repoDir, path)
		base := d.Name()
		switch {
		case manifests[base] || (eco == "pypi" && strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")):
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if declared, dev := spec.manifestDecl(data, name); declared {
				declaredIn = appendLimited(declaredIn, rel)
				if dev || isDevManifest(rel) {
					devIn = appendLimited(devIn, rel)
				}
			}
		case lockfiles[base]:
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if lockfileContains(data, eco, name) {
				lockedIn = appendLimited(lockedIn, rel)
			}
		case len(patterns) > 0 && exts[filepath.Ext(base)]:
			files++
			if files > maxFiles {
				return filepath.SkipAll
			}
			if isTestPath(rel) {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, re := range patterns {
				if re.Match(data) {
					importHits[name] = appendLimited(importHits[name], rel)
					importCount++
					break
				}
			}
		}
		return nil
	})

	var items []Item
	switch {
	case len(declaredIn) > 0 && len(devIn) == len(declaredIn):
		items = append(items, Item{Kind: KindDevDependency, Summary: fmt.Sprintf("%s is declared only as a development/test dependency (%s); it is not part of the product's runtime dependency set", name, strings.Join(devIn, ", ")), Details: map[string]any{"manifests": devIn}})
		items = append(items, Item{Kind: KindDirectDependency, Summary: fmt.Sprintf("%s is declared in %s", name, strings.Join(declaredIn, ", ")), Details: map[string]any{"manifests": declaredIn}})
	case len(declaredIn) > 0:
		items = append(items, Item{Kind: KindDirectDependency, Summary: fmt.Sprintf("%s is a direct dependency declared in %s", name, strings.Join(declaredIn, ", ")), Details: map[string]any{"manifests": declaredIn}})
	case len(lockedIn) > 0:
		items = append(items, Item{Kind: KindTransitive, Summary: fmt.Sprintf("%s appears only in lockfile(s) %s, i.e. it is a transitive dependency", name, strings.Join(lockedIn, ", ")), Details: map[string]any{"lockfiles": lockedIn}})
	default:
		items = append(items, Item{Kind: KindManifestNotFound, Summary: fmt.Sprintf("%s is not declared in any %s manifest or lockfile of the checkout (bundled, vendored or from a different build context?)", name, eco)})
	}

	if len(patterns) > 0 {
		if importCount > 0 {
			files := importHits[name]
			items = append(items, Item{Kind: KindPackageImported, Summary: fmt.Sprintf("product source imports %s in %d file(s), e.g. %s", name, importCount, strings.Join(files, ", ")), Details: map[string]any{"files": files, "count": importCount}})
		} else {
			items = append(items, Item{Kind: KindImportNotFound, Summary: fmt.Sprintf("no product source file (%s) imports %s directly (transitive use still possible)", strings.Join(spec.sourceExts, " "), name)})
		}
	}
	return items
}

// purlName extracts the ecosystem package name from a PURL:
// pkg:npm/%40scope/name@1.0.0 → @scope/name, pkg:maven/g/a@1 → g/a.
func purlName(purl string) string {
	s := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	} else {
		return ""
	}
	for _, sep := range []string{"?", "#"} {
		if j := strings.Index(s, sep); j >= 0 {
			s = s[:j]
		}
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		s = s[:i]
	}
	if u, err := url.PathUnescape(s); err == nil {
		s = u
	}
	return s
}

func isDevManifest(rel string) bool {
	b := strings.ToLower(filepath.Base(rel))
	return strings.Contains(b, "dev") || strings.Contains(b, "test")
}

func isTestPath(rel string) bool {
	l := strings.ToLower(rel)
	for _, seg := range strings.Split(l, string(filepath.Separator)) {
		switch seg {
		case "test", "tests", "__tests__", "spec", "specs", "e2e", "cypress":
			return true
		}
	}
	base := filepath.Base(l)
	return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.HasPrefix(base, "test_") || strings.HasSuffix(strings.TrimSuffix(base, filepath.Ext(base)), "_test")
}

func npmManifestDecl(content []byte, name string) (bool, bool) {
	var m struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if json.Unmarshal(content, &m) != nil {
		return bytes.Contains(content, []byte(`"`+name+`"`)), false
	}
	_, prod := m.Dependencies[name]
	_, peer := m.PeerDependencies[name]
	_, opt := m.OptionalDependencies[name]
	_, dev := m.DevDependencies[name]
	runtime := prod || peer || opt
	return runtime || dev, dev && !runtime
}

// pypiNameRE matches a requirement line / TOML dependency string for name.
func pypiDeclRE(name string) *regexp.Regexp {
	// PEP 503 normalisation: -, _ and . are interchangeable, case-insensitive.
	norm := regexp.MustCompile(`[-_.]+`).ReplaceAllString(regexp.QuoteMeta(name), `[-_.]+`)
	return regexp.MustCompile(`(?im)(^|["'\s=])` + norm + `\s*([<>=!~\[;@ ]|$|["'])`)
}

func pypiManifestDecl(content []byte, name string) (bool, bool) {
	re := pypiDeclRE(name)
	if !re.Match(content) {
		return false, false
	}
	// Dev-only when every match sits in a dev/test group of pyproject/Pipfile.
	dev := true
	section := ""
	for _, line := range strings.Split(string(content), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(t)
			continue
		}
		if re.MatchString(line) {
			if !isDevSection(section) {
				dev = false
			}
		}
	}
	return true, dev && section != ""
}

func isDevSection(section string) bool {
	return strings.Contains(section, "dev") || strings.Contains(section, "test") || strings.Contains(section, "lint") || strings.Contains(section, "docs")
}

func tomlDepDecl(content []byte, name string) (bool, bool) {
	re := regexp.MustCompile(`(?m)^\s*"?` + regexp.QuoteMeta(name) + `"?\s*=`)
	if !re.Match(content) {
		return false, false
	}
	dev, section := true, ""
	for _, line := range strings.Split(string(content), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(t)
			continue
		}
		if re.MatchString(line) && !(strings.Contains(section, "dev-dependencies") || strings.Contains(section, "build-dependencies")) {
			dev = false
		}
	}
	return true, dev && section != ""
}

func lockfileContains(data []byte, eco, name string) bool {
	switch eco {
	case "npm":
		return bytes.Contains(data, []byte(`"node_modules/`+name+`"`)) || // package-lock v2/v3
			bytes.Contains(data, []byte(`"`+name+`": {`)) || // package-lock v1
			bytes.Contains(data, []byte("\n"+name+"@")) || bytes.Contains(data, []byte(`"`+name+`@`)) || // yarn
			bytes.Contains(data, []byte("  /"+name+"@")) || bytes.Contains(data, []byte("  "+name+"@")) // pnpm
	case "pypi":
		return pypiDeclRE(name).Match(data)
	case "cargo":
		return bytes.Contains(data, []byte(`name = "`+name+`"`))
	case "gem":
		return regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(name) + ` \(`).Match(data)
	default:
		return bytes.Contains(data, []byte(name))
	}
}

// pythonModules maps a distribution name to the import names it provides.
func pythonModules(dist string) []string {
	l := strings.ToLower(dist)
	if mods, ok := pythonImportNames[l]; ok {
		return mods
	}
	mods := []string{strings.ReplaceAll(strings.ReplaceAll(l, "-", "_"), ".", "_")}
	if strings.HasPrefix(l, "python-") {
		mods = append(mods, strings.ReplaceAll(strings.TrimPrefix(l, "python-"), "-", "_"))
	}
	if strings.HasPrefix(l, "py") && len(l) > 2 {
		mods = append(mods, strings.ReplaceAll(l[2:], "-", "_"))
	}
	sort.Strings(mods)
	return mods
}

// Distribution → import name for common packages where they differ.
var pythonImportNames = map[string][]string{
	"pyyaml":                   {"yaml"},
	"pillow":                   {"PIL"},
	"beautifulsoup4":           {"bs4"},
	"scikit-learn":             {"sklearn"},
	"python-dateutil":          {"dateutil"},
	"opencv-python":            {"cv2"},
	"protobuf":                 {"google.protobuf"},
	"attrs":                    {"attr", "attrs"},
	"msgpack-python":           {"msgpack"},
	"pycryptodome":             {"Crypto"},
	"pycryptodomex":            {"Cryptodome"},
	"cryptography":             {"cryptography"},
	"pyjwt":                    {"jwt"},
	"python-jose":              {"jose"},
	"markupsafe":               {"markupsafe"},
	"jinja2":                   {"jinja2"},
	"pyopenssl":                {"OpenSSL"},
	"setuptools":               {"setuptools", "pkg_resources"},
	"gitpython":                {"git"},
	"django":                   {"django"},
	"psycopg2-binary":          {"psycopg2"},
	"mysqlclient":              {"MySQLdb"},
	"pymongo":                  {"pymongo", "bson", "gridfs"},
	"python-multipart":         {"multipart", "python_multipart"},
	"typing-extensions":        {"typing_extensions"},
	"importlib-metadata":       {"importlib_metadata"},
	"grpcio":                   {"grpc"},
	"google-api-python-client": {"googleapiclient"},
	"ruamel.yaml":              {"ruamel.yaml"},
	"zope.interface":           {"zope.interface"},
	"aiohttp":                  {"aiohttp"},
	"tornado":                  {"tornado"},
	"twisted":                  {"twisted"},
	"lxml":                     {"lxml"},
	"certifi":                  {"certifi"},
	"urllib3":                  {"urllib3"},
	"requests":                 {"requests"},
	"idna":                     {"idna"},
	"werkzeug":                 {"werkzeug"},
	"flask":                    {"flask"},
	"sqlalchemy":               {"sqlalchemy"},
	"paramiko":                 {"paramiko"},
	"ansible-core":             {"ansible"},
}
