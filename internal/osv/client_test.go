package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func fixtureServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var gets atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		data, err := os.ReadFile(filepath.Join("testdata", r.PathValue("id")+".json"))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &gets
}

func TestGetAndHelpers(t *testing.T) {
	srv, gets := fixtureServer(t)
	c := New(srv.URL, nil)
	ctx := context.Background()

	v, err := c.Get(ctx, "GO-2023-2102")
	if err != nil {
		t.Fatal(err)
	}
	if v.CVE() != "CVE-2023-39325" {
		t.Errorf("CVE = %q", v.CVE())
	}
	if !strings.Contains(v.Summary, "rapid reset") {
		t.Errorf("summary = %q", v.Summary)
	}
	fixed := v.FixedVersions("")
	if len(fixed) != 3 || fixed[0] != "1.20.10" || fixed[2] != "0.17.0" {
		t.Errorf("fixed = %v", fixed)
	}
	if got := v.FixedVersions("pkg:golang/stdlib"); len(got) != 2 {
		t.Errorf("stdlib fixed = %v", got)
	}
	imports := v.VulnerableImports()
	if len(imports) != 2 || imports[0].Path != "net/http" || imports[1].Path != "golang.org/x/net/http2" || len(imports[0].Symbols) == 0 {
		t.Errorf("imports = %+v", imports)
	}
	if fixes := v.ReferenceURLs("FIX"); len(fixes) < 2 || !strings.Contains(fixes[0], "go.dev/cl/") {
		t.Errorf("fix refs = %v", fixes)
	}
	if all := v.ReferenceURLs(); len(all) <= len(v.ReferenceURLs("FIX")) {
		t.Errorf("all refs should be superset")
	}

	// cached
	if _, err := c.Get(ctx, "GO-2023-2102"); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != 1 {
		t.Fatalf("expected cached second Get, gets=%d", gets.Load())
	}

	ghsa, err := c.Get(ctx, "GHSA-4374-p667-p6c8")
	if err != nil {
		t.Fatal(err)
	}
	if got := ghsa.FixedVersions("pkg:golang/golang.org/x/net"); len(got) != 1 || got[0] != "0.17.0" {
		t.Errorf("x/net fixed = %v", got)
	}
	if got := ghsa.FixedVersions("pkg:golang/does/not/exist"); len(got) != 0 {
		t.Errorf("unexpected fixed for other purl: %v", got)
	}

	if _, err := c.Get(ctx, "NOPE-1"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found, got %v", err)
	}
}
