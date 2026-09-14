package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/mfahlandt/vexviper/internal/bomhort"
	"github.com/mfahlandt/vexviper/internal/config"
	"github.com/mfahlandt/vexviper/internal/evidence"
	"github.com/mfahlandt/vexviper/internal/llm"
	"github.com/mfahlandt/vexviper/internal/repo"
	"github.com/mfahlandt/vexviper/internal/source"
)

type fakeBOMHort struct {
	sbom     bomhort.SBOM
	vulns    []bomhort.Vulnerability
	deps     []bomhort.DependencyNode
	raw      []byte
	uploads  []string
	uploaded [][]byte
	upErr    error
}

func (f *fakeBOMHort) FindSBOM(_ context.Context, ref string) (bomhort.SBOM, error) {
	if ref != f.sbom.ID && ref != f.sbom.DocumentName {
		return bomhort.SBOM{}, errors.New("not found")
	}
	return f.sbom, nil
}
func (f *fakeBOMHort) Vulnerabilities(context.Context, string) ([]bomhort.Vulnerability, error) {
	return f.vulns, nil
}
func (f *fakeBOMHort) Dependencies(context.Context, string) ([]bomhort.DependencyNode, error) {
	return f.deps, nil
}
func (f *fakeBOMHort) DownloadSBOM(context.Context, string) ([]byte, error) { return f.raw, nil }
func (f *fakeBOMHort) UploadVEX(_ context.Context, name string, doc []byte) (bomhort.UploadResult, error) {
	if f.upErr != nil {
		return bomhort.UploadResult{}, f.upErr
	}
	f.uploads = append(f.uploads, name)
	f.uploaded = append(f.uploaded, doc)
	return bomhort.UploadResult{Status: "pending", JobID: "job-1", JobType: "vex"}, nil
}

type fakeCloner struct {
	dir  string
	locs []repo.Location
	err  error
}

func (c *fakeCloner) Clone(_ context.Context, loc repo.Location) (string, error) {
	c.locs = append(c.locs, loc)
	return c.dir, c.err
}

func newTestPipeline(t *testing.T, bh *fakeBOMHort, prov llm.Provider, cl Cloner) *Pipeline {
	t.Helper()
	cfg := config.Default()
	cfg.Repo.Clone = cl != nil
	cfg.Repo.Govulncheck = false
	return &Pipeline{
		Cfg:      cfg,
		BOMHort:  bh,
		Provider: prov,
		Cloner:   cl,
		Evidence: &evidence.Collector{}, // no OSV → offline
		Log:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}
}

func bomhortFixture(t *testing.T) *fakeBOMHort {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "bomhort-0.6.1.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeBOMHort{
		sbom: bomhort.SBOM{ID: "sbom-1", DocumentName: ".", SourceFile: "bomhort-0.6.1.spdx.json"},
		vulns: []bomhort.Vulnerability{
			{VulnID: "GO-2025-0001", PURL: "pkg:golang/golang.org/x/net@v0.30.0", Severity: "HIGH", FixedVersion: "v0.31.0"},
			{VulnID: "GO-2025-0002", PURL: "pkg:golang/github.com/foo/bar@v1.2.3", Severity: "LOW"},
			{VulnID: "GO-2025-0003", PURL: "pkg:golang/github.com/baz/qux@v2.0.0", Severity: "MEDIUM", VEXStatus: "not_affected"},
		},
		raw: raw,
	}
}

func TestRunWritesDocumentAndUploads(t *testing.T) {
	bh := bomhortFixture(t)
	mock := &llm.Mock{
		ByVulnID: map[string]llm.Assessment{
			"GO-2025-0001": {Status: vex.StatusAffected, ActionStatement: "upgrade to v0.31.0", Confidence: 0.9, Reasoning: "outdated"},
			"GO-2025-0002": {Status: vex.StatusNotAffected, Justification: vex.VulnerableCodeNotInExecutePath, Confidence: 0.95, Reasoning: "unsupported claim"},
		},
	}
	cl := &fakeCloner{dir: t.TempDir()}
	p := newTestPipeline(t, bh, mock, cl)

	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", OutDir: t.TempDir(), Upload: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings != 2 || out.Skipped != 1 {
		t.Fatalf("findings=%d skipped=%d, want 2/1", out.Findings, out.Skipped)
	}
	if len(mock.Calls) != 2 {
		t.Fatalf("provider called %d times", len(mock.Calls))
	}
	// Repo resolved from SBOM hints of the BOMHort SBOM.
	if len(cl.locs) == 0 || cl.locs[0].URL != "https://github.com/seebom-labs/bomhort" || cl.locs[0].Ref != "v0.6.1" {
		t.Fatalf("cloner locs = %+v", cl.locs)
	}
	if out.RepoDir != cl.dir {
		t.Fatalf("RepoDir = %q", out.RepoDir)
	}
	if _, err := os.Stat(out.Path); err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	if out.Filename != "bomhort-0.6.1.vexviper.openvex.json" {
		t.Fatalf("filename = %q", out.Filename)
	}
	if len(bh.uploads) != 1 || bh.uploads[0] != out.Filename {
		t.Fatalf("uploads = %v", bh.uploads)
	}
	if out.Upload == nil || out.Upload.JobID != "job-1" {
		t.Fatalf("upload result = %+v", out.Upload)
	}

	var doc vex.VEX
	if err := json.Unmarshal(out.Document, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d", len(doc.Statements))
	}
	byVuln := map[string]vex.Statement{}
	for _, s := range doc.Statements {
		byVuln[string(s.Vulnerability.Name)] = s
	}
	if s := byVuln["GO-2025-0001"]; s.Status != vex.StatusAffected || s.Products[0].ID != "pkg:golang/golang.org/x/net@v0.30.0" {
		t.Errorf("GO-2025-0001 = %+v", s)
	}
	// not_affected without strong evidence must be downgraded by the guardrail.
	if s := byVuln["GO-2025-0002"]; s.Status != vex.StatusUnderInvestigation {
		t.Errorf("GO-2025-0002 status = %s, want under_investigation (guardrail)", s.Status)
	}
	if len(out.Guardrails) != 1 {
		t.Errorf("guardrails = %+v", out.Guardrails)
	}
}

func TestRunRegenerateOnlyAndOverride(t *testing.T) {
	bh := bomhortFixture(t)
	mock := &llm.Mock{Default: &llm.Assessment{Status: vex.StatusUnderInvestigation, Confidence: 0.5}}
	cl := &fakeCloner{dir: t.TempDir()}
	p := newTestPipeline(t, bh, mock, cl)

	out, err := p.Run(context.Background(), RunOptions{SBOMRef: ".", Regenerate: true, Only: []string{"go-2025-0003"}, RepoOverride: "acme/product"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Findings != 1 || out.Skipped != 2 {
		t.Fatalf("findings=%d skipped=%d", out.Findings, out.Skipped)
	}
	if cl.locs[0].URL != "https://github.com/acme/product" || cl.locs[0].How != "override" {
		t.Fatalf("override not preferred: %+v", cl.locs[0])
	}
	if out.Path != "" {
		t.Fatalf("no OutDir but Path=%q", out.Path)
	}
	if out.Counts[vex.StatusUnderInvestigation] != 1 {
		t.Fatalf("counts = %v", out.Counts)
	}
}

func TestRunCloneFailureDegrades(t *testing.T) {
	bh := bomhortFixture(t)
	cl := &fakeCloner{err: errors.New("git: boom")}
	p := newTestPipeline(t, bh, llm.Heuristic{}, cl)

	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.RepoDir != "" {
		t.Fatalf("expected no repo dir, got %q", out.RepoDir)
	}
	if len(out.Assessments) != 2 {
		t.Fatalf("assessments = %d", len(out.Assessments))
	}
	// heuristic without code evidence is conservative: everything stays under_investigation
	for _, a := range out.Assessments {
		if a.Status != vex.StatusUnderInvestigation {
			t.Fatalf("%s status = %s", a.VulnID, a.Status)
		}
	}
	if out.Counts[vex.StatusUnderInvestigation] != 2 {
		t.Fatalf("counts = %v", out.Counts)
	}
}

func TestRunNoCloner(t *testing.T) {
	bh := bomhortFixture(t)
	p := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.RepoDir != "" || out.RepoHow != "https://github.com/seebom-labs/bomhort" {
		t.Fatalf("RepoDir=%q RepoHow=%q", out.RepoDir, out.RepoHow)
	}
}

func TestRunProviderErrorIsSurvivable(t *testing.T) {
	bh := bomhortFixture(t)
	p := newTestPipeline(t, bh, &llm.Mock{Err: errors.New("llm down")}, nil)
	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range out.Assessments {
		if a.Status != vex.StatusUnderInvestigation {
			t.Fatalf("%s status = %s", a.VulnID, a.Status)
		}
	}
}

func TestRunUploadErrorReturnsOutcome(t *testing.T) {
	bh := bomhortFixture(t)
	bh.upErr = errors.New("401")
	p := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	out, err := p.Run(context.Background(), RunOptions{SBOMRef: "sbom-1", Upload: true})
	if err == nil || out == nil || len(out.Document) == 0 {
		t.Fatalf("err=%v out=%v", err, out)
	}
}

func TestRunUnknownSBOM(t *testing.T) {
	p := newTestPipeline(t, bomhortFixture(t), llm.Heuristic{}, nil)
	if _, err := p.Run(context.Background(), RunOptions{SBOMRef: "nope"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestFilename(t *testing.T) {
	cases := []struct {
		p    source.Product
		want string
	}{
		{source.Product{SourceFile: "dir/bomhort-0.6.1.spdx.json"}, "bomhort-0.6.1.vexviper.openvex.json"},
		{source.Product{DocumentName: "my app/v1"}, "my-app-v1.vexviper.openvex.json"},
		{source.Product{SBOMID: "abc"}, "abc.vexviper.openvex.json"},
		{source.Product{DocumentName: "."}, "vex.vexviper.openvex.json"},
		{source.Product{SourceFile: "x.cdx.json"}, "x.vexviper.openvex.json"},
	}
	for _, c := range cases {
		if got := Filename(c.p); got != c.want {
			t.Errorf("Filename(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestVersionFromName(t *testing.T) {
	cases := map[string]string{
		"bomhort-0.6.1.spdx.json":                       "v0.6.1",
		"kubermatic_kubelb_1.4.2.spdx.json":             "v1.4.2",
		"dir/agones_1_57_0_spdx.json":                   "",
		"app-v2.0.0-rc.1.cdx.json":                      "v2.0.0-rc.1",
		"github.com/seebom-labs/bomhort/backend":        "",
		"other.spdx.json":                               "",
		"kubermatic_developer-platform_0.9.0.spdx.json": "v0.9.0",
	}
	for in, want := range cases {
		if got := VersionFromName(in); got != want {
			t.Errorf("VersionFromName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := VersionFromName("", "x-1.2.3"); got != "v1.2.3" {
		t.Errorf("second name: %q", got)
	}
}

func TestNewProvider(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cases := []struct {
		cfg     config.LLM
		wantErr bool
		name    string
	}{
		{config.LLM{Provider: config.ProviderHeuristic}, false, "heuristic"},
		{config.LLM{Provider: config.ProviderOpenAI, OpenAI: config.OpenAI{Model: "m"}}, false, "openai:m+heuristic"},
		{config.LLM{Provider: config.ProviderMCPTool, MCP: config.MCP{Transport: config.MCPTransportStdio, Tool: "t"}}, false, "mcptool:t+heuristic"},
		{config.LLM{Provider: config.ProviderMCPTool, MCP: config.MCP{Transport: config.MCPTransportHTTP, Tool: "t"}}, false, "mcptool:t+heuristic"},
		{config.LLM{Provider: config.ProviderMCPTool, MCP: config.MCP{Transport: "carrier-pigeon"}}, true, ""},
		{config.LLM{Provider: "nope"}, true, ""},
	}
	for _, c := range cases {
		p, err := NewProvider(c.cfg, log)
		if (err != nil) != c.wantErr {
			t.Fatalf("%+v: err=%v", c.cfg, err)
		}
		if err == nil && p.Name() != c.name {
			t.Errorf("name = %q want %q", p.Name(), c.name)
		}
	}
}

func TestNewFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Repo.CacheDir = t.TempDir()
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Cloner == nil || p.Evidence == nil || p.Provider == nil {
		t.Fatalf("pipeline not fully wired: %+v", p)
	}
	cfg.Repo.Clone = false
	p, _ = New(cfg, nil)
	if p.Cloner != nil {
		t.Fatal("cloner should be nil when clone disabled")
	}
}
