// Package pipeline orchestrates one VEX generation run:
// BOMHort findings → product repo → evidence → assessment → OpenVEX (→ upload).
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/mfahlandt/vexviper/internal/bomhort"
	"github.com/mfahlandt/vexviper/internal/config"
	"github.com/mfahlandt/vexviper/internal/evidence"
	"github.com/mfahlandt/vexviper/internal/llm"
	"github.com/mfahlandt/vexviper/internal/osv"
	"github.com/mfahlandt/vexviper/internal/repo"
	"github.com/mfahlandt/vexviper/internal/source"
	"github.com/mfahlandt/vexviper/internal/vexgen"
)

// Version is stamped by the CLI for the tooling field.
var Version = "dev"

// BOMHortAPI is what the pipeline needs from BOMHort (source.API + upload).
type BOMHortAPI interface {
	source.API
	UploadVEX(ctx context.Context, filename string, doc []byte) (bomhort.UploadResult, error)
}

// Cloner materializes repositories (repo.Cloner or a fake).
type Cloner interface {
	Clone(ctx context.Context, loc repo.Location) (string, error)
}

// Pipeline wires the stages together.
type Pipeline struct {
	Cfg      config.Config
	BOMHort  BOMHortAPI
	Provider llm.Provider
	Cloner   Cloner
	Evidence *evidence.Collector
	Log      *slog.Logger
}

// New builds a pipeline from config with real dependencies.
func New(cfg config.Config, log *slog.Logger) (*Pipeline, error) {
	if log == nil {
		log = slog.Default()
	}
	var opts []bomhort.Option
	if cfg.BOMHort.APIKey != "" {
		opts = append(opts, bomhort.WithAPIKey(cfg.BOMHort.APIKey))
	}
	if cfg.BOMHort.ServiceToken != "" {
		opts = append(opts, bomhort.WithServiceToken(cfg.BOMHort.ServiceToken))
	}
	p := &Pipeline{
		Cfg:     cfg,
		BOMHort: bomhort.New(cfg.BOMHort.URL, opts...),
		Log:     log,
	}
	provider, err := NewProvider(cfg.LLM, log)
	if err != nil {
		return nil, err
	}
	p.Provider = provider
	if cfg.Repo.Clone {
		p.Cloner = &repo.Cloner{CacheDir: cfg.Repo.CacheDir}
	}
	p.Evidence = &evidence.Collector{OSV: osv.New("", nil)}
	if cfg.Repo.Govulncheck {
		p.Evidence.Govulncheck = findGovulncheck()
		if p.Evidence.Govulncheck == "" {
			log.Warn("govulncheck not found in PATH or GOPATH/bin; reachability analysis disabled")
		}
	}
	return p, nil
}

// NewProvider instantiates the configured LLM provider, always wrapped with
// the heuristic fallback so a flaky LLM never aborts a run.
func NewProvider(cfg config.LLM, log *slog.Logger) (llm.Provider, error) {
	var primary llm.Provider
	switch cfg.Provider {
	case config.ProviderHeuristic:
		return llm.Heuristic{}, nil
	case config.ProviderOpenAI:
		primary = &llm.OpenAI{BaseURL: cfg.OpenAI.BaseURL, Model: cfg.OpenAI.Model, APIKey: cfg.OpenAI.APIKey, Temperature: cfg.OpenAI.Temperature, StructuredOutput: true}
		if cfg.OpenAI.Timeout > 0 {
			primary.(*llm.OpenAI).HTTP = &http.Client{Timeout: cfg.OpenAI.Timeout}
		}
	case config.ProviderMCPTool:
		switch cfg.MCP.Transport {
		case config.MCPTransportStdio:
			primary = llm.NewMCPToolStdio(cfg.MCP.Command, cfg.MCP.Args, cfg.MCP.Env, cfg.MCP.Tool, cfg.MCP.Timeout)
		case config.MCPTransportHTTP:
			primary = llm.NewMCPToolHTTP(cfg.MCP.URL, cfg.MCP.Headers, cfg.MCP.Tool, cfg.MCP.Timeout)
		default:
			return nil, fmt.Errorf("unknown mcp transport %q", cfg.MCP.Transport)
		}
	default:
		return nil, fmt.Errorf("unknown llm provider %q", cfg.Provider)
	}
	return llm.WithFallback{Primary: primary, Fallback: llm.Heuristic{}, OnError: func(req llm.Request, err error) {
		log.Warn("llm provider failed, using heuristic fallback", "vuln", req.Report.Finding.VulnID, "purl", req.Report.Finding.PURL, "err", err)
	}}, nil
}

func findGovulncheck() string {
	for _, c := range []string{"govulncheck", filepath.Join(os.Getenv("GOPATH"), "bin", "govulncheck"), filepath.Join(os.Getenv("HOME"), "go", "bin", "govulncheck")} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// RunOptions tunes a single run.
type RunOptions struct {
	// SBOMRef is the SBOM id, document name or source file in BOMHort.
	SBOMRef string
	// RepoOverride forces the product repository.
	RepoOverride string
	// OutDir receives <name>.openvex.json ("" = no file).
	OutDir string
	// Upload pushes the document to BOMHort.
	Upload bool
	// Regenerate includes findings that already have a vex_status.
	Regenerate bool
	// Only restricts to specific vuln IDs (empty = all).
	Only []string
}

// Outcome summarizes a run.
type Outcome struct {
	SBOM        bomhort.SBOM
	Product     source.Product
	RepoDir     string
	RepoHow     string
	Findings    int
	Skipped     int
	Document    []byte
	Filename    string
	Path        string
	Counts      map[vex.Status]int
	Guardrails  []vexgen.Guardrail
	Assessments []AssessmentRecord
	Upload      *bomhort.UploadResult
}

// AssessmentRecord is one finding's verdict for reporting.
type AssessmentRecord struct {
	VulnID     string
	PURL       string
	Status     vex.Status
	Confidence float64
	Provider   string
	Reasoning  string
}

// Run executes the pipeline for one SBOM.
func (p *Pipeline) Run(ctx context.Context, opts RunOptions) (*Outcome, error) {
	if p.Cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.Cfg.Timeout)
		defer cancel()
	}
	log := p.Log
	if log == nil {
		log = slog.Default()
	}

	res, err := source.Load(ctx, p.BOMHort, opts.SBOMRef)
	if err != nil {
		return nil, err
	}
	out := &Outcome{Product: res.Product, SBOM: bomhort.SBOM{ID: res.Product.SBOMID, DocumentName: res.Product.DocumentName, SourceFile: res.Product.SourceFile}}
	log.Info("loaded findings", "sbom", res.Product.SBOMID, "name", res.Product.DocumentName, "findings", len(res.Findings))

	// Filter.
	var findings []source.Finding
	for _, f := range res.Findings {
		if !opts.Regenerate && f.VEXStatus != "" {
			out.Skipped++
			continue
		}
		if len(opts.Only) > 0 && !contains(opts.Only, f.VulnID) {
			out.Skipped++
			continue
		}
		findings = append(findings, f)
	}
	out.Findings = len(findings)

	// Product repository.
	repoDir, how := p.MaterializeRepo(ctx, res.Product, opts.RepoOverride)
	out.RepoDir, out.RepoHow = repoDir, how

	var gvc *evidence.GovulncheckResult
	if repoDir != "" && p.Evidence != nil {
		gvc, err = p.Evidence.RunGovulncheck(ctx, repoDir)
		if err != nil {
			log.Warn("govulncheck failed; continuing without reachability", "err", err)
		} else if gvc != nil {
			log.Info("govulncheck completed", "scan_level", gvc.ScanLevel, "reported", len(gvc.Findings))
		}
	}

	// Assess.
	var entries []vexgen.Entry
	for i, f := range findings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rep := p.Evidence.Collect(ctx, f, repoDir, gvc)
		req := llm.Request{ProductName: productName(res.Product), Report: rep}
		if repoDir != "" {
			req.ProductRepo = how
		}
		a, err := p.Provider.Assess(ctx, req)
		if err != nil {
			log.Error("assessment failed; marking under_investigation", "vuln", f.VulnID, "purl", f.PURL, "err", err)
			a = llm.Assessment{Status: vex.StatusUnderInvestigation, Reasoning: "assessment error: " + err.Error(), Provider: p.Provider.Name()}
		}
		log.Info("assessed", "n", fmt.Sprintf("%d/%d", i+1, len(findings)), "vuln", f.VulnID, "purl", f.PURL, "status", a.Status, "confidence", a.Confidence, "provider", a.Provider)
		entries = append(entries, vexgen.Entry{Report: rep, Assessment: a})
	}

	// Build.
	built, err := vexgen.Build(res.Product.SBOMID, entries, p.VEXOptions(p.Provider.Name()))
	if err != nil {
		return nil, err
	}
	out.Counts, out.Guardrails = built.Counts, built.Guardrails
	for _, s := range built.Document.Statements {
		out.Assessments = append(out.Assessments, AssessmentRecord{VulnID: string(s.Vulnerability.Name), PURL: s.Products[0].ID, Status: s.Status, Reasoning: s.StatusNotes})
	}
	for _, g := range built.Guardrails {
		log.Warn("guardrail applied", "vuln", g.VulnID, "purl", g.PURL, "reason", g.Reason)
	}
	doc, err := vexgen.Marshal(built.Document)
	if err != nil {
		return nil, err
	}
	out.Document = doc
	out.Filename = Filename(res.Product)

	if opts.OutDir != "" {
		if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
			return nil, err
		}
		out.Path = filepath.Join(opts.OutDir, out.Filename)
		if err := os.WriteFile(out.Path, doc, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", out.Path, err)
		}
		log.Info("wrote VEX document", "path", out.Path, "statements", len(built.Document.Statements))
	}

	if opts.Upload {
		if len(built.Document.Statements) == 0 {
			log.Info("nothing to upload: no statements")
		} else {
			r, err := p.BOMHort.UploadVEX(ctx, out.Filename, doc)
			if err != nil {
				return out, fmt.Errorf("upload: %w", err)
			}
			out.Upload = &r
			log.Info("uploaded VEX document to BOMHort", "status", r.Status, "job_id", r.JobID, "sha256", r.SHA256Hash)
		}
	}
	return out, nil
}

// VEXOptions returns the document options derived from config.
func (p *Pipeline) VEXOptions(provider string) vexgen.Options {
	return vexgen.Options{
		Author:                      p.Cfg.VEX.Author,
		AuthorRole:                  p.Cfg.VEX.AuthorRole,
		Supplier:                    p.Cfg.VEX.Supplier,
		Tooling:                     "vexviper/" + Version + " provider=" + provider,
		Namespace:                   p.Cfg.VEX.Namespace,
		MinConfidence:               p.Cfg.LLM.MinConfidence,
		AllowUnsupportedNotAffected: p.Cfg.LLM.AllowUnsupportedNotAffected,
	}
}

// MaterializeRepo resolves and clones the product repository. Order:
// override → config override → SBOM hints → root PURLs. It returns the
// checkout dir ("" if unavailable) and the repository URL it settled on.
func (p *Pipeline) MaterializeRepo(ctx context.Context, prod source.Product, override string) (string, string) {
	log := p.Log
	if log == nil {
		log = slog.Default()
	}
	var candidates []repo.Location
	if override == "" {
		override = p.Cfg.Repo.Override
	}
	if loc, ok := repo.FromOverride(override); ok {
		candidates = append(candidates, loc)
	} else if override != "" {
		log.Warn("repo override not understood", "override", override)
	}
	fallbackRef := VersionFromName(prod.SourceFile, prod.DocumentName)
	for _, h := range prod.RepoHints {
		if loc, ok := repo.FromOverride(h); ok {
			loc.How = "sbom"
			if loc.Ref == "" {
				loc.Ref = fallbackRef
			}
			candidates = append(candidates, loc)
		}
	}
	for _, purl := range prod.RootPURLs {
		if loc, ok := repo.FromPURL(purl); ok {
			loc.How = "root-purl"
			if loc.Ref == "" {
				loc.Ref = fallbackRef
			}
			candidates = append(candidates, loc)
		}
	}
	if len(candidates) == 0 {
		log.Info("no product repository could be determined; pass --repo to enable code analysis", "sbom", prod.SBOMID)
		return "", ""
	}
	if p.Cloner == nil {
		return "", candidates[0].URL
	}
	var errs []error
	for _, c := range candidates {
		dir, err := p.Cloner.Clone(ctx, c)
		if err == nil {
			log.Info("product repository ready", "url", c.URL, "ref", c.Ref, "via", c.How, "dir", dir)
			return dir, c.URL
		}
		errs = append(errs, err)
	}
	log.Warn("could not clone any product repository candidate", "err", errors.Join(errs...))
	return "", ""
}

var versionRE = regexp.MustCompile(`[-_@ ]v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?:[._-]|$)`)

// VersionFromName extracts a semantic version from SBOM file/document names
// such as "bomhort-0.6.1.spdx.json" or "kubermatic_kubelb_1.4.2.spdx.json"
// and returns it as a "v"-prefixed git ref candidate ("" if none).
func VersionFromName(names ...string) string {
	for _, n := range names {
		n = filepath.Base(n)
		for _, suf := range []string{".spdx.json", ".cdx.json", ".json", ".spdx", ".cdx"} {
			n = strings.TrimSuffix(n, suf)
		}
		if m := versionRE.FindStringSubmatch(n); m != nil {
			return "v" + m[1]
		}
	}
	return ""
}

// Filename derives the companion OpenVEX file name for an SBOM.
func Filename(prod source.Product) string {
	base := filepath.Base(prod.SourceFile)
	if base == "" || base == "." {
		base = prod.DocumentName
	}
	if base == "" || base == "." {
		base = prod.SBOMID
	}
	for _, suf := range []string{".spdx.json", ".cdx.json", ".json", ".spdx", ".cdx"} {
		base = strings.TrimSuffix(base, suf)
	}
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			return r
		}
		return '-'
	}, base)
	if base == "" || base == "." {
		base = "vex"
	}
	return base + ".vexviper.openvex.json"
}

func productName(p source.Product) string {
	switch {
	case p.DocumentName != "" && p.DocumentName != ".":
		return p.DocumentName
	case p.SourceFile != "":
		return p.SourceFile
	}
	return p.SBOMID
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// Wait polls BOMHort until statements from the uploaded document are
// visible or the timeout expires. It is used by the CLI (--wait) and E2E.
func (p *Pipeline) Wait(ctx context.Context, docID string, timeout time.Duration, statements func(ctx context.Context) ([]bomhort.VEXStatement, error)) error {
	deadline := time.Now().Add(timeout)
	for {
		list, err := statements(ctx)
		if err == nil {
			for _, s := range list {
				if s.DocumentID == docID {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for VEX document %s to be ingested", docID)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
