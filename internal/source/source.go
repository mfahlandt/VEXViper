// Package source turns BOMHort API data for one SBOM into the Finding list
// the rest of the pipeline works on. BOMHort is the single source of truth
// for vulnerabilities; the raw SBOM is only consulted for repository hints
// and to distinguish direct from transitive dependencies.
package source

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	bomhort "github.com/seebom-labs/bomhort-go"

	"github.com/seebom-labs/vexviper/internal/sbom"
)

// Finding is one (vulnerability, package) pair as BOMHort reports it. VulnID
// and PURL are kept verbatim because BOMHort matches VEX statements on exact
// string equality of both.
type Finding struct {
	VulnID       string
	PURL         string
	Severity     string
	Summary      string
	FixedVersion string
	// VEXStatus is the status BOMHort already applies from ingested VEX (empty if none).
	VEXStatus string
	// VEXTimestamp is the timestamp of the effective statement behind
	// VEXStatus (BOMHort #335); empty on BOMHort <= 0.6.1.
	VEXTimestamp string
	// VEXTooling is the tooling field of the effective statement (BOMHort
	// #334); VEXViper's own statements start with "vexviper/".
	VEXTooling string
	// Aliases are the other OSV ids of the same flaw (BOMHort >= 0.8, #412).
	Aliases []string
	// Direct is true when the package is a direct dependency of the product.
	Direct bool
	// DirectKnown is false when the SBOM carries no relationship data at all.
	DirectKnown bool
	// PackageName and PackageVersion are taken from the dependency tree when available.
	PackageName    string
	PackageVersion string
}

// Product describes the SBOM under analysis.
type Product struct {
	SBOMID       string
	DocumentName string
	SourceFile   string
	// SourceRepo and SourceRef are BOMHort's first-class source repository
	// attributes for the SBOM (#332); empty when unknown.
	SourceRepo string
	SourceRef  string
	// RepoHints are candidate source repositories for the product, best first.
	RepoHints []string
	// RootPURLs are the PURLs of the components the SBOM describes, if any.
	RootPURLs []string
}

// Result bundles the product with its findings.
type Result struct {
	Product  Product
	Findings []Finding
}

// API is the subset of bomhort.Client the source needs (for tests).
type API interface {
	FindSBOM(ctx context.Context, ref string) (bomhort.SBOM, error)
	Vulnerabilities(ctx context.Context, sbomID string) ([]bomhort.Vulnerability, error)
	Dependencies(ctx context.Context, sbomID string) ([]bomhort.DependencyNode, error)
	DownloadSBOM(ctx context.Context, sbomID string) ([]byte, error)
}

// Load resolves ref (SBOM id, document name or source file) and collects findings.
func Load(ctx context.Context, api API, ref string) (*Result, error) {
	s, err := api.FindSBOM(ctx, ref)
	if err != nil {
		return nil, err
	}
	return LoadSBOM(ctx, api, s)
}

// LoadSBOM collects findings for an already-resolved SBOM.
func LoadSBOM(ctx context.Context, api API, s bomhort.SBOM) (*Result, error) {
	vulns, err := api.Vulnerabilities(ctx, s.ID)
	if err != nil {
		return nil, fmt.Errorf("source: vulnerabilities of %s: %w", s.ID, err)
	}
	res := &Result{Product: Product{SBOMID: s.ID, DocumentName: s.DocumentName, SourceFile: s.SourceFile, SourceRepo: s.SourceRepo, SourceRef: s.SourceRef}}

	// Dependency tree: best effort.
	direct := map[string]bool{}
	names := map[string]bomhort.DependencyNode{}
	directKnown := false
	if deps, err := api.Dependencies(ctx, s.ID); err != nil {
		slog.Warn("source: dependency tree unavailable", "sbom", s.ID, "err", err)
	} else {
		directKnown = markDirect(deps, direct, names)
	}

	// Raw SBOM: repo hints and a second opinion on direct deps.
	var doc *sbom.Document
	if raw, err := api.DownloadSBOM(ctx, s.ID); err != nil {
		slog.Warn("source: raw SBOM unavailable", "sbom", s.ID, "err", err)
	} else if doc, err = sbom.Parse(raw); err != nil {
		slog.Warn("source: raw SBOM unparsable", "sbom", s.ID, "err", err)
		doc = nil
	}
	if doc != nil {
		res.Product.RepoHints = doc.RepoHints
		for _, c := range doc.Components {
			if c.Root && c.PURL != "" {
				res.Product.RootPURLs = append(res.Product.RootPURLs, c.PURL)
			}
			if !directKnown && c.Direct {
				direct[c.PURL] = true
				directKnown = true
			}
		}
	}

	// Since #335 BOMHort returns exactly one row per (vuln_id, purl) with the
	// effective statement; older gateways emitted one row per matching VEX
	// statement. Collapse duplicates defensively, preferring a row that
	// carries a vex_status (and, among those, the newest vex_timestamp).
	seen := map[string]int{}
	for _, v := range vulns {
		purl := strings.TrimSpace(v.PURL)
		f := Finding{
			VulnID:       strings.TrimSpace(v.VulnID),
			PURL:         purl,
			Severity:     v.Severity,
			Summary:      v.Summary,
			FixedVersion: v.FixedVersion,
			VEXStatus:    v.VEXStatus,
			VEXTimestamp: v.VEXTimestamp,
			VEXTooling:   v.VEXTooling,
			Aliases:      v.Aliases,
			Direct:       direct[purl],
			DirectKnown:  directKnown,
		}
		// BOMHort >= 0.8 stores the scope at parse time (#444); trust it over
		// our own tree walk. "unknown" (flat SBOM, pre-025 row) and "root"
		// (the product itself) carry no direct/transitive information.
		switch v.DependencyScope {
		case "direct", "transitive":
			f.Direct, f.DirectKnown = v.DependencyScope == "direct", true
		}
		if n, ok := names[purl]; ok {
			f.PackageName, f.PackageVersion = n.Name, n.Version
		} else if doc != nil {
			if c, ok := doc.ByPURL()[purl]; ok {
				f.PackageName, f.PackageVersion = c.Name, c.Version
			}
		}
		if f.VulnID == "" || f.PURL == "" {
			slog.Warn("source: skipping finding without vuln_id or purl", "sbom", s.ID, "vuln", v.VulnID, "purl", v.PURL)
			continue
		}
		// Since 0.8 BOMHort applies a statement to every finding whose
		// vuln_id or alias matches (#412), so alias twins of one purl are a
		// single finding for us: assess once, emit once.
		var dup bool
		var i int
		for _, id := range append([]string{f.VulnID}, f.Aliases...) {
			if i, dup = seen[id+"\x00"+f.PURL]; dup {
				break
			}
		}
		if dup {
			// Pre-#335 BOMHort emits one row per matching VEX statement, so
			// several documents for the same (vuln, purl) surface as
			// duplicates with possibly different statuses. Any non-empty
			// status means "already VEXed".
			prev := &res.Findings[i]
			switch {
			case f.VEXStatus == "":
			case prev.VEXStatus == "":
				prev.VEXStatus, prev.VEXTimestamp, prev.VEXTooling = f.VEXStatus, f.VEXTimestamp, f.VEXTooling
			case f.VEXStatus != prev.VEXStatus:
				slog.Debug("source: conflicting vex_status rows", "sbom", s.ID, "vuln", f.VulnID, "purl", f.PURL, "kept", prev.VEXStatus, "other", f.VEXStatus)
			}
			continue
		}
		for _, id := range append([]string{f.VulnID}, f.Aliases...) {
			seen[id+"\x00"+f.PURL] = len(res.Findings)
		}
		res.Findings = append(res.Findings, f)
	}
	return res, nil
}

// markDirect flags children of root nodes (nodes nobody points to) as direct.
// It returns false when the tree carries no edges at all.
func markDirect(nodes []bomhort.DependencyNode, direct map[string]bool, names map[string]bomhort.DependencyNode) bool {
	byIndex := make(map[uint32]bomhort.DependencyNode, len(nodes))
	hasParent := map[uint32]bool{}
	edges := 0
	for _, n := range nodes {
		byIndex[n.Index] = n
		if n.PURL != "" {
			names[n.PURL] = n
		}
		for _, c := range n.Children {
			hasParent[c] = true
			edges++
		}
	}
	if edges == 0 {
		return false
	}
	for _, n := range nodes {
		if hasParent[n.Index] {
			continue
		}
		for _, c := range n.Children {
			if child, ok := byIndex[c]; ok && child.PURL != "" {
				direct[child.PURL] = true
			}
		}
	}
	return true
}
