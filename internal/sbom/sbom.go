// Package sbom is a deliberately minimal reader for SPDX 2.x JSON and
// CycloneDX 1.x JSON documents. It extracts what VEXViper needs: components
// with PURLs, which of them are direct dependencies of the described product,
// and any hints about the product's source repository.
package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Format identifies the SBOM format.
type Format string

// Supported formats.
const (
	FormatSPDX      Format = "spdx"
	FormatCycloneDX Format = "cyclonedx"
)

// Component is a package described by the SBOM.
type Component struct {
	ID      string // SPDXID or bom-ref
	Name    string
	Version string
	PURL    string
	// Direct is true when the component is a direct dependency of a root.
	Direct bool
	// Root is true when the component is (one of) the product(s) the document describes.
	Root bool
	// SourceInfo carries free text about where the component was found (SPDX sourceInfo).
	SourceInfo string
}

// Document is the parsed SBOM.
type Document struct {
	Format     Format
	Name       string
	Components []Component
	// RepoHints are candidate source repository URLs for the product, best first.
	RepoHints []string
}

// Parse detects the format and parses data.
func Parse(data []byte) (*Document, error) {
	var probe struct {
		SPDXVersion string `json:"spdxVersion"`
		BOMFormat   string `json:"bomFormat"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("sbom: not a JSON object: %w", err)
	}
	switch {
	case probe.SPDXVersion != "":
		return parseSPDX(data)
	case strings.EqualFold(probe.BOMFormat, "CycloneDX"):
		return parseCycloneDX(data)
	}
	return nil, errors.New("sbom: unrecognized format (expected spdxVersion or bomFormat=CycloneDX)")
}

// ByPURL indexes components by exact PURL.
func (d *Document) ByPURL() map[string]Component {
	m := make(map[string]Component, len(d.Components))
	for _, c := range d.Components {
		if c.PURL != "" {
			m[c.PURL] = c
		}
	}
	return m
}

// PURLs returns all non-empty, de-duplicated PURLs in stable order.
func (d *Document) PURLs() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range d.Components {
		if c.PURL != "" && !seen[c.PURL] {
			seen[c.PURL] = true
			out = append(out, c.PURL)
		}
	}
	sort.Strings(out)
	return out
}

// ---- SPDX ----

type spdxDoc struct {
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	Packages          []struct {
		Name             string `json:"name"`
		SPDXID           string `json:"SPDXID"`
		VersionInfo      string `json:"versionInfo"`
		DownloadLocation string `json:"downloadLocation"`
		Homepage         string `json:"homepage"`
		SourceInfo       string `json:"sourceInfo"`
		ExternalRefs     []struct {
			ReferenceType    string `json:"referenceType"`
			ReferenceLocator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
	Relationships []struct {
		Element string `json:"spdxElementId"`
		Related string `json:"relatedSpdxElement"`
		Type    string `json:"relationshipType"`
	} `json:"relationships"`
}

func parseSPDX(data []byte) (*Document, error) {
	var s spdxDoc
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("sbom: parse SPDX: %w", err)
	}
	doc := &Document{Format: FormatSPDX, Name: s.Name}

	roots := map[string]bool{}
	direct := map[string]bool{}
	for _, r := range s.Relationships {
		if r.Type == "DESCRIBES" && r.Element == "SPDXRef-DOCUMENT" {
			roots[r.Related] = true
		}
	}
	for _, r := range s.Relationships {
		switch r.Type {
		case "DEPENDS_ON":
			if roots[r.Element] {
				direct[r.Related] = true
			}
		case "DEPENDENCY_OF":
			if roots[r.Related] {
				direct[r.Element] = true
			}
		}
	}

	var hints []string
	for _, p := range s.Packages {
		c := Component{ID: p.SPDXID, Name: p.Name, Version: p.VersionInfo, SourceInfo: p.SourceInfo, Root: roots[p.SPDXID], Direct: direct[p.SPDXID]}
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType == "purl" && c.PURL == "" {
				c.PURL = ref.ReferenceLocator
			}
		}
		if c.Version == "UNKNOWN" || c.Version == "NOASSERTION" {
			c.Version = ""
		}
		if c.Root {
			hints = append(hints, repoURLFrom(p.DownloadLocation), repoURLFrom(p.Homepage))
		}
		doc.Components = append(doc.Components, c)
	}
	// Some generators (syft dir:) describe a directory; the product is then the
	// Go main module with an unknown version, or a Go module with sourceInfo
	// pointing to go.mod at the top level.
	for _, c := range doc.Components {
		if strings.HasPrefix(c.PURL, "pkg:golang/") && c.Version == "" {
			hints = append(hints, repoURLFromPURL(c.PURL))
		}
	}
	hints = append(hints, mainModuleHints(doc.Components)...)
	doc.RepoHints = dedupe(hints)
	if len(roots) == 0 {
		// Fall back to marking everything direct: no relationship data at all.
		for i := range doc.Components {
			doc.Components[i].Direct = len(s.Relationships) == 0
		}
	}
	return doc, nil
}

// ---- CycloneDX ----

type cdxComponent struct {
	BOMRef             string `json:"bom-ref"`
	Name               string `json:"name"`
	Group              string `json:"group"`
	Version            string `json:"version"`
	PURL               string `json:"purl"`
	ExternalReferences []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"externalReferences"`
	Components []cdxComponent `json:"components"`
}

type cdxDoc struct {
	Metadata struct {
		Component *cdxComponent `json:"component"`
	} `json:"metadata"`
	Components   []cdxComponent `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

func parseCycloneDX(data []byte) (*Document, error) {
	var c cdxDoc
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("sbom: parse CycloneDX: %w", err)
	}
	doc := &Document{Format: FormatCycloneDX}
	var hints []string
	rootRef := ""
	if mc := c.Metadata.Component; mc != nil {
		rootRef = mc.BOMRef
		doc.Name = mc.Name
		root := toComponent(*mc)
		root.Root = true
		doc.Components = append(doc.Components, root)
		for _, ref := range mc.ExternalReferences {
			if ref.Type == "vcs" || ref.Type == "website" || ref.Type == "distribution" {
				hints = append(hints, repoURLFrom(ref.URL))
			}
		}
		if mc.PURL != "" {
			hints = append(hints, repoURLFromPURL(mc.PURL))
		}
	}
	direct := map[string]bool{}
	for _, d := range c.Dependencies {
		if d.Ref == rootRef && rootRef != "" {
			for _, dep := range d.DependsOn {
				direct[dep] = true
			}
		}
	}
	var walk func(list []cdxComponent)
	walk = func(list []cdxComponent) {
		for _, cc := range list {
			comp := toComponent(cc)
			comp.Direct = direct[cc.BOMRef]
			doc.Components = append(doc.Components, comp)
			walk(cc.Components)
		}
	}
	walk(c.Components)
	if len(c.Dependencies) == 0 {
		for i := range doc.Components {
			if !doc.Components[i].Root {
				doc.Components[i].Direct = true
			}
		}
	}
	hints = append(hints, mainModuleHints(doc.Components)...)
	doc.RepoHints = dedupe(hints)
	return doc, nil
}

// mainModuleHints handles SBOMs whose root is an opaque product
// (pkg:generic/<name>@<ver>, e.g. from mikebom/cdxgen): the Go main module
// usually appears as a component whose module path ends in the product
// name, so its repository is a good candidate.
func mainModuleHints(components []Component) []string {
	var roots []string
	for _, c := range components {
		if c.Root && c.Name != "" && c.Name != "." {
			roots = append(roots, strings.ToLower(c.Name))
		}
	}
	if len(roots) == 0 {
		return nil
	}
	var hints []string
	for _, c := range components {
		if c.Root || !strings.HasPrefix(c.PURL, "pkg:golang/") {
			continue
		}
		mod := strings.TrimPrefix(c.PURL, "pkg:golang/")
		if i := strings.IndexByte(mod, '@'); i >= 0 {
			mod = mod[:i]
		}
		last := strings.ToLower(mod[strings.LastIndexByte(mod, '/')+1:])
		for _, r := range roots {
			if last == r {
				hints = append(hints, repoURLFromPURL(c.PURL))
			}
		}
	}
	return hints
}

func toComponent(c cdxComponent) Component {
	name := c.Name
	if c.Group != "" {
		name = c.Group + "/" + c.Name
	}
	return Component{ID: c.BOMRef, Name: name, Version: c.Version, PURL: c.PURL}
}

// ---- helpers ----

// repoURLFrom normalizes a download/vcs location into an https repo URL when
// it looks like a hosted git repository; otherwise returns "".
func repoURLFrom(loc string) string {
	loc = strings.TrimSpace(loc)
	if loc == "" || loc == "NOASSERTION" || loc == "NONE" {
		return ""
	}
	loc = strings.TrimPrefix(loc, "git+")
	loc = strings.TrimPrefix(loc, "git://")
	if strings.HasPrefix(loc, "git@") { // git@github.com:owner/repo.git
		loc = "https://" + strings.Replace(strings.TrimPrefix(loc, "git@"), ":", "/", 1)
	}
	if !strings.HasPrefix(loc, "http://") && !strings.HasPrefix(loc, "https://") {
		loc = "https://" + loc
	}
	u, err := url.Parse(loc)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Host)
	if host != "github.com" && host != "gitlab.com" && host != "bitbucket.org" && !strings.Contains(host, "gitlab.") && !strings.Contains(host, "gitea.") && !strings.Contains(host, "codeberg.") {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	repo := strings.TrimSuffix(parts[1], ".git")
	if i := strings.Index(repo, "@"); i > 0 {
		repo = repo[:i]
	}
	return "https://" + host + "/" + parts[0] + "/" + repo
}

// repoURLFromPURL maps pkg:golang/github.com/o/r/... and pkg:github/o/r to repo URLs.
func repoURLFromPURL(purl string) string {
	p := purl
	for _, sep := range []string{"@", "?", "#"} {
		if i := strings.Index(p, sep); i > 0 {
			p = p[:i]
		}
	}
	switch {
	case strings.HasPrefix(p, "pkg:golang/github.com/"):
		return repoURLFrom(strings.TrimPrefix(p, "pkg:golang/"))
	case strings.HasPrefix(p, "pkg:github/"):
		return repoURLFrom("github.com/" + strings.TrimPrefix(p, "pkg:github/"))
	}
	return ""
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
