// Package llm defines the assessment provider abstraction and the shared
// request/response schema exchanged with language models.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/mfahlandt/vexviper/internal/evidence"
)

// Request is everything a provider gets about one finding.
type Request struct {
	ProductName string           `json:"product_name"`
	ProductRepo string           `json:"product_repo,omitempty"`
	Report      *evidence.Report `json:"report"`
}

// Assessment is the provider's verdict. It intentionally mirrors OpenVEX
// statement fields so it can be validated with go-vex before use.
type Assessment struct {
	Status          vex.Status        `json:"status"`
	Justification   vex.Justification `json:"justification,omitempty"`
	ImpactStatement string            `json:"impact_statement,omitempty"`
	ActionStatement string            `json:"action_statement,omitempty"`
	// Confidence in [0,1].
	Confidence float64 `json:"confidence"`
	// Reasoning is a short explanation kept in status_notes.
	Reasoning string `json:"reasoning"`
	// EvidenceRefs lists evidence kinds the verdict relies on.
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	// Provider names the provider that produced the assessment.
	Provider string `json:"provider,omitempty"`
}

// Provider assesses one finding.
type Provider interface {
	Name() string
	Assess(ctx context.Context, req Request) (Assessment, error)
}

// Validate checks the assessment against OpenVEX rules and value ranges.
func (a *Assessment) Validate() error {
	if a.Confidence < 0 || a.Confidence > 1 {
		return fmt.Errorf("confidence %v out of range [0,1]", a.Confidence)
	}
	s := vex.Statement{
		Status:          a.Status,
		Justification:   a.Justification,
		ImpactStatement: a.ImpactStatement,
		ActionStatement: a.ActionStatement,
	}
	return s.Validate()
}

// Normalize coerces common LLM sloppiness (case, dashes, empty strings) into
// valid OpenVEX enum values before validation.
func (a *Assessment) Normalize() {
	a.Status = vex.Status(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(string(a.Status)), "-", "_")))
	a.Justification = vex.Justification(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(string(a.Justification)), "-", "_")))
	a.ImpactStatement = strings.TrimSpace(a.ImpactStatement)
	a.ActionStatement = strings.TrimSpace(a.ActionStatement)
	a.Reasoning = strings.TrimSpace(a.Reasoning)
	// Drop fields that are forbidden for the status; LLMs love to fill them in.
	switch a.Status {
	case vex.StatusAffected:
		a.Justification, a.ImpactStatement = "", ""
		if a.ActionStatement == "" {
			a.ActionStatement = "Upgrade the affected component to a fixed version."
		}
	case vex.StatusFixed, vex.StatusUnderInvestigation:
		a.Justification, a.ImpactStatement, a.ActionStatement = "", "", ""
	case vex.StatusNotAffected:
		a.ActionStatement = ""
	}
}

// ParseAssessment decodes JSON (optionally wrapped in markdown fences or
// surrounded by prose) into an Assessment and normalizes it.
func ParseAssessment(text string) (Assessment, error) {
	raw := extractJSON(text)
	if raw == "" {
		return Assessment{}, fmt.Errorf("no JSON object found in model output: %.200q", text)
	}
	var a Assessment
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return Assessment{}, fmt.Errorf("decode assessment: %w (input %.200q)", err, raw)
	}
	a.Normalize()
	return a, nil
}

func extractJSON(text string) string {
	text = strings.TrimSpace(text)
	if i := strings.Index(text, "```"); i >= 0 {
		rest := text[i+3:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:]
		}
		if j := strings.Index(rest, "```"); j >= 0 {
			text = rest[:j]
		}
	}
	start := strings.IndexByte(text, '{')
	end := strings.LastIndexByte(text, '}')
	if start < 0 || end <= start {
		return ""
	}
	return text[start : end+1]
}

// JSONSchema is the response schema handed to structured-output capable
// providers and included in the prompt for the others.
var JSONSchema = map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"status", "confidence", "reasoning"},
	"properties": map[string]any{
		"status":           map[string]any{"type": "string", "enum": vex.Statuses()},
		"justification":    map[string]any{"type": "string", "enum": append([]string{""}, vex.Justifications()...)},
		"impact_statement": map[string]any{"type": "string"},
		"action_statement": map[string]any{"type": "string"},
		"confidence":       map[string]any{"type": "number", "minimum": 0, "maximum": 1},
		"reasoning":        map[string]any{"type": "string"},
		"evidence_refs":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	},
}
