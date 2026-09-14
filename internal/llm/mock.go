package llm

import (
	"context"
	"errors"
	"sync"
)

// Mock returns canned assessments, for tests and dry runs.
type Mock struct {
	// ByVulnID returns a specific assessment for a vulnerability ID.
	ByVulnID map[string]Assessment
	// Default is returned when no specific entry exists; zero value → error.
	Default *Assessment
	// Err, when set, is returned for every call.
	Err error

	mu    sync.Mutex
	Calls []Request
}

// Name implements Provider.
func (*Mock) Name() string { return "mock" }

// Assess implements Provider.
func (m *Mock) Assess(_ context.Context, req Request) (Assessment, error) {
	m.mu.Lock()
	m.Calls = append(m.Calls, req)
	m.mu.Unlock()
	if m.Err != nil {
		return Assessment{}, m.Err
	}
	if req.Report == nil {
		return Assessment{}, errors.New("mock: nil report")
	}
	if a, ok := m.ByVulnID[req.Report.Finding.VulnID]; ok {
		a.Provider = "mock"
		return a, nil
	}
	if m.Default != nil {
		a := *m.Default
		a.Provider = "mock"
		return a, nil
	}
	return Assessment{}, errors.New("mock: no assessment configured for " + req.Report.Finding.VulnID)
}

// WithFallback wraps primary so that provider errors degrade to fallback
// (typically Heuristic) instead of aborting the whole run. The returned
// assessment carries the fallback's provider name and a lowered confidence.
type WithFallback struct {
	Primary  Provider
	Fallback Provider
	// OnError is called with the primary's error (for logging).
	OnError func(req Request, err error)
}

// Name implements Provider.
func (w WithFallback) Name() string { return w.Primary.Name() + "+" + w.Fallback.Name() }

// Assess implements Provider.
func (w WithFallback) Assess(ctx context.Context, req Request) (Assessment, error) {
	a, err := w.Primary.Assess(ctx, req)
	if err == nil {
		return a, nil
	}
	if w.OnError != nil {
		w.OnError(req, err)
	}
	fb, ferr := w.Fallback.Assess(ctx, req)
	if ferr != nil {
		return Assessment{}, errors.Join(err, ferr)
	}
	fb.Reasoning = "[primary provider failed: " + err.Error() + "] " + fb.Reasoning
	return fb, nil
}
