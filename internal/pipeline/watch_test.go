package pipeline

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mfahlandt/vexviper/internal/bomhort"
	"github.com/mfahlandt/vexviper/internal/llm"
)

type fakeLister struct {
	sboms []bomhort.SBOM
	err   error
	calls int
}

func (l *fakeLister) AllSBOMs(context.Context) ([]bomhort.SBOM, error) {
	l.calls++
	return l.sboms, l.err
}

func TestWatchOnceAndState(t *testing.T) {
	bh := bomhortFixture(t)
	bh.sbom.VulnCount = 3
	bh.sbom.IngestedAt = "2025-01-01T00:00:00Z"
	mock := &llm.Mock{Default: &llm.Assessment{Status: "under_investigation", Confidence: 0.4}}
	p := newTestPipeline(t, bh, mock, nil)
	lister := &fakeLister{sboms: []bomhort.SBOM{bh.sbom, {ID: "empty", VulnCount: 0}}}
	stateFile := filepath.Join(t.TempDir(), "state", "watch.json")
	out := t.TempDir()

	opts := WatchOptions{StateFile: stateFile, OutDir: out, Upload: true, Once: true, SkipZero: true}
	if err := p.Watch(context.Background(), lister, opts); err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 2 || len(bh.uploads) != 1 {
		t.Fatalf("calls=%d uploads=%d", len(mock.Calls), len(bh.uploads))
	}
	st, err := LoadWatchState(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Processed["sbom-1"] != "3@2025-01-01T00:00:00Z" || st.Processed["empty"] != "0@" || st.LastRun.IsZero() {
		t.Fatalf("state = %+v", st)
	}

	// Second pass: nothing changed → nothing processed.
	if err := p.Watch(context.Background(), lister, opts); err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 2 {
		t.Fatalf("re-processed unchanged sbom: calls=%d", len(mock.Calls))
	}

	// Vuln count changed → processed again.
	lister.sboms[0].VulnCount = 4
	if err := p.Watch(context.Background(), lister, opts); err != nil {
		t.Fatal(err)
	}
	if len(mock.Calls) != 4 {
		t.Fatalf("changed sbom not re-processed: calls=%d", len(mock.Calls))
	}
}

func TestWatchLoopStopsOnCancel(t *testing.T) {
	bh := bomhortFixture(t)
	p := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	lister := &fakeLister{err: errors.New("bomhort down")}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := p.Watch(ctx, lister, WatchOptions{Interval: 20 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if lister.calls < 2 {
		t.Fatalf("expected multiple passes, got %d", lister.calls)
	}
}

func TestWatchOnceReportsRunErrors(t *testing.T) {
	bh := bomhortFixture(t)
	p := newTestPipeline(t, bh, llm.Heuristic{}, nil)
	lister := &fakeLister{sboms: []bomhort.SBOM{{ID: "ghost", VulnCount: 1}}}
	err := p.Watch(context.Background(), lister, WatchOptions{Once: true})
	if err == nil {
		t.Fatal("expected error for unknown sbom")
	}
}

func TestLoadWatchStateBad(t *testing.T) {
	f := filepath.Join(t.TempDir(), "s.json")
	if err := (&WatchState{}).Save(f); err != nil {
		t.Fatal(err)
	}
	st, err := LoadWatchState(f)
	if err != nil || st.Processed == nil {
		t.Fatalf("st=%+v err=%v", st, err)
	}
	if st, err := LoadWatchState(""); err != nil || st == nil {
		t.Fatal("empty path must yield empty state")
	}
}
