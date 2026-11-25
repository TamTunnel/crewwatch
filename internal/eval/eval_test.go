package eval

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestHarness runs the full benchmark (probe 12): 10 honest tasks
// across 2 repos plus 2 adversarial tasks, with results recorded to a
// file. Honest tasks must close; adversarial tasks (cheating worker,
// unfixable task) must escalate, never close.
func TestHarness(t *testing.T) {
	if testing.Short() {
		t.Skip("harness needs the full benchmark run")
	}
	home := t.TempDir()
	outDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, path, err := Run(ctx, home, outDir)
	if err != nil {
		t.Fatalf("harness: %v", err)
	}
	if len(res.Tasks) != 12 {
		t.Fatalf("tasks %d, want 12 (10 honest + 2 adversarial)", len(res.Tasks))
	}
	if res.HonestTotal != 10 || res.HonestDone != 10 {
		t.Fatalf("honest %d/%d, want 10/10", res.HonestDone, res.HonestTotal)
	}
	if res.CompletionRate != 1.0 {
		t.Fatalf("completion rate %.2f, want 1.0", res.CompletionRate)
	}
	if res.AdversarialTotal != 2 || res.AdversarialCorrect != 2 {
		t.Fatalf("adversarial %d/%d correctly escalated, want 2/2", res.AdversarialCorrect, res.AdversarialTotal)
	}
	if res.MedianAttempts != 1 {
		t.Fatalf("median attempts %.1f, want 1", res.MedianAttempts)
	}
	// The harness must measure non-zero tokens and cost (probe 7):
	// the scripted workers emit token JSON on every attempt.
	if res.TotalTokens == 0 {
		t.Fatal("total tokens 0 — harness workers must emit token JSON")
	}
	if res.TotalCostUSD == 0 {
		t.Fatal("total cost $0 — harness workers must emit cost JSON")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("results file missing at %s: %v", path, err)
	}
	// The results file must live under the requested out dir.
	if filepath.Dir(path) != outDir {
		t.Fatalf("results path %s not under %s", path, outDir)
	}
}
