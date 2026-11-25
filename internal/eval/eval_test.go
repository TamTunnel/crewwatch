package eval

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestHarness runs the full benchmark (probe 12): 10 real tasks across
// 2 repos, with results recorded to a file.
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
	if len(res.Tasks) != 10 {
		t.Fatalf("tasks %d, want 10", len(res.Tasks))
	}
	if res.CompletionRate != 1.0 {
		t.Fatalf("completion rate %.2f, want 1.0", res.CompletionRate)
	}
	if res.MedianAttempts != 1 {
		t.Fatalf("median attempts %.1f, want 1", res.MedianAttempts)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("results file missing at %s: %v", path, err)
	}
	// The results file must live under the requested out dir.
	if filepath.Dir(path) != outDir {
		t.Fatalf("results path %s not under %s", path, outDir)
	}
}
