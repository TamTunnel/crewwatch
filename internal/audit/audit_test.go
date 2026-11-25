package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := l.Append(map[string]any{"event": "test", "i": int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := Verify(path); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	// Reopen must resume the chain.
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l2.Append(map[string]any{"event": "more"}); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path); err != nil {
		t.Fatalf("verify after reopen failed: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(map[string]any{"event": "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(map[string]any{"event": "b"}); err != nil {
		t.Fatal(err)
	}
	// Delete the first entry (truncated chain is internally consistent in
	// seq terms only if renumbered — here the seq gap exposes it).
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Keep only the second line.
	nl := 0
	for i, b := range raw {
		if b == '\n' {
			nl = i
			break
		}
	}
	if err := os.WriteFile(path, raw[nl+1:], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path); err == nil {
		t.Fatal("truncated chain verified")
	}
}
