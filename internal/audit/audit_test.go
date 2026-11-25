package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func otherKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(100 + i)
	}
	return k
}
func TestAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, testKey(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := l.Append(map[string]any{"event": "test", "i": int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := Verify(path, testKey(), "", 0); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	// Reopen must resume the chain.
	l2, err := Open(path, testKey(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l2.Append(map[string]any{"event": "more"}); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, testKey(), "", 0); err != nil {
		t.Fatalf("verify after reopen failed: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, testKey(), "", 0)
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
	if err := Verify(path, testKey(), "", 0); err == nil {
		t.Fatal("truncated chain verified")
	}
}

// TestRewriteDetected is B2: editing a payload and recomputing the
// plain SHA-256 chain must still fail, because the HMAC key is not in
// the log file.
func TestRewriteDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, testKey(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(map[string]any{"event": "x", "i": int64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// Rewrite entry 2's payload and recompute the plain chain forward
	// (the pre-HMAC attack), leaving the HMACs stale.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(t, raw)
	lines[1] = rewritePayload(t, lines[1], "PWNED")
	// Recompute entry_hash forward from the edited entry.
	lines[1] = rehashLine(t, lines[1], firstHash(t, lines[0]))
	lines[2] = rehashLine(t, lines[2], entryHashOf(t, lines[1]))
	if err := os.WriteFile(path, joinLines(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, testKey(), "", 0); err == nil {
		t.Fatal("rewritten chain verified despite stale HMAC")
	}
	// Open must refuse it too — the daemon must not build on it.
	if _, err := Open(path, testKey(), "", 0); err == nil {
		t.Fatal("Open accepted a rewritten chain")
	}
}

// TestTruncationVsSQLite is B2: a file with fewer entries than SQLite
// recorded is refused, while a file with more (crash between file
// append and SQLite update) is accepted.
func TestTruncationVsSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, testKey(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var head string
	for i := 0; i < 4; i++ {
		e, err := l.Append(map[string]any{"event": "x", "i": int64(i)})
		if err != nil {
			t.Fatal(err)
		}
		head = e.EntryHash
	}
	// Truncation: drop the last entry, keep the SQLite expectation.
	raw, _ := os.ReadFile(path)
	lines := splitLines(t, raw)
	if err := os.WriteFile(path, joinLines(lines[:3]), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, testKey(), head, 4); err == nil {
		t.Fatal("Open accepted a truncated log")
	}
	if err := Verify(path, testKey(), head, 4); err == nil {
		t.Fatal("Verify accepted a truncated log")
	}
	// Crash case: file has MORE entries than SQLite recorded — accept.
	raw, _ = os.ReadFile(path)
	lines = splitLines(t, raw)
	_ = lines
	l2, err := Open(path, testKey(), head, 2)
	if err != nil {
		t.Fatalf("Open refused a longer-than-recorded log: %v", err)
	}
	if l2.Count() != 3 {
		t.Fatalf("count %d, want 3", l2.Count())
	}
}

func splitLines(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for _, ln := range splitByteLines(raw) {
		if len(ln) > 0 {
			out = append(out, ln)
		}
	}
	return out
}

func splitByteLines(raw []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range raw {
		if b == '\n' {
			out = append(out, raw[start:i])
			start = i + 1
		}
	}
	if start < len(raw) {
		out = append(out, raw[start:])
	}
	return out
}

func joinLines(lines [][]byte) []byte {
	var out []byte
	for _, ln := range lines {
		out = append(out, ln...)
		out = append(out, '\n')
	}
	return out
}

func rewritePayload(t *testing.T, line []byte, title string) []byte {
	t.Helper()
	var e Entry
	if err := jsonUnmarshal(line, &e); err != nil {
		t.Fatal(err)
	}
	e.Payload["title"] = title
	raw, err := jsonMarshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func firstHash(t *testing.T, line []byte) string { return entryHashOf(t, line) }

func entryHashOf(t *testing.T, line []byte) string {
	t.Helper()
	var e Entry
	if err := jsonUnmarshal(line, &e); err != nil {
		t.Fatal(err)
	}
	return e.EntryHash
}

// rehashLine recomputes entry_hash for a line given the previous hash
// (the attacker's plain-chain recomputation), without touching hmac.
func rehashLine(t *testing.T, line []byte, prev string) []byte {
	t.Helper()
	var e Entry
	if err := jsonUnmarshal(line, &e); err != nil {
		t.Fatal(err)
	}
	e.PrevHash = prev
	h, err := hashEntry(e.PrevHash, e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	e.EntryHash = h
	raw, err := jsonMarshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
