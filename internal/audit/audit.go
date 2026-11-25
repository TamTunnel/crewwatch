// Package audit is a hash-chained, append-only JSONL audit log. Every
// manager decision (goal added, task dispatched, verified, closed,
// escalated, cancelled) is appended as one entry. Each entry hashes the
// previous entry's hash, so deleting or reordering an entry breaks the
// chain — detectable offline by Verify.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/TamTunnel/crewwatch/internal/canonical"
)

// Entry is one audit-log line.
type Entry struct {
	Seq       int64          `json:"seq"`
	PrevHash  string         `json:"prev_hash"`
	Payload   map[string]any `json:"payload"`
	EntryHash string         `json:"entry_hash"`
}

// Log is an append-only audit log backed by a file.
type Log struct {
	mu   sync.Mutex
	path string
	seq  int64
	prev string
}

// Open opens (creating if needed) the audit log at path and replays it to
// find the current sequence and head hash.
func Open(path string) (*Log, error) {
	l := &Log{path: path, prev: genesis()}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("audit: corrupt entry: %w", err)
		}
		if err := checkEntry(&e); err != nil {
			return nil, fmt.Errorf("audit: chain broken at seq %d: %w", e.Seq, err)
		}
		l.seq = e.Seq
		l.prev = e.EntryHash
	}
	return l, sc.Err()
}

func genesis() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

// hashEntry computes the entry hash from prev hash + canonical payload.
func hashEntry(prev string, payload map[string]any) (string, error) {
	canon, err := canonical.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(prev + string(canon)))
	return hex.EncodeToString(sum[:]), nil
}

func checkEntry(e *Entry) error {
	want, err := hashEntry(e.PrevHash, e.Payload)
	if err != nil {
		return err
	}
	if want != e.EntryHash {
		return fmt.Errorf("entry hash mismatch")
	}
	return nil
}

// Append adds one entry and returns it.
func (l *Log) Append(payload map[string]any) (*Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	h, err := hashEntry(l.prev, payload)
	if err != nil {
		return nil, err
	}
	e := &Entry{Seq: l.seq + 1, PrevHash: l.prev, Payload: payload, EntryHash: h}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	l.seq = e.Seq
	l.prev = e.EntryHash
	return e, nil
}

// Verify replays the whole log and reports the first broken entry, if any.
func Verify(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	prev := genesis()
	seq := int64(0)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return fmt.Errorf("audit: corrupt entry at line %d: %w", seq+1, err)
		}
		if e.Seq != seq+1 {
			return fmt.Errorf("audit: seq gap at line %d: got %d want %d", seq+1, e.Seq, seq+1)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("audit: prev-hash mismatch at seq %d", e.Seq)
		}
		if err := checkEntry(&e); err != nil {
			return fmt.Errorf("audit: entry %d: %w", e.Seq, err)
		}
		prev = e.EntryHash
		seq = e.Seq
	}
	return sc.Err()
}
