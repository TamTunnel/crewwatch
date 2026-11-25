// Package audit is a hash-chained, HMAC-authenticated, append-only JSONL
// audit log. Every manager decision (goal added, task dispatched,
// verified, closed, escalated, cancelled) is appended as one entry.
// Each entry hashes the previous entry's hash, and carries an HMAC
// (SHA-256, key in <home>/audit.key, 0600, generated on first use and
// kept out of the log file) over seq + prev hash + canonical payload,
// so deleting, editing, or reordering an entry breaks verification
// even for someone who can rewrite the plain SHA-256 chain.
//
// Tamper-evidence is anchored in SQLite meta: the expected head hash
// and entry count are persisted on every append (file first, then
// SQLite). On open, a file with FEWER entries than SQLite recorded is
// a truncation and the log is refused; a file with MORE entries (a
// crash between the file append and the SQLite update) is accepted and
// the caller re-syncs SQLite from the file.
package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/TamTunnel/crewwatch/internal/canonical"
)

// Entry is one audit-log line.
type Entry struct {
	Seq       int64          `json:"seq"`
	PrevHash  string         `json:"prev_hash"`
	Payload   map[string]any `json:"payload"`
	EntryHash string         `json:"entry_hash"`
	HMAC      string         `json:"hmac"`
}

// Log is an append-only audit log backed by a file. Appends are
// serialized across processes with a flock on <path>.lock, and each
// append replays the file first, so a daemon and a CLI (e.g. `goal
// cancel`) appending concurrently can never produce duplicate
// sequence numbers or build on a stale head hash.
type Log struct {
	mu       sync.Mutex
	path     string
	lockPath string
	key      []byte
	seq      int64
	prev     string
}

// LoadOrCreateKey loads the HMAC key from dir/audit.key (0600),
// creating a fresh 32-byte random key if it does not exist.
func LoadOrCreateKey(dir string) ([]byte, error) {
	path := dir + "/audit.key"
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) != 32 {
			return nil, fmt.Errorf("audit: corrupt audit.key: %d bytes, want 32", len(raw))
		}
		return raw, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// Open opens (creating if needed) the audit log at path and runs the
// SAME full verification as Verify: HMACs, seq/prev_hash linkage, and
// the truncation check against the expected head/count from SQLite
// meta (pass ""/0 when there is no recorded expectation, e.g. a fresh
// home). A broken chain or a truncated file is refused. A file with
// MORE entries than expected is accepted (crash between file append
// and SQLite update); the caller must re-sync SQLite from Head()/Count().
func Open(path string, key []byte, expectedHead string, expectedCount int64) (*Log, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("audit: HMAC key must be 32 bytes")
	}
	l := &Log{path: path, lockPath: path + ".lock", key: key, prev: genesis()}
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
		if e.Seq != l.seq+1 {
			return nil, fmt.Errorf("audit: chain broken at line %d: seq gap got %d want %d", l.seq+1, e.Seq, l.seq+1)
		}
		if e.PrevHash != l.prev {
			return nil, fmt.Errorf("audit: chain broken at seq %d: prev-hash mismatch", e.Seq)
		}
		if err := checkEntry(key, &e); err != nil {
			return nil, fmt.Errorf("audit: chain broken at seq %d: %w", e.Seq, err)
		}
		l.seq = e.Seq
		l.prev = e.EntryHash
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if expectedCount > 0 && l.seq < expectedCount {
		return nil, fmt.Errorf("audit: log truncated: SQLite recorded %d entries with head %s, file has %d entries with head %s",
			expectedCount, expectedHead, l.seq, l.prev)
	}
	if expectedCount > 0 && l.seq == expectedCount && expectedHead != "" && l.prev != expectedHead {
		return nil, fmt.Errorf("audit: head hash mismatch: SQLite recorded %s, file head is %s", expectedHead, l.prev)
	}
	return l, nil
}

// Head returns the current head entry hash (genesis if empty).
func (l *Log) Head() string { return l.prev }

// Count returns the number of entries in the log.
func (l *Log) Count() int64 { return l.seq }

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

func macEntry(key []byte, seq int64, prev string, payload map[string]any) (string, error) {
	canon, err := canonical.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%d|%s|%s", seq, prev, canon)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func checkEntry(key []byte, e *Entry) error {
	want, err := hashEntry(e.PrevHash, e.Payload)
	if err != nil {
		return err
	}
	if want != e.EntryHash {
		return fmt.Errorf("entry hash mismatch")
	}
	wantMAC, err := macEntry(key, e.Seq, e.PrevHash, e.Payload)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(wantMAC), []byte(e.HMAC)) {
		return fmt.Errorf("entry HMAC mismatch")
	}
	return nil
}

// replay re-reads the whole file and resets seq/prev to the true
// head, verifying HMACs and seq/prev_hash linkage as it goes. It
// must be called with the append lock held.
func (l *Log) replay() error {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			l.seq = 0
			l.prev = genesis()
			return nil
		}
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
			return fmt.Errorf("audit: corrupt entry: %w", err)
		}
		if e.Seq != seq+1 {
			return fmt.Errorf("audit: chain broken at seq %d: seq gap got %d want %d", e.Seq, e.Seq, seq+1)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("audit: chain broken at seq %d: prev-hash mismatch", e.Seq)
		}
		if err := checkEntry(l.key, &e); err != nil {
			return fmt.Errorf("audit: chain broken at seq %d: %w", e.Seq, err)
		}
		prev = e.EntryHash
		seq = e.Seq
	}
	if err := sc.Err(); err != nil {
		return err
	}
	l.seq = seq
	l.prev = prev
	return nil
}

// Append adds one entry and returns it.
func (l *Log) Append(payload map[string]any) (*Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Serialize across processes and refresh from the file, so this
	// append builds on the true head even if another process (a
	// second daemon, a cancel CLI) appended since this Log was opened.
	lf, err := os.OpenFile(l.lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	if err := l.replay(); err != nil {
		return nil, err
	}
	h, err := hashEntry(l.prev, payload)
	if err != nil {
		return nil, err
	}
	e := &Entry{Seq: l.seq + 1, PrevHash: l.prev, Payload: payload, EntryHash: h}
	mac, err := macEntry(l.key, e.Seq, e.PrevHash, e.Payload)
	if err != nil {
		return nil, err
	}
	e.HMAC = mac
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

// Verify replays the whole log and reports the first broken entry, if
// any. It applies the same checks as Open, including the truncation
// check against expectedHead/expectedCount (pass ""/0 to skip it).
func Verify(path string, key []byte, expectedHead string, expectedCount int64) error {
	if len(key) != 32 {
		return fmt.Errorf("audit: HMAC key must be 32 bytes")
	}
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
		if err := checkEntry(key, &e); err != nil {
			return fmt.Errorf("audit: entry %d: %w", e.Seq, err)
		}
		prev = e.EntryHash
		seq = e.Seq
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if expectedCount > 0 && seq < expectedCount {
		return fmt.Errorf("audit: log truncated: SQLite recorded %d entries with head %s, file has %d entries with head %s",
			expectedCount, expectedHead, seq, prev)
	}
	if expectedCount > 0 && seq == expectedCount && expectedHead != "" && prev != expectedHead {
		return fmt.Errorf("audit: head hash mismatch: SQLite recorded %s, file head is %s", expectedHead, prev)
	}
	return nil
}

// ParseCount converts a meta-table count string to int64.
func ParseCount(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
