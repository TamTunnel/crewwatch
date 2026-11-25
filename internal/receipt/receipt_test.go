package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := Payload{
		GoalID: "goal-1", TaskID: "task-1", Title: "fix bug",
		WorkerAdapter: "opencode", Attempts: 2, DiffSHA256: "abc",
		VerifyCmd: "go test ./...", VerifiedAt: time.Now().Unix(),
	}
	r, err := Sign(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(r); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestTamperedReceiptFails(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Sign(Payload{GoalID: "g", TaskID: "t", Title: "x"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one byte in the payload.
	r.Payload.Title = "y"
	if err := Verify(r); err == nil {
		t.Fatal("tampered receipt verified")
	}
	// Flip one byte in the signature.
	r2, _ := Sign(Payload{GoalID: "g", TaskID: "t", Title: "x"}, priv)
	sig := r2.Signature
	b := []byte(sig)
	b[0] ^= 1
	r2.Signature = string(b)
	if err := Verify(r2); err == nil {
		t.Fatal("forged signature verified")
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(k1) != string(k2) {
		t.Fatal("key not stable across loads")
	}
	info, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %o, want 0600", info.Mode().Perm())
	}
}
