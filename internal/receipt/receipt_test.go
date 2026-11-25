package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
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
	// key.pub must exist and match the key.
	pub, err := LoadPinnedPublicKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(pub) != string(k1.Public().(ed25519.PublicKey)) {
		t.Fatal("key.pub does not match key.pem")
	}
}

// TestPinnedVerification is B1: a receipt signed under any other key
// fails VerifyPinned even though its own signature checks out, and the
// error names the expected vs actual fingerprint.
func TestPinnedVerification(t *testing.T) {
	_, operator, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := Sign(Payload{GoalID: "g", TaskID: "t", Title: "forged"}, attacker)
	if err != nil {
		t.Fatal(err)
	}
	// The forgery verifies against its own embedded key (that is the
	// hole Verify alone has).
	if err := Verify(forged); err != nil {
		t.Fatalf("forged receipt should verify against its own key: %v", err)
	}
	// Against the pinned operator key it must fail, with fingerprints.
	if err := VerifyPinned(forged, operator.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("forged receipt verified against the pinned key")
	} else if !strings.Contains(err.Error(), KeyID(operator.Public().(ed25519.PublicKey))) {
		t.Fatalf("pinned error must name the expected fingerprint: %v", err)
	}
	// A genuine receipt passes.
	genuine, err := Sign(Payload{GoalID: "g", TaskID: "t", Title: "real"}, operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinned(genuine, operator.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("genuine receipt failed pinned verification: %v", err)
	}
}
