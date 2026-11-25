// Package receipt issues and verifies signed, content-addressed work
// receipts. A receipt proves a task closed on deterministic verification:
// the payload is JCS-canonicalized, hashed (receipt ID), and signed with
// the operator's Ed25519 key.
//
// Trust model (B1): the operator public key is pinned. At key creation
// the public key is written to <home>/key.pub and its fingerprint is
// recorded in the SQLite meta table. Verify only checks the signature
// against the key embedded in the receipt; VerifyPinned additionally
// requires that embedded key to equal the pinned operator key and
// refuses any other key. Replacing key.pem/key.pub is a revocation
// event: receipts signed before the rotation fail verification against
// the new pinned key by design.
package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TamTunnel/crewwatch/internal/canonical"
)

// Format is the receipt format identifier.
const Format = "crewwatch/1"

// Payload is the signed content of a receipt.
type Payload struct {
	Format        string  `json:"format"`
	ReceiptID     string  `json:"receipt_id,omitempty"`
	GoalID        string  `json:"goal_id"`
	TaskID        string  `json:"task_id"`
	Title         string  `json:"title"`
	WorkerAdapter string  `json:"worker_adapter"`
	Attempts      int     `json:"attempts"`
	DiffSHA256    string  `json:"diff_sha256"`
	VerifyCmd     string  `json:"verify_cmd"`
	VerifiedAt    int64   `json:"verified_at"`
	DurationMs    int64   `json:"duration_ms"`
	CostTokens    int64   `json:"cost_tokens"`
	CostUSD       float64 `json:"cost_usd"`
	// WorkerExitCode is the worker process's exit code on the closing
	// attempt (0 normally). A receipt can still close on verification
	// even when the worker exited non-zero; the code is recorded so
	// the receipt does not attest a clean worker run it did not have.
	WorkerExitCode int `json:"worker_exit_code"`
}

// Receipt is the stored form: payload + signature + public key.
type Receipt struct {
	Payload   Payload `json:"payload"`
	Signature string  `json:"signature"`  // base64 Ed25519 signature over canonical(payload)
	PublicKey string  `json:"public_key"` // base64 Ed25519 public key
	KeyID     string  `json:"key_id"`     // first 16 hex chars of sha256(public key)
}

// KeyID returns the key identifier for a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// Sign canonicalizes p, fills ReceiptID, signs, and returns the receipt.
func Sign(p Payload, priv ed25519.PrivateKey) (*Receipt, error) {
	p.Format = Format
	p.ReceiptID = ""
	canon, err := canonical.Marshal(payloadMap(p))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	p.ReceiptID = hex.EncodeToString(sum[:])
	canon, err = canonical.Marshal(payloadMap(p))
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, canon)
	pub := priv.Public().(ed25519.PublicKey)
	return &Receipt{
		Payload:   p,
		Signature: base64.StdEncoding.EncodeToString(sig),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		KeyID:     KeyID(pub),
	}, nil
}

// Verify checks the receipt ID, the key binding, and the signature.
// It needs no outside state: the public key travels in the receipt.
// It proves only "someone holding the embedded key signed this" — use
// VerifyPinned to prove the operator's manager signed it.
func Verify(r *Receipt) error {
	if r.Payload.Format != Format {
		return fmt.Errorf("receipt: unknown format %q", r.Payload.Format)
	}
	pub, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil {
		return fmt.Errorf("receipt: bad public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("receipt: bad public key length %d", len(pub))
	}
	if KeyID(ed25519.PublicKey(pub)) != r.KeyID {
		return fmt.Errorf("receipt: key_id does not match public key")
	}
	want := *r
	want.Payload.ReceiptID = ""
	canon, err := canonical.Marshal(payloadMap(want.Payload))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canon)
	if hex.EncodeToString(sum[:]) != r.Payload.ReceiptID {
		return fmt.Errorf("receipt: receipt_id mismatch — payload was modified")
	}
	canon, err = canonical.Marshal(payloadMap(r.Payload))
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("receipt: bad signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), canon, sig) {
		return fmt.Errorf("receipt: signature verification failed")
	}
	return nil
}

// VerifyPinned checks the receipt cryptographically (as Verify does)
// and additionally requires the embedded public key to equal the pinned
// operator key. A receipt signed under any other key is refused, with
// the expected vs actual fingerprints in the error.
func VerifyPinned(r *Receipt, pinned ed25519.PublicKey) error {
	if err := Verify(r); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil {
		return fmt.Errorf("receipt: bad public key: %w", err)
	}
	if !bytes.Equal(pub, []byte(pinned)) {
		return fmt.Errorf("receipt: public key %s does not match pinned operator key %s (expected fingerprint %s, got %s)",
			r.PublicKey, base64.StdEncoding.EncodeToString(pinned),
			KeyID(pinned), KeyID(ed25519.PublicKey(pub)))
	}
	return nil
}

// LoadPinnedPublicKey reads the pinned operator public key from
// <home>/key.pub (base64), falling back to deriving it from key.pem.
func LoadPinnedPublicKey(home string) (ed25519.PublicKey, error) {
	if raw, err := os.ReadFile(filepath.Join(home, "key.pub")); err == nil {
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("receipt: corrupt key.pub: %w", err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("receipt: corrupt key.pub: bad public key length %d", len(pub))
		}
		return ed25519.PublicKey(pub), nil
	}
	priv, err := LoadOrCreateKey(home)
	if err != nil {
		return nil, err
	}
	return priv.Public().(ed25519.PublicKey), nil
}

// WritePublicKey writes the base64 public key to dir/key.pub (0644).
// It is called at key creation and on every load so a missing key.pub
// is restored from key.pem.
func WritePublicKey(dir string, pub ed25519.PublicKey) error {
	return os.WriteFile(filepath.Join(dir, "key.pub"),
		[]byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
}
func payloadMap(p Payload) map[string]any {
	return map[string]any{
		"format":           p.Format,
		"receipt_id":       p.ReceiptID,
		"goal_id":          p.GoalID,
		"task_id":          p.TaskID,
		"title":            p.Title,
		"worker_adapter":   p.WorkerAdapter,
		"attempts":         int64(p.Attempts),
		"diff_sha256":      p.DiffSHA256,
		"verify_cmd":       p.VerifyCmd,
		"verified_at":      p.VerifiedAt,
		"duration_ms":      p.DurationMs,
		"cost_tokens":      p.CostTokens,
		"cost_usd":         p.CostUSD,
		"worker_exit_code": int64(p.WorkerExitCode),
	}
}

// LoadOrCreateKey loads the operator key from dir/key.pem (0600), creating
// one if it does not exist. The key is a raw 32-byte Ed25519 seed,
// base64-encoded. No passphrase in v1: the key file must be kept private
// by filesystem permissions, like an SSH key.
func LoadOrCreateKey(dir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, "key.pem")
	if raw, err := os.ReadFile(path); err == nil {
		seed, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			return nil, fmt.Errorf("receipt: corrupt key file: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("receipt: corrupt key file: bad seed length %d", len(seed))
		}
		priv := ed25519.NewKeyFromSeed(seed)
		// Restore key.pub if it was deleted; replacing key.pem/key.pub
		// is a revocation event, so a restored key.pub always matches
		// the key that signed existing receipts.
		_ = WritePublicKey(dir, priv.Public().(ed25519.PublicKey))
		return priv, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seed := priv.Seed()
	enc := base64.StdEncoding.EncodeToString(seed)
	if err := os.WriteFile(path, []byte(enc), 0o600); err != nil {
		return nil, err
	}
	if err := WritePublicKey(dir, priv.Public().(ed25519.PublicKey)); err != nil {
		return nil, err
	}
	return priv, nil
}

// MarshalJSON renders a receipt as indented JSON for storage.
func (r *Receipt) MarshalJSON() ([]byte, error) {
	type receiptJSON Receipt
	return json.MarshalIndent((*receiptJSON)(r), "", "  ")
}
