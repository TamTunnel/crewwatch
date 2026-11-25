package redact

import (
	"os"
	"strings"
	"testing"
)

func TestRedactCanaryAndKeys(t *testing.T) {
	t.Setenv("CREWWATCH_CANARY", "CANARY-SECRET-123")
	in := "key AKIAIOSFODNN7EXAMPLE and sk-abc1234567890abcdef and CANARY-SECRET-123 and api_key=supersecret"
	out := String(in)
	if ContainsSecret(out) {
		t.Fatalf("redacted output still contains a secret: %q", out)
	}
	for _, leak := range []string{"AKIAIOSFODNN7EXAMPLE", "sk-abc1234567890abcdef", "CANARY-SECRET-123", "supersecret"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q in %q", leak, out)
		}
	}
}

func TestRedactPEMBlock(t *testing.T) {
	in := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	out := String(in)
	if strings.Contains(out, "MIIEowIBAAKCAQEA") {
		t.Fatalf("PEM body leaked: %q", out)
	}
	if !strings.Contains(out, "[REDACTED-PRIVATE-KEY]") {
		t.Fatalf("expected redaction marker, got %q", out)
	}
}

func TestRedactLeavesNormalText(t *testing.T) {
	in := "go test ./... passed, diff sha256 abc123"
	if got := String(in); got != in {
		t.Fatalf("normal text changed: %q", got)
	}
}

func TestContainsSecretDetectsUnredacted(t *testing.T) {
	os.Setenv("CREWWATCH_CANARY", "")
	if !ContainsSecret("ghp_abcdefghij1234567890") {
		t.Fatal("expected github token to be detected")
	}
}
