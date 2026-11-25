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

func TestRedactNewTokenShapes(t *testing.T) {
	// B8: every token shape the judge leaked must now redact.
	cases := []struct{ in, leak string }{
		{"Authorization: Bearer BEARER-FAKE-TOKEN-1234567890abcdef", "BEARER-FAKE-TOKEN-1234567890abcdef"},
		{"slack xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOp", "xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOp"},
		{"slack xoxp-123456789012-abcdefghij", "xoxp-123456789012-abcdefghij"},
		{"token deadbeefcafebabe0123456789abcdef", "deadbeefcafebabe0123456789abcdef"},
		{"secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}
	for _, c := range cases {
		out := String(c.in)
		if strings.Contains(out, c.leak) {
			t.Fatalf("leaked %q in %q", c.leak, out)
		}
		if ContainsSecret(out) {
			t.Fatalf("redacted output still contains a secret: %q", out)
		}
	}
	// A 40-hex git SHA must NOT be redacted (not a token shape).
	sha := "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
	if got := String("commit " + sha); !strings.Contains(got, sha) {
		t.Fatalf("git SHA was wrongly redacted: %q", got)
	}
	// A 64-hex SHA-256 must NOT be redacted either.
	sha256hex := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := String("diff " + sha256hex); !strings.Contains(got, sha256hex) {
		t.Fatalf("SHA-256 was wrongly redacted: %q", got)
	}
	// A long mixed-case filesystem path is 40+ base64-ish characters
	// joined by slashes — it is a path, not a token, and must survive.
	p := "/tmp/TestWorktreeEscape320792497/001/ignored.txt"
	if got := String("wrote " + p); !strings.Contains(got, p) {
		t.Fatalf("filesystem path was wrongly redacted: %q", got)
	}
	if ContainsSecret("wrote " + p) {
		t.Fatalf("filesystem path wrongly detected as a secret: %q", p)
	}
	// A 40-char window of a longer path is a path fragment, not a
	// token: SQLite record bytes place a title ("fix Add") adjacent to
	// a path ("/tmp/TestSecretRedaction<9 digits>/001"), which carves
	// out exactly 40 base64 chars when the temp-dir suffix has 9
	// digits. That fragment contains a numeric path segment (/001/).
	p = "fix Add/tmp/TestSecretRedaction283704322/001"
	if got := String("wrote " + p); !strings.Contains(got, p) {
		t.Fatalf("path fragment was wrongly redacted: %q", got)
	}
	if ContainsSecret("wrote " + p) {
		t.Fatalf("path fragment wrongly detected as a secret: %q", p)
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
