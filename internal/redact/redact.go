// Package redact removes secrets from text before it is stored in logs,
// transcripts, receipts, or the audit trail. A value that looks like a
// credential is replaced, never stored.
//
// Two layers: pattern redaction (known token shapes) and exact-value
// redaction (the literal values of environment variables passed to a
// worker, registered with AddValues — today the canary plus every
// allowlisted worker env value). Exact values are redacted first, so a
// token shape the patterns miss is still scrubbed if it came from the
// worker's environment.
package redact

import (
	"os"
	"regexp"
	"strings"
	"sync"
)

var patterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// AWS access key IDs.
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}`), "[REDACTED-AWS-KEY]"},
	// OpenAI-style keys and similar sk- tokens. The leading \b
	// matters: without it, "sk-" matches inside the word "task-"
	// in raw SQLite bytes (task-<hex>goal-<hex>...).
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{16,}`), "[REDACTED]"},
	// GitHub tokens.
	{regexp.MustCompile(`\bghp_[A-Za-z0-9]{20,}`), "[REDACTED]"},
	{regexp.MustCompile(`\bgho_[A-Za-z0-9]{20,}`), "[REDACTED]"},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`), "[REDACTED]"},
	// Bearer tokens: "Bearer <token>".
	{regexp.MustCompile(`(?i)Bearer [A-Za-z0-9\-._~+/=]{8,}`), "Bearer [REDACTED]"},
	// Slack-style tokens (xoxb-, xoxp-, xoxa-, xoxr-, xoxs- families).
	{regexp.MustCompile(`\bxox[bpras]-[A-Za-z0-9\-]{10,}`), "[REDACTED]"},
	// Bare 32-hex tokens (e.g. MD5-shaped API tokens). A 64-hex SHA-256
	// does not match: the word boundary after 32 chars fails because
	// the 33rd character is still a hex digit.
	{regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`), "[REDACTED]"},
	// PEM private key blocks (whole block, including newlines).
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), "[REDACTED-PRIVATE-KEY]"},
	// Generic key=value assignments for common secret names.
	{regexp.MustCompile(`(?i)(api[_-]?key|apikey|token|secret|password|passwd)\s*[:=]\s*\S+`), `${1}=[REDACTED]`},
}

// bareTokenRunRe matches maximal runs of base64-alphabet characters.
// A bare 40-character token (e.g. an AWS secret key) is a run of
// EXACTLY 40 such characters, delimited by anything else. Matching
// maximal runs (not 40-char windows) is what keeps this from firing
// on longer base64 blobs — an 88-char Ed25519 signature, a 44-char
// public key — or on long filesystem paths, whose runs are longer
// than 40 characters. A run is a token only if it is exactly 40
// characters, mixed case, and not pure hex (see isHighEntropy40).
var bareTokenRunRe = regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`)

// redactBare40 replaces bare 40-char high-entropy tokens. A run is a
// token only if it is exactly 40 characters, mixed case, not pure hex,
// and not path-shaped: a run starting with '/' is an absolute path,
// and a run followed by '/' or by '.' + a letter is a path segment
// (a file extension or a deeper directory).
func redactBare40(s string) string {
	var out strings.Builder
	last := 0
	for _, loc := range bareTokenRunRe.FindAllStringIndex(s, -1) {
		if !isTokenRun(s, loc) {
			continue
		}
		out.WriteString(s[last:loc[0]])
		out.WriteString("[REDACTED]")
		last = loc[1]
	}
	out.WriteString(s[last:])
	return out.String()
}

// containsBare40 reports whether s holds a redactable bare 40-char token.
func containsBare40(s string) bool {
	for _, loc := range bareTokenRunRe.FindAllStringIndex(s, -1) {
		if isTokenRun(s, loc) {
			return true
		}
	}
	return false
}

// isTokenRun reports whether the maximal base64 run at loc is a bare
// 40-char secret token rather than a longer blob or a filesystem path.
func isTokenRun(s string, loc []int) bool {
	m := s[loc[0]:loc[1]]
	if len(m) != 40 || !isHighEntropy40(m) {
		return false
	}
	if strings.HasPrefix(m, "/") {
		return false
	}
	// A purely numeric path segment (e.g. /001/) marks a filesystem
	// path fragment, not a token: SQLite record bytes can place a title
	// ("fix Add") adjacent to a path ("/tmp/TestSecretRedaction<digits>/001"),
	// carving out an exactly-40-char base64 window when the temp-dir
	// suffix has 9 digits. A real bare token's slash-separated segments
	// are mixed-case high-entropy strings, never all digits.
	for _, seg := range strings.Split(m, "/") {
		if seg == "" {
			continue
		}
		allDigits := true
		for _, c := range seg {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return false
		}
	}
	if loc[1] < len(s) {
		if s[loc[1]] == '/' {
			return false
		}
		if s[loc[1]] == '.' && loc[1]+1 < len(s) {
			c := s[loc[1]+1]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				return false
			}
		}
	}
	return true
}

func isHighEntropy40(s string) bool {
	if len(s) != 40 {
		return false
	}
	// Pure hex (a git SHA) is not a secret token shape.
	isHex := true
	hasUpper, hasLower := false, false
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
			hasLower = true
		case c >= 'A' && c <= 'F':
			hasUpper = true
		case c >= 'g' && c <= 'z':
			hasLower = true
			isHex = false
		case c >= 'G' && c <= 'Z':
			hasUpper = true
			isHex = false
		default:
			isHex = false
		}
	}
	if isHex {
		return false
	}
	// Require mixed case (real secret keys mix cases); a 40-char
	// all-lowercase identifier is not a token.
	return hasUpper && hasLower
}

var (
	mu        sync.Mutex
	extraVals []string // exact secret values to scrub (env values, canary)
)

// AddValues registers literal values to redact from all later output.
// Values shorter than 8 characters are ignored: they are too likely to
// be ordinary words. Callers pass the values of every env var handed
// to a worker; the canary is registered from the environment as well.
func AddValues(vals []string) {
	mu.Lock()
	defer mu.Unlock()
	for _, v := range vals {
		if len(v) < 8 {
			continue
		}
		extraVals = append(extraVals, v)
	}
}

func extraValues() []string {
	if canary := os.Getenv("CREWWATCH_CANARY"); canary != "" {
		return append(append([]string{}, extraVals...), canary)
	}
	return append([]string{}, extraVals...)
}

// String returns s with all known secret patterns and all registered
// exact values replaced.
func String(s string) string {
	for _, v := range extraValues() {
		if v != "" {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	for _, p := range patterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	s = redactBare40(s)
	return s
}

// markerRe matches the placeholders String() emits, so a redacted value
// is not mistaken for a live secret.
var markerRe = regexp.MustCompile(`\[[A-Z-]*REDACTED[A-Z-]*\]`)

// ContainsSecret reports whether s still contains a known secret pattern
// or a registered exact value. Used by tests to prove nothing leaked
// into stored state.
func ContainsSecret(s string) bool {
	for _, v := range extraValues() {
		if v != "" && strings.Contains(s, v) {
			return true
		}
	}
	s = markerRe.ReplaceAllString(s, "")
	for _, p := range patterns {
		if p.re.MatchString(s) {
			return true
		}
	}
	if containsBare40(s) {
		return true
	}
	return false
}
