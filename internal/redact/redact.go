// Package redact removes secrets from text before it is stored in logs,
// transcripts, receipts, or the audit trail. A value that looks like a
// credential is replaced, never stored.
package redact

import (
	"os"
	"regexp"
	"strings"
)

var patterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// AWS access key IDs.
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "[REDACTED-AWS-KEY]"},
	// OpenAI-style keys and similar sk- tokens.
	{regexp.MustCompile(`sk-[A-Za-z0-9_\-]{16,}`), "[REDACTED]"},
	// GitHub tokens.
	{regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`), "[REDACTED]"},
	{regexp.MustCompile(`gho_[A-Za-z0-9]{20,}`), "[REDACTED]"},
	{regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`), "[REDACTED]"},
	// PEM private key blocks (whole block, including newlines).
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), "[REDACTED-PRIVATE-KEY]"},
	// Generic key=value assignments for common secret names.
	{regexp.MustCompile(`(?i)(api[_-]?key|apikey|token|secret|password|passwd)\s*[:=]\s*\S+`), `${1}=[REDACTED]`},
}

// String returns s with all known secret patterns replaced.
// If the CREWWATCH_CANARY environment variable is set, its literal value
// is also replaced (the test fixture uses this to prove redaction).
func String(s string) string {
	if canary := os.Getenv("CREWWATCH_CANARY"); canary != "" {
		s = strings.ReplaceAll(s, canary, "[REDACTED-CANARY]")
	}
	for _, p := range patterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}

// markerRe matches the placeholders String() emits, so a redacted value
// is not mistaken for a live secret.
var markerRe = regexp.MustCompile(`\[[A-Z-]*REDACTED[A-Z-]*\]`)

// ContainsSecret reports whether s still contains a known secret pattern.
// Used by tests to prove nothing leaked into stored state.
func ContainsSecret(s string) bool {
	if canary := os.Getenv("CREWWATCH_CANARY"); canary != "" && strings.Contains(s, canary) {
		return true
	}
	s = markerRe.ReplaceAllString(s, "")
	for _, p := range patterns {
		if p.re.MatchString(s) {
			return true
		}
	}
	return false
}
