// Package adapter defines the worker interface and its implementations.
// A worker adapter shells out to a coding-agent CLI in a git worktree and
// returns the result. The manager never trusts a worker's self-report —
// the verifier decides whether a task is done. Adapters declare their
// command as data (binary + args), so a CLI whose flags change can be
// re-pinned without touching manager code; the exact command can be
// overridden with CREWWATCH_ADAPTER_<NAME>_CMD.
package adapter

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/TamTunnel/crewwatch/internal/redact"
)

// Request is one unit of work handed to a worker.
type Request struct {
	TaskID     string
	Title      string
	Acceptance string
	WorkDir    string
	Prompt     string
	Timeout    time.Duration
	ExtraEnv   []string
	// PIDFile, if set, receives the worker's process-group id while it
	// runs (so a separate process can cancel it). Removed on completion.
	PIDFile string
}

// Result is what a worker run produced.
type Result struct {
	ExitCode   int
	Transcript string // redacted combined output
	Tokens     int64
	CostUSD    float64
	TimedOut   bool
	DurationMs int64
}

// Adapter runs one worker.
type Adapter interface {
	Name() string
	Dispatch(ctx context.Context, req Request) (*Result, error)
}

// Definition pins one CLI adapter's command. {prompt} in Args is replaced
// by the task prompt.
type Definition struct {
	Name         string
	CLI          string
	Args         []string
	Capabilities []string
}

// DefaultAdapters returns the v1 CLI adapters. "Hermes" is deliberately
// absent: it is a model family, not a CLI — pin a runner (e.g. OpenCode
// pointed at a local Hermes endpoint) or drop it from v1.
func DefaultAdapters() []Definition {
	return []Definition{
		{Name: "opencode", CLI: "opencode", Args: []string{"run", "{prompt}"}, Capabilities: []string{"streaming"}},
		{Name: "qwen", CLI: "qwen", Args: []string{"-p", "{prompt}"}, Capabilities: []string{"non-interactive"}},
		{Name: "claude", CLI: "claude", Args: []string{"-p", "--output-format", "text", "{prompt}"}, Capabilities: []string{"non-interactive"}},
		{Name: "codex", CLI: "codex", Args: []string{"exec", "{prompt}"}, Capabilities: []string{"non-interactive"}},
		{Name: "gemini", CLI: "gemini", Args: []string{"-p", "{prompt}"}, Capabilities: []string{"non-interactive"}},
	}
}

// Lookup returns the adapter for name, or an error if unknown.
func Lookup(name string) (Adapter, error) {
	if name == "script" {
		return nil, fmt.Errorf("adapter: script adapter needs a command; use NewScriptAdapter")
	}
	for _, d := range DefaultAdapters() {
		if d.Name == name {
			return &cliAdapter{def: d}, nil
		}
	}
	return nil, fmt.Errorf("adapter: unknown adapter %q", name)
}

// cliAdapter shells out to a coding-agent CLI.
type cliAdapter struct{ def Definition }

func (a *cliAdapter) Name() string { return a.def.Name }

func (a *cliAdapter) Dispatch(ctx context.Context, req Request) (*Result, error) {
	bin, args := a.def.CLI, a.def.Args
	if override := os.Getenv("CREWWATCH_ADAPTER_" + strings.ToUpper(a.def.Name) + "_CMD"); override != "" {
		parts := strings.Fields(override)
		if len(parts) == 0 {
			return nil, fmt.Errorf("adapter %s: empty CREWWATCH_ADAPTER_%s_CMD", a.def.Name, strings.ToUpper(a.def.Name))
		}
		bin, args = parts[0], parts[1:]
	}
	final := make([]string, 0, len(args)+1)
	for _, arg := range args {
		if arg == "{prompt}" {
			final = append(final, req.Prompt)
		} else {
			final = append(final, arg)
		}
	}
	// If no {prompt} placeholder was present, append the prompt last.
	hasPrompt := false
	for _, arg := range args {
		if arg == "{prompt}" {
			hasPrompt = true
		}
	}
	if !hasPrompt {
		final = append(final, req.Prompt)
	}
	return runCommand(ctx, bin, final, req)
}

// NewScriptAdapter returns an adapter that runs cmd via sh -c in the
// worktree. It exists for the eval harness and tests only: real goals use
// CLI adapters. The manager selects it only for tasks with ScriptCmd set.
func NewScriptAdapter(cmd string) Adapter {
	return &scriptAdapter{cmd: cmd}
}

type scriptAdapter struct{ cmd string }

func (a *scriptAdapter) Name() string { return "script" }

func (a *scriptAdapter) Dispatch(ctx context.Context, req Request) (*Result, error) {
	return runCommand(ctx, "sh", []string{"-c", a.cmd}, req)
}

var tokenRe = regexp.MustCompile(`"(?:input_tokens|prompt_tokens)"\s*:\s*(\d+)`)
var outTokenRe = regexp.MustCompile(`"(?:output_tokens|completion_tokens)"\s*:\s*(\d+)`)

// runCommand executes bin args in req.WorkDir, killing the whole process
// group on timeout (no orphaned grandchildren), and returns the redacted
// combined transcript.
func runCommand(ctx context.Context, bin string, args []string, req Request) (*Result, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Dir = req.WorkDir
	cmd.Env = append(os.Environ(), req.ExtraEnv...)
	// Own process group so a timeout kill takes grandchildren with it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	start := time.Now()
	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("adapter: failed to start %s: %w", bin, err)
	}
	if req.PIDFile != "" {
		// The child is its own process-group leader (Setpgid), so its
		// pid is the group id a canceller needs.
		_ = os.WriteFile(req.PIDFile, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0o644)
		defer os.Remove(req.PIDFile)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
	timedOut := false
	select {
	case waitErr = <-done:
	case <-cctx.Done():
		// Kill the whole process group, then wait for reaping.
		timedOut = true
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		waitErr = <-done
	}
	dur := time.Since(start)

	res := &Result{
		ExitCode:   0,
		Transcript: redact.String(out.String()),
		DurationMs: dur.Milliseconds(),
		TimedOut:   timedOut,
	}
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
		}
	}
	// Best-effort token accounting from JSON-flavoured output.
	res.Tokens = parseTokens(out.String())
	return res, nil
}

func parseTokens(s string) int64 {
	var total int64
	for _, m := range tokenRe.FindAllStringSubmatch(s, -1) {
		var n int64
		fmt.Sscanf(m[1], "%d", &n)
		total += n
	}
	for _, m := range outTokenRe.FindAllStringSubmatch(s, -1) {
		var n int64
		fmt.Sscanf(m[1], "%d", &n)
		total += n
	}
	return total
}
