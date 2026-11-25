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
	"strconv"
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
var costRe = regexp.MustCompile(`"cost_usd"\s*:\s*([0-9]*\.?[0-9]+)`)

// pricePerMTok reads a per-million-token price (dollars) from the
// environment. Defaults are 0: free local models cost nothing unless
// the operator configures pricing.
//
//	CREWWATCH_PRICE_INPUT_PER_MTOK  — dollars per 1M input tokens
//	CREWWATCH_PRICE_OUTPUT_PER_MTOK — dollars per 1M output tokens
func pricePerMTok(name string) float64 {
	v, err := strconv.ParseFloat(os.Getenv(name), 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// costFromTokens applies the configured per-adapter price table to
// parsed token counts. With no pricing configured the cost is $0
// (free local models); an adapter that reports cost_usd itself takes
// precedence (see parseCost).
func costFromTokens(in, out int64) float64 {
	return float64(in)/1e6*pricePerMTok("CREWWATCH_PRICE_INPUT_PER_MTOK") +
		float64(out)/1e6*pricePerMTok("CREWWATCH_PRICE_OUTPUT_PER_MTOK")
}

// WorkerEnvAllowlist is the exact environment a worker receives.
// Workers do NOT get the operator's full environment (B8): only these
// variables are passed, plus any ExtraEnv the manager supplies.
//   - PATH, HOME, USER, TERM, LANG, LC_ALL, LC_CTYPE, TZ: the minimal
//     locale/identity surface a CLI needs to run.
//   - CREWWATCH_*: Crewwatch's own variables (e.g. the test canary).
//   - *_API_KEY: the API keys the coding-agent CLIs need to authenticate
//     (e.g. ANTHROPIC_API_KEY, OPENAI_API_KEY). Their VALUES are
//     registered for exact-value redaction, so a key a worker echoes
//     into its transcript is scrubbed before storage.
//
// Anything else in the operator's environment (other tokens, session
// credentials, unrelated secrets) is never visible to a worker.
var WorkerEnvAllowlist = []string{
	"PATH", "HOME", "USER", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
}

// WorkerEnv builds the environment for a worker process: the allowlist
// above, plus CREWWATCH_* and *_API_KEY variables from the operator's
// environment, plus req.ExtraEnv. It also registers every passed value
// (except the non-secret system values PATH/HOME/USER/TERM/LANG/LC_*/TZ)
// for exact-value redaction, and returns the env list.
func WorkerEnv(req Request) []string {
	env := []string{}
	seen := map[string]bool{}
	add := func(kv string) {
		if k, _, ok := strings.Cut(kv, "="); ok {
			if seen[k] {
				return
			}
			seen[k] = true
		}
		env = append(env, kv)
	}
	nonSecret := map[string]bool{
		"PATH": true, "HOME": true, "USER": true, "TERM": true,
		"LANG": true, "LC_ALL": true, "LC_CTYPE": true, "TZ": true,
	}
	var secretVals []string
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		allowed := false
		for _, a := range WorkerEnvAllowlist {
			if k == a {
				allowed = true
				break
			}
		}
		if !allowed && (strings.HasPrefix(k, "CREWWATCH_") || strings.HasSuffix(k, "_API_KEY")) {
			allowed = true
		}
		if !allowed {
			continue
		}
		add(kv)
		if !nonSecret[k] {
			secretVals = append(secretVals, v)
		}
	}
	for _, kv := range req.ExtraEnv {
		add(kv)
		if _, v, ok := strings.Cut(kv, "="); ok {
			secretVals = append(secretVals, v)
		}
	}
	redact.AddValues(secretVals)
	return env
}

// KillTree SIGKILLs pid, every descendant found by walking /proc, and
// the whole process group. A plain group kill misses grandchildren
// that called setsid; the /proc walk catches them while they are still
// descendants of the worker. Residual: a process that double-forked and
// whose parent already exited is reparented to init (ppid 1) and no
// longer appears as a descendant — it cannot be found this way.
func KillTree(pid int) {
	if pid <= 0 {
		return
	}
	// Walk /proc to build the parent map.
	children := map[int][]int{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		p, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// stat format: pid (comm) state ppid ... — comm may contain
		// spaces/parens, so find the last ')'.
		s := string(raw)
		i := strings.LastIndex(s, ")")
		if i < 0 {
			continue
		}
		fields := strings.Fields(s[i+1:])
		if len(fields) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		children[ppid] = append(children[ppid], p)
	}
	// Collect all descendants, deepest first.
	var order []int
	var walk func(int)
	walk = func(p int) {
		for _, c := range children[p] {
			walk(c)
			order = append(order, c)
		}
	}
	walk(pid)
	for _, p := range order {
		_ = syscall.Kill(p, syscall.SIGKILL)
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

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
	cmd.Env = WorkerEnv(req)
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
		// Kill the whole process tree (group + /proc descendants),
		// then wait for reaping.
		timedOut = true
		if cmd.Process != nil {
			KillTree(cmd.Process.Pid)
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
	// Best-effort token and cost accounting from JSON-flavoured output.
	// Cost comes from an adapter-reported cost_usd field when present,
	// otherwise from the configured per-token price table (default $0).
	tin, tout := parseTokenParts(out.String())
	res.Tokens = tin + tout
	if c := parseCost(out.String()); c >= 0 {
		res.CostUSD = c
	} else {
		res.CostUSD = costFromTokens(tin, tout)
	}
	return res, nil
}

func parseTokenParts(s string) (in, out int64) {
	for _, m := range tokenRe.FindAllStringSubmatch(s, -1) {
		var n int64
		fmt.Sscanf(m[1], "%d", &n)
		in += n
	}
	for _, m := range outTokenRe.FindAllStringSubmatch(s, -1) {
		var n int64
		fmt.Sscanf(m[1], "%d", &n)
		out += n
	}
	return in, out
}

// parseCost returns the adapter-reported cost_usd, or -1 if absent.
func parseCost(s string) float64 {
	m := costRe.FindStringSubmatch(s)
	if m == nil {
		return -1
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return -1
	}
	return v
}

func parseTokens(s string) int64 {
	in, out := parseTokenParts(s)
	return in + out
}
