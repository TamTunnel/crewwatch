// Package manager owns the goal lifecycle: decompose a goal into tasks,
// dispatch workers into isolated git worktrees, verify results with the
// repo's own checks, and close tasks only when verification passes. A
// worker's self-report is never sufficient. The manager never merges and
// never pushes: a verified task waits in its worktree for a human.
package manager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TamTunnel/crewwatch/internal/adapter"
	"github.com/TamTunnel/crewwatch/internal/audit"
	"github.com/TamTunnel/crewwatch/internal/receipt"
	"github.com/TamTunnel/crewwatch/internal/redact"
	"github.com/TamTunnel/crewwatch/internal/state"
)

// Disclosure is printed to stderr on every dispatch and appears in the
// README and --help: workers run with the operator's credentials and
// filesystem access. There is no sandbox in v1.
const Disclosure = "crewwatch: workers run with your credentials and filesystem access (no sandbox in v1)"

// Spec is a goal definition file.
type Spec struct {
	Title       string     `json:"title"`
	Repo        string     `json:"repo"`
	Adapter     string     `json:"adapter"`
	TimeoutSecs int        `json:"timeout_secs"`
	Tasks       []TaskSpec `json:"tasks"`
}

// TaskSpec is one task inside a goal spec.
type TaskSpec struct {
	Title       string `json:"title"`
	Acceptance  string `json:"acceptance"`
	VerifyCmd   string `json:"verify_cmd"`
	ScriptCmd   string `json:"script_cmd"`
	MaxAttempts int    `json:"max_attempts"`
}

// Manager owns one Crewwatch home directory.
type Manager struct {
	Home  string
	Store *state.Store
	Audit *audit.Log
	Priv  ed25519.PrivateKey
}

// New opens the home directory (creating it), the state DB, the audit log,
// and the signing key. Home defaults to ~/.crewwatch.
func New(home string) (*Manager, error) {
	if home == "" {
		hd, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		home = filepath.Join(hd, ".crewwatch")
	}
	for _, sub := range []string{"", "worktrees", "transcripts", "receipts", "running"} {
		if err := os.MkdirAll(filepath.Join(home, sub), 0o700); err != nil {
			return nil, err
		}
	}
	store, err := state.Open(filepath.Join(home, "crewwatch.db"))
	if err != nil {
		return nil, err
	}
	alog, err := audit.Open(filepath.Join(home, "audit.jsonl"))
	if err != nil {
		store.Close()
		return nil, err
	}
	priv, err := receipt.LoadOrCreateKey(home)
	if err != nil {
		store.Close()
		return nil, err
	}
	// Register the default adapters (idempotent).
	for _, d := range adapter.DefaultAdapters() {
		args, _ := json.Marshal(d.Args)
		caps, _ := json.Marshal(d.Capabilities)
		if err := store.RegisterAdapter(d.Name, d.CLI, string(args), string(caps), true); err != nil {
			store.Close()
			return nil, err
		}
	}
	return &Manager{Home: home, Store: store, Audit: alog, Priv: priv}, nil
}

// Close releases state.
func (m *Manager) Close() error { return m.Store.Close() }

func newID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

func (m *Manager) auditEvent(event string, fields map[string]any) {
	payload := map[string]any{"event": event}
	for k, v := range fields {
		if s, ok := v.(string); ok {
			payload[k] = redact.String(s)
		} else {
			payload[k] = v
		}
	}
	_, _ = m.Audit.Append(payload)
}

// --- goal intake ---

// AddGoal validates a spec and creates a running goal. A task without a
// verify command gets the repo's default (go test / npm test); if none can
// be determined the goal is rejected — a task that cannot be verified must
// never be dispatched.
func (m *Manager) AddGoal(spec *Spec) (*state.Goal, error) {
	if strings.TrimSpace(spec.Title) == "" {
		return nil, fmt.Errorf("goal: title is required")
	}
	if strings.TrimSpace(spec.Repo) == "" {
		return nil, fmt.Errorf("goal: repo path is required")
	}
	if _, err := os.Stat(spec.Repo); err != nil {
		return nil, fmt.Errorf("goal: repo %q: %w", spec.Repo, err)
	}
	if out, err := exec.Command("git", "-C", spec.Repo, "rev-parse", "--git-dir").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("goal: %q is not a git repo: %s", spec.Repo, strings.TrimSpace(string(out)))
	}
	if spec.Adapter == "" {
		spec.Adapter = "opencode"
	}
	if spec.Adapter != "script" {
		if _, err := adapter.Lookup(spec.Adapter); err != nil {
			return nil, fmt.Errorf("goal: %w", err)
		}
	}
	if spec.TimeoutSecs <= 0 {
		spec.TimeoutSecs = 600
	}
	for i := range spec.Tasks {
		t := &spec.Tasks[i]
		if strings.TrimSpace(t.Title) == "" {
			return nil, fmt.Errorf("goal: task %d has no title", i)
		}
		if t.VerifyCmd == "" {
			t.VerifyCmd = defaultVerifyCmd(spec.Repo)
		}
		if t.VerifyCmd == "" {
			return nil, fmt.Errorf("goal: task %q has no verify_cmd and no default could be detected for repo %q (add go test / npm test support or set verify_cmd)", t.Title, spec.Repo)
		}
		if t.MaxAttempts <= 0 {
			t.MaxAttempts = 3
		}
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	g := &state.Goal{
		ID: newID("goal"), Title: spec.Title, Repo: spec.Repo,
		SpecJSON: string(raw), Status: state.GoalRunning,
	}
	if err := m.Store.CreateGoal(g); err != nil {
		return nil, err
	}
	for _, ts := range spec.Tasks {
		t := &state.Task{
			ID: newID("task"), GoalID: g.ID, Title: ts.Title,
			Acceptance: ts.Acceptance, VerifyCmd: ts.VerifyCmd,
			ScriptCmd: ts.ScriptCmd, MaxAttempts: ts.MaxAttempts,
			Status: state.TaskPending, Adapter: spec.Adapter,
		}
		if err := m.Store.CreateTask(t); err != nil {
			return nil, err
		}
	}
	m.auditEvent("goal_added", map[string]any{"goal_id": g.ID, "title": g.Title, "repo": g.Repo, "tasks": int64(len(spec.Tasks))})
	return g, nil
}

// defaultVerifyCmd detects the repo's test command.
func defaultVerifyCmd(repo string) string {
	if _, err := os.Stat(filepath.Join(repo, "go.mod")); err == nil {
		return "go test ./..."
	}
	if _, err := os.Stat(filepath.Join(repo, "package.json")); err == nil {
		return "npm test"
	}
	return ""
}

// --- decomposition ---

// decompose turns a running goal with no tasks into tasks. Explicit tasks
// in the spec were already created at intake; this path only runs for
// goals that arrived taskless. It asks the goal's adapter to propose a
// task list as JSON; anything unparseable or empty fails the goal closed
// with zero dispatches.
func (m *Manager) decompose(ctx context.Context, g *state.Goal) error {
	var spec Spec
	if err := json.Unmarshal([]byte(g.SpecJSON), &spec); err != nil {
		return m.blockGoal(g, fmt.Sprintf("bad spec: %v", err))
	}
	prompt := "Decompose this engineering goal into concrete tasks. " +
		"Reply with ONLY a JSON array of objects with keys title, acceptance, verify_cmd. " +
		"Goal: " + spec.Title + "\nRepo: " + spec.Repo
	ad, err := m.adapterFor(&state.Task{Adapter: spec.Adapter})
	if err != nil {
		return m.blockGoal(g, err.Error())
	}
	work := filepath.Join(m.Home, "worktrees", "decompose-"+g.ID)
	_ = os.MkdirAll(work, 0o700)
	res, err := ad.Dispatch(ctx, adapter.Request{
		TaskID: "decompose-" + g.ID, Title: "decompose", WorkDir: work,
		Prompt: prompt, Timeout: 5 * time.Minute,
	})
	if err != nil {
		return m.blockGoal(g, fmt.Sprintf("decomposition failed: %v", err))
	}
	var tasks []TaskSpec
	if err := extractJSONArray(res.Transcript, &tasks); err != nil || len(tasks) == 0 {
		return m.blockGoal(g, "goal could not be decomposed into tasks (no parseable task list); failing closed with zero dispatches")
	}
	for _, ts := range tasks {
		if strings.TrimSpace(ts.Title) == "" {
			continue
		}
		if ts.VerifyCmd == "" {
			ts.VerifyCmd = defaultVerifyCmd(spec.Repo)
		}
		if ts.VerifyCmd == "" || ts.MaxAttempts <= 0 {
			if ts.MaxAttempts <= 0 {
				ts.MaxAttempts = 3
			}
			if ts.VerifyCmd == "" {
				continue
			}
		}
		t := &state.Task{
			ID: newID("task"), GoalID: g.ID, Title: ts.Title,
			Acceptance: ts.Acceptance, VerifyCmd: ts.VerifyCmd,
			MaxAttempts: ts.MaxAttempts, Status: state.TaskPending, Adapter: spec.Adapter,
		}
		if err := m.Store.CreateTask(t); err != nil {
			return err
		}
	}
	m.auditEvent("goal_decomposed", map[string]any{"goal_id": g.ID, "tasks": int64(len(tasks))})
	return nil
}

func (m *Manager) blockGoal(g *state.Goal, reason string) error {
	if err := m.Store.SetGoalStatus(g.ID, state.GoalBlocked, reason); err != nil {
		return err
	}
	m.auditEvent("goal_blocked", map[string]any{"goal_id": g.ID, "reason": reason})
	return nil
}

// extractJSONArray finds the first JSON array in s and decodes it into out.
func extractJSONArray(s string, out any) error {
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start < 0 || end <= start {
		return fmt.Errorf("no JSON array found")
	}
	return json.Unmarshal([]byte(s[start:end+1]), out)
}

// --- daemon loop ---

// Tick performs one unit of daemon work: reap stale state, decompose a
// taskless goal, or process one pending task. It returns true if it did
// work (so the caller can loop without sleeping).
func (m *Manager) Tick(ctx context.Context) (bool, error) {
	if err := m.reapStale(); err != nil {
		return false, err
	}
	if g, err := m.Store.NextPendingGoal(); err != nil {
		return false, err
	} else if g != nil {
		if err := m.decompose(ctx, g); err != nil {
			return false, err
		}
		return true, nil
	}
	t, err := m.Store.NextPendingTask()
	if err != nil {
		return false, err
	}
	if t == nil {
		return false, nil
	}
	if err := m.processTask(ctx, t); err != nil {
		return true, err
	}
	return true, nil
}

// Run loops Tick until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		did, err := m.Tick(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "crewwatch: tick error: %v\n", redact.String(err.Error()))
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		if !did {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
}

// RunUntilIdle ticks until there is no more work or ctx ends. Used by
// tests, the smoke run, and the eval harness.
func (m *Manager) RunUntilIdle(ctx context.Context) error {
	for i := 0; i < 10000; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		did, err := m.Tick(ctx)
		if err != nil {
			return err
		}
		if !did {
			return nil
		}
	}
	return fmt.Errorf("manager: RunUntilIdle hit the tick limit — possible loop")
}

// reapStale recovers from a dead daemon: tasks left in dispatched or
// verifying, and their running attempts, are marked interrupted and the
// tasks return to pending. No new attempt is created here, so attempt
// counts prove no duplicated dispatches.
func (m *Manager) reapStale() error {
	running, err := m.Store.RunningAttempts()
	if err != nil {
		return err
	}
	for _, a := range running {
		a.Status = state.AttemptInterrupted
		a.EndedAt = time.Now().Unix()
		if err := m.Store.FinishAttempt(a); err != nil {
			return err
		}
	}
	stale, err := m.Store.StaleTasks()
	if err != nil {
		return err
	}
	for _, t := range stale {
		g, err := m.Store.GetGoal(t.GoalID)
		if err != nil || g.Status != state.GoalRunning {
			continue
		}
		if err := m.Store.SetTaskStatus(t.ID, state.TaskPending); err != nil {
			return err
		}
		m.auditEvent("task_recovered", map[string]any{"task_id": t.ID, "goal_id": t.GoalID})
	}
	return nil
}

// --- task processing ---

func (m *Manager) adapterFor(t *state.Task) (adapter.Adapter, error) {
	if t.ScriptCmd != "" {
		return adapter.NewScriptAdapter(t.ScriptCmd), nil
	}
	if t.Adapter == "" {
		t.Adapter = "opencode"
	}
	return adapter.Lookup(t.Adapter)
}

func (m *Manager) processTask(ctx context.Context, t *state.Task) error {
	g, err := m.Store.GetGoal(t.GoalID)
	if err != nil {
		return err
	}
	var spec Spec
	_ = json.Unmarshal([]byte(g.SpecJSON), &spec)
	timeout := time.Duration(spec.TimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	// Worktree: create once per task, reuse across repair retries.
	worktree, branch, err := m.ensureWorktree(g.Repo, t)
	if err != nil {
		// A task that cannot get a worktree can never run: escalate it
		// instead of retry-looping on it forever.
		return m.escalate(t, g, fmt.Sprintf("worktree setup failed: %v", err))
	}
	if err := m.Store.SetTaskWorktree(t.ID, worktree, branch, t.Adapter); err != nil {
		return err
	}
	if err := m.Store.SetTaskStatus(t.ID, state.TaskDispatched); err != nil {
		return err
	}

	// Build the prompt, including prior failures for repair attempts.
	attempts, _ := m.Store.AttemptsForTask(t.ID)
	var failures strings.Builder
	for _, a := range attempts {
		if a.Status == state.AttemptFailed || a.Status == state.AttemptTimeout {
			fmt.Fprintf(&failures, "Previous attempt failed (exit %d). Fix the problem; do not repeat the same approach blindly.\n", a.ExitCode)
		}
	}
	prompt := fmt.Sprintf("You are working in a git worktree at %s. Do not write outside it.\n\nTask: %s\nAcceptance: %s\n\n%s\nRun the verification command yourself before claiming done (%s). End with a short summary of what you changed.",
		worktree, t.Title, t.Acceptance, failures.String(), t.VerifyCmd)

	ad, err := m.adapterFor(t)
	if err != nil {
		return m.escalate(t, g, fmt.Sprintf("no worker adapter: %v", err))
	}
	fmt.Fprintln(os.Stderr, Disclosure)

	// Snapshot the main checkout: a worker that writes outside its
	// worktree is an escape. There is no sandbox in v1, so the manager
	// detects the escape and escalates instead of attributing it.
	beforeStatus := m.repoStatusHash(g.Repo)

	// Last check before dispatch: the goal may have been cancelled while
	// the worktree was being set up. Never dispatch into a dead goal.
	if g2, err := m.Store.GetGoal(g.ID); err == nil && g2.Status != state.GoalRunning {
		if g2.Status == state.GoalCancelled {
			m.RemoveWorktree(g.Repo, worktree, branch)
			_ = m.Store.SetTaskStatus(t.ID, state.TaskCancelled)
		}
		return nil
	}

	attempt := &state.Attempt{
		ID: newID("attempt"), TaskID: t.ID, Adapter: ad.Name(),
		Status: state.AttemptRunning, StartedAt: time.Now().Unix(),
	}
	if err := m.Store.CreateAttempt(attempt); err != nil {
		return err
	}
	pidFile := filepath.Join(m.Home, "running", t.ID+".pid")
	res, dispatchErr := ad.Dispatch(ctx, adapter.Request{
		TaskID: t.ID, Title: t.Title, Acceptance: t.Acceptance,
		WorkDir: worktree, Prompt: prompt, Timeout: timeout, PIDFile: pidFile,
	})
	m.auditEvent("task_dispatched", map[string]any{"task_id": t.ID, "goal_id": t.GoalID, "adapter": ad.Name(), "attempt": attempt.ID})
	if dispatchErr != nil {
		attempt.Status = state.AttemptFailed
		attempt.EndedAt = time.Now().Unix()
		attempt.DurationMs = time.Since(time.Unix(attempt.StartedAt, 0)).Milliseconds()
		_ = m.Store.FinishAttempt(attempt)
		return m.failOrEscalate(t, g, fmt.Sprintf("dispatch failed: %v", dispatchErr))
	}

	// Transcript: manager header/footer with timestamps so cost and
	// duration reconcile against the stored attempt (probe 7).
	started := time.Unix(attempt.StartedAt, 0).UTC().Format(time.RFC3339)
	ended := time.Now().UTC().Format(time.RFC3339)
	transcript := fmt.Sprintf("=== crewwatch attempt %s started %s ===\n%s\n=== ended %s duration_ms=%d ===\n",
		attempt.ID, started, res.Transcript, ended, res.DurationMs)
	transcriptPath := filepath.Join(m.Home, "transcripts", attempt.ID+".log")
	if err := os.WriteFile(transcriptPath, []byte(transcript), 0o644); err != nil {
		return err
	}

	// The goal may have been cancelled while the worker ran. If so, stop
	// here: no verification, no receipt, no retry. A cancelled goal's
	// worktree is removed so nothing is left running or checked out.
	if g2, err := m.Store.GetGoal(g.ID); err == nil && g2.Status != state.GoalRunning {
		attempt.Status = state.AttemptInterrupted
		attempt.EndedAt = time.Now().Unix()
		attempt.ExitCode = res.ExitCode
		attempt.DurationMs = res.DurationMs
		attempt.TranscriptRef = transcriptPath
		_ = m.Store.FinishAttempt(attempt)
		if g2.Status == state.GoalCancelled {
			m.RemoveWorktree(g.Repo, worktree, branch)
			_ = m.Store.SetTaskStatus(t.ID, state.TaskCancelled)
		}
		return nil
	}

	// Worktree escape: the main checkout must be exactly as it was.
	if after := m.repoStatusHash(g.Repo); after != beforeStatus {
		attempt.Status = state.AttemptFailed
		attempt.EndedAt = time.Now().Unix()
		attempt.ExitCode = res.ExitCode
		attempt.DurationMs = res.DurationMs
		attempt.TranscriptRef = transcriptPath
		if err := m.Store.FinishAttempt(attempt); err != nil {
			return err
		}
		return m.escalate(t, g, "worker wrote outside its worktree (main checkout changed) — escalated")
	}

	// Diff hash of the worktree vs HEAD.
	diffHash := m.diffHash(worktree)

	// Verification: the repo's own checks, run by the manager. The
	// worker's claim is ignored.
	if err := m.Store.SetTaskStatus(t.ID, state.TaskVerifying); err != nil {
		return err
	}
	verifyOut, verifyErr := m.runVerify(worktree, t.VerifyCmd)
	verifyText := redact.String(verifyOut)
	// Append verification output to the transcript file.
	if f, err := os.OpenFile(transcriptPath, os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, "=== verification: %s ===\n%s\n", t.VerifyCmd, verifyText)
		f.Close()
	}

	attempt.EndedAt = time.Now().Unix()
	attempt.ExitCode = res.ExitCode
	attempt.DiffHash = diffHash
	attempt.CostTokens = res.Tokens
	attempt.CostUSD = res.CostUSD
	attempt.DurationMs = res.DurationMs
	attempt.TranscriptRef = transcriptPath
	if res.TimedOut {
		attempt.Status = state.AttemptTimeout
	} else if res.ExitCode != 0 {
		attempt.Status = state.AttemptFailed
	} else {
		attempt.Status = state.AttemptCompleted
	}
	if err := m.Store.FinishAttempt(attempt); err != nil {
		return err
	}
	m.auditEvent("attempt_finished", map[string]any{"task_id": t.ID, "attempt": attempt.ID, "status": attempt.Status, "exit_code": int64(res.ExitCode)})

	// The goal may have been cancelled during verification. If so, stop:
	// no close, no retry — CancelGoal already marked the task cancelled.
	if g2, err := m.Store.GetGoal(g.ID); err == nil && g2.Status != state.GoalRunning {
		if g2.Status == state.GoalCancelled {
			m.RemoveWorktree(g.Repo, worktree, branch)
			_ = m.Store.SetTaskStatus(t.ID, state.TaskCancelled)
		}
		return nil
	}

	verified := verifyErr == nil && (strings.TrimSpace(verifyText) != "" || diffHash != emptySHA256())
	if !verified {
		reason := "verification failed"
		if verifyErr == nil {
			reason = "verification produced no evidence (empty output and empty diff) — escalated"
			return m.escalate(t, g, reason)
		}
		return m.failOrEscalate(t, g, reason+": "+redact.String(verifyErr.Error()))
	}
	if res.TimedOut || res.ExitCode != 0 {
		// The worker failed but verification passed anyway (e.g. a
		// previous attempt's changes verified). The task still closes:
		// verification is king.
		m.auditEvent("task_closed_despite_worker_failure", map[string]any{"task_id": t.ID, "exit_code": int64(res.ExitCode)})
	}
	return m.closeTask(t, g, attempt, diffHash)
}

func emptySHA256() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}

// failOrEscalate retries a failed task until its attempt budget is spent,
// then escalates it to the human and blocks the goal.
func (m *Manager) failOrEscalate(t *state.Task, g *state.Goal, reason string) error {
	// A cancelled goal must never be retried or re-blocked.
	if g2, err := m.Store.GetGoal(g.ID); err == nil && g2.Status == state.GoalCancelled {
		_ = m.Store.SetTaskStatus(t.ID, state.TaskCancelled)
		return nil
	}
	done, err := m.Store.CountAttempts(t.ID, state.AttemptCompleted)
	if err != nil {
		return err
	}
	failed, err := m.Store.CountAttempts(t.ID, state.AttemptFailed)
	if err != nil {
		return err
	}
	timedOut, err := m.Store.CountAttempts(t.ID, state.AttemptTimeout)
	if err != nil {
		return err
	}
	used := done + failed + timedOut
	if used < t.MaxAttempts {
		if err := m.Store.SetTaskStatus(t.ID, state.TaskPending); err != nil {
			return err
		}
		m.auditEvent("task_retry", map[string]any{"task_id": t.ID, "attempts_used": int64(used), "max_attempts": int64(t.MaxAttempts), "reason": reason})
		return nil
	}
	return m.escalate(t, g, fmt.Sprintf("attempt budget spent (%d attempts): %s", used, reason))
}

func (m *Manager) escalate(t *state.Task, g *state.Goal, reason string) error {
	// A cancelled goal must never be overwritten to blocked.
	if g2, err := m.Store.GetGoal(g.ID); err == nil && g2.Status == state.GoalCancelled {
		_ = m.Store.SetTaskStatus(t.ID, state.TaskCancelled)
		return nil
	}
	if err := m.Store.SetTaskStatus(t.ID, state.TaskEscalated); err != nil {
		return err
	}
	if err := m.Store.SetGoalStatus(g.ID, state.GoalBlocked, fmt.Sprintf("task %q escalated: %s", t.Title, reason)); err != nil {
		return err
	}
	m.auditEvent("task_escalated", map[string]any{"task_id": t.ID, "goal_id": g.ID, "reason": reason})
	return nil
}

// closeTask issues the signed receipt and marks the task (and the goal,
// when all its tasks are done) complete.
func (m *Manager) closeTask(t *state.Task, g *state.Goal, attempt *state.Attempt, diffHash string) error {
	if err := m.Store.SetTaskStatus(t.ID, state.TaskDone); err != nil {
		return err
	}
	payload := receipt.Payload{
		GoalID: g.ID, TaskID: t.ID, Title: t.Title,
		WorkerAdapter: attempt.Adapter,
		Attempts:      len(mustAttempts(m.Store, t.ID)),
		DiffSHA256:    diffHash, VerifyCmd: t.VerifyCmd,
		VerifiedAt: time.Now().Unix(), DurationMs: attempt.DurationMs,
		CostTokens: attempt.CostTokens, CostUSD: attempt.CostUSD,
	}
	r, err := receipt.Sign(payload, m.Priv)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	receiptPath := filepath.Join(m.Home, "receipts", r.Payload.ReceiptID+".json")
	if err := os.WriteFile(receiptPath, raw, 0o644); err != nil {
		return err
	}
	if err := m.Store.SaveReceipt(t.ID, string(raw), r.Signature, r.Payload.ReceiptID); err != nil {
		return err
	}
	m.auditEvent("receipt_issued", map[string]any{"task_id": t.ID, "receipt_id": r.Payload.ReceiptID, "path": receiptPath})
	m.auditEvent("task_closed", map[string]any{"task_id": t.ID, "goal_id": g.ID})

	tasks, err := m.Store.TasksForGoal(g.ID)
	if err != nil {
		return err
	}
	allDone := true
	for _, tk := range tasks {
		if tk.Status != state.TaskDone {
			allDone = false
			break
		}
	}
	if allDone && len(tasks) > 0 {
		if err := m.Store.SetGoalStatus(g.ID, state.GoalDone, ""); err != nil {
			return err
		}
		m.auditEvent("goal_done", map[string]any{"goal_id": g.ID})
	}
	return nil
}

func mustAttempts(s *state.Store, taskID string) []*state.Attempt {
	a, _ := s.AttemptsForTask(taskID)
	return a
}

// --- verification ---

// runVerify runs cmd in dir with a 5-minute timeout and returns combined
// output. A non-zero exit is an error.
func (m *Manager) runVerify(dir, cmdline string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdline)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("verify %q failed: %w", cmdline, err)
	}
	return string(out), nil
}

// diffHash returns the sha256 of `git diff HEAD` in the worktree.
func (m *Manager) diffHash(worktree string) string {
	out, err := exec.Command("git", "-C", worktree, "diff", "HEAD").Output()
	if err != nil {
		return emptySHA256()
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:])
}

// repoStatusHash returns the sha256 of `git status --porcelain` for the
// main checkout — used to detect a worker escaping its worktree.
func (m *Manager) repoStatusHash(repo string) string {
	out, err := exec.Command("git", "-C", repo, "status", "--porcelain").Output()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:])
}

// --- worktrees ---

func (m *Manager) ensureWorktree(repo string, t *state.Task) (string, string, error) {
	branch := "cw-" + t.ID
	path := filepath.Join(m.Home, "worktrees", t.ID)
	if _, err := os.Stat(path); err == nil {
		return path, branch, nil // reuse across repair retries
	}
	cmd := exec.Command("git", "-C", repo, "worktree", "add", "-b", branch, path, "HEAD")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("worktree add failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return path, branch, nil
}

// RemoveWorktree removes a task's worktree and branch. Best effort.
func (m *Manager) RemoveWorktree(repo, worktree, branch string) {
	if worktree != "" {
		_, _ = exec.Command("git", "-C", repo, "worktree", "remove", "--force", worktree).CombinedOutput()
	}
	if branch != "" {
		_, _ = exec.Command("git", "-C", repo, "branch", "-D", branch).CombinedOutput()
	}
	_, _ = exec.Command("git", "-C", repo, "worktree", "prune").CombinedOutput()
}

// ReapOrphans removes worktree dirs no live task references.
func (m *Manager) ReapOrphans() error {
	entries, err := os.ReadDir(filepath.Join(m.Home, "worktrees"))
	if err != nil {
		return err
	}
	live := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "decompose-") {
			continue
		}
		t, err := m.Store.GetTask(e.Name())
		if err != nil || t == nil {
			live[e.Name()] = false
			continue
		}
		live[e.Name()] = true
	}
	for name, ok := range live {
		if ok {
			continue
		}
		_ = os.RemoveAll(filepath.Join(m.Home, "worktrees", name))
	}
	return nil
}

// --- cancellation ---

// CancelGoal stops a goal: kills any running workers (via their pid files),
// removes non-done worktrees, marks tasks cancelled and the goal cancelled.
// The goal status is set FIRST so a concurrently ticking daemon sees the
// cancellation before it can re-dispatch or retry a task.
func (m *Manager) CancelGoal(goalID string) error {
	g, err := m.Store.GetGoal(goalID)
	if err != nil {
		return err
	}
	if err := m.Store.SetGoalStatus(goalID, state.GoalCancelled, "cancelled by operator"); err != nil {
		return err
	}
	tasks, err := m.Store.TasksForGoal(goalID)
	if err != nil {
		return err
	}
	for _, t := range tasks {
		if t.Status == state.TaskDone {
			continue
		}
		// Kill the running worker's process group, if any.
		if raw, err := os.ReadFile(filepath.Join(m.Home, "running", t.ID+".pid")); err == nil {
			var pid int
			if _, err := fmt.Sscanf(string(raw), "%d", &pid); err == nil && pid > 0 {
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
			_ = os.Remove(filepath.Join(m.Home, "running", t.ID+".pid"))
		}
		if t.Status == state.TaskDispatched || t.Status == state.TaskVerifying {
			running, _ := m.Store.RunningAttempts()
			for _, a := range running {
				if a.TaskID == t.ID {
					a.Status = state.AttemptInterrupted
					a.EndedAt = time.Now().Unix()
					_ = m.Store.FinishAttempt(a)
				}
			}
		}
		m.RemoveWorktree(g.Repo, t.Worktree, t.Branch)
		_ = m.Store.SetTaskStatus(t.ID, state.TaskCancelled)
	}
	m.auditEvent("goal_cancelled", map[string]any{"goal_id": goalID})
	return nil
}
