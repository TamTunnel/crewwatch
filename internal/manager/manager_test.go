package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TamTunnel/crewwatch/internal/audit"
	"github.com/TamTunnel/crewwatch/internal/receipt"
	"github.com/TamTunnel/crewwatch/internal/redact"
	"github.com/TamTunnel/crewwatch/internal/state"
)

// makeRepo creates a temp git repo with the given files, committed.
func makeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
	}
	run("init", "-q")
	run("-c", "user.name=Gina", "-c", "user.email=gina@local", "add", "-A")
	run("-c", "user.name=Gina", "-c", "user.email=gina@local", "commit", "-qm", "init")
	return dir
}

// auditVerify checks the manager's audit log, including the HMAC and
// the SQLite truncation anchor.
func auditVerify(mgr *Manager) error {
	key, err := audit.LoadOrCreateKey(mgr.Home)
	if err != nil {
		return err
	}
	head, _ := mgr.Store.GetMeta("audit_head")
	count, _ := mgr.Store.GetMeta("audit_count")
	return audit.Verify(filepath.Join(mgr.Home, "audit.jsonl"), key, head, audit.ParseCount(count))
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	mgr, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mgr.Close() })
	return mgr
}

func runIdle(t *testing.T, mgr *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := mgr.RunUntilIdle(ctx); err != nil {
		t.Fatalf("RunUntilIdle: %v", err)
	}
}

const calcGo = "package calc\n\nfunc Add(a, b int) int { return a - b }\n"
const calcTest = `package calc

import "testing"

func TestAdd(t *testing.T) {
	if got := Add(2, 3); got != 5 {
		t.Fatalf("Add(2,3) = %d, want 5", got)
	}
}
`

// TestHappyPath is the core loop: dispatch → verify → receipt → goal done.
func TestHappyPath(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	fix := `python3 - <<'EOF'
p = "calc.go"
s = open(p).read().replace("return a - b", "return a + b")
open(p, "w").write(s)
EOF
echo '{"input_tokens": 100, "output_tokens": 50, "cost_usd": 0.0015}'`
	g, err := mgr.AddGoal(&Spec{
		Title: "fix Add", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: []TaskSpec{{Title: "fix Add", Acceptance: "Add returns a+b", VerifyCmd: "go test ./...", ScriptCmd: fix, MaxAttempts: 3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runIdle(t, mgr)
	goal, err := mgr.Store.GetGoal(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if goal.Status != state.GoalDone {
		t.Fatalf("goal status %q, want done (error: %s)", goal.Status, goal.Error)
	}
	tasks, _ := mgr.Store.TasksForGoal(g.ID)
	if len(tasks) != 1 || tasks[0].Status != state.TaskDone {
		t.Fatalf("task status %v", tasks)
	}
	// Receipt exists and verifies offline; tampering fails (probe 8).
	receipts, err := mgr.Store.ReceiptsForTask(tasks[0].ID)
	if err != nil || len(receipts) != 1 {
		t.Fatalf("receipts: %v, err %v", receipts, err)
	}
	var r receipt.Receipt
	if err := json.Unmarshal([]byte(receipts[0]), &r); err != nil {
		t.Fatal(err)
	}
	if err := receipt.Verify(&r); err != nil {
		t.Fatalf("receipt verify: %v", err)
	}
	if r.Payload.Format != "crewwatch/1" {
		t.Fatalf("receipt format %q", r.Payload.Format)
	}
	// Cost accounting reconciles against the transcript (probe 7):
	// tokens and cost are hand-computed from the token JSON the
	// worker emitted (100 in + 50 out, cost_usd 0.0015).
	atts, _ := mgr.Store.AttemptsForTask(tasks[0].ID)
	if len(atts) != 1 {
		t.Fatalf("attempts %d, want 1", len(atts))
	}
	if atts[0].CostTokens != 150 {
		t.Fatalf("tokens %d, want 150 (100 in + 50 out)", atts[0].CostTokens)
	}
	if atts[0].CostUSD != 0.0015 {
		t.Fatalf("cost %v, want 0.0015", atts[0].CostUSD)
	}
	raw, err := os.ReadFile(atts[0].TranscriptRef)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"input_tokens": 100`) || !strings.Contains(string(raw), `"cost_usd": 0.0015`) {
		t.Fatalf("transcript lacks the token/cost JSON it reconciles against: %q", string(raw))
	}
	footer := fmt.Sprintf("duration_ms=%d", atts[0].DurationMs)
	if !strings.Contains(string(raw), footer) {
		t.Fatalf("transcript footer %q missing duration %s", raw, footer)
	}
	// Audit log verifies.
	if err := auditVerify(mgr); err != nil {
		t.Fatalf("audit: %v", err)
	}
}

// TestDecomposeOrFail is probe 1: a goal with no decomposable tasks fails
// closed with zero dispatches.
func TestDecomposeOrFail(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module x\n\ngo 1.25.0\n"})
	g, err := mgr.AddGoal(&Spec{
		Title: "make it better", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: nil, // no tasks: must decompose or fail closed
	})
	if err != nil {
		t.Fatal(err)
	}
	// The decompose step uses the script adapter with no ScriptCmd, which
	// fails: the goal must block with zero dispatches.
	runIdle(t, mgr)
	goal, _ := mgr.Store.GetGoal(g.ID)
	if goal.Status != state.GoalBlocked {
		t.Fatalf("goal status %q, want blocked", goal.Status)
	}
	tasks, _ := mgr.Store.TasksForGoal(g.ID)
	if len(tasks) != 0 {
		t.Fatalf("expected zero tasks, got %d", len(tasks))
	}
}

// TestWorktreeEscape is probe 3: a worker writing outside its worktree is
// detected and the task escalates; the main checkout change is never
// attributed to the task.
func TestWorktreeEscape(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	escape := fmt.Sprintf(`echo "pwned" >> %s/ESCAPE.txt
python3 - <<'EOF'
p = "calc.go"
s = open(p).read().replace("return a - b", "return a + b")
open(p, "w").write(s)
EOF`, repo)
	g, err := mgr.AddGoal(&Spec{
		Title: "fix Add", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: []TaskSpec{{Title: "fix Add", Acceptance: "Add returns a+b", VerifyCmd: "go test ./...", ScriptCmd: escape, MaxAttempts: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runIdle(t, mgr)
	tasks, _ := mgr.Store.TasksForGoal(g.ID)
	if len(tasks) != 1 || tasks[0].Status != state.TaskEscalated {
		t.Fatalf("task status %v, want escalated", tasks)
	}
	goal, _ := mgr.Store.GetGoal(g.ID)
	if goal.Status != state.GoalBlocked {
		t.Fatalf("goal status %q, want blocked", goal.Status)
	}
	if _, err := os.Stat(filepath.Join(repo, "ESCAPE.txt")); err != nil {
		t.Fatal("escape file should exist (the write happened) — the point is detection, not prevention")
	}
}

// TestVerifierIsKing is probe 4: a worker that claims "done" with failing
// tests has its task failed, not done.
func TestVerifierIsKing(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	liar := `echo "done! all fixed, trust me" && true`
	g, err := mgr.AddGoal(&Spec{
		Title: "fix Add", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: []TaskSpec{{Title: "fix Add", Acceptance: "Add returns a+b", VerifyCmd: "go test ./...", ScriptCmd: liar, MaxAttempts: 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runIdle(t, mgr)
	tasks, _ := mgr.Store.TasksForGoal(g.ID)
	if len(tasks) != 1 || tasks[0].Status != state.TaskEscalated {
		t.Fatalf("task status %v, want escalated after 2 failed verifies", tasks)
	}
	atts, _ := mgr.Store.AttemptsForTask(tasks[0].ID)
	if len(atts) != 2 {
		t.Fatalf("attempts %d, want 2 (bounded repair)", len(atts))
	}
	receipts, _ := mgr.Store.ReceiptsForTask(tasks[0].ID)
	if len(receipts) != 0 {
		t.Fatalf("a failed task must have no receipt, got %d", len(receipts))
	}
}

// TestBoundedRepair is probe 5: a deliberately unfixable task stops after
// max_attempts and the daemon stays healthy.
func TestBoundedRepair(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	g, err := mgr.AddGoal(&Spec{
		Title: "unfixable", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: []TaskSpec{{Title: "impossible", Acceptance: "cannot be done", VerifyCmd: "go test ./...", ScriptCmd: "exit 1", MaxAttempts: 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runIdle(t, mgr) // must return, not loop forever
	tasks, _ := mgr.Store.TasksForGoal(g.ID)
	if tasks[0].Status != state.TaskEscalated {
		t.Fatalf("task status %q, want escalated", tasks[0].Status)
	}
}

// TestSecretRedaction is probe 10: a canary secret in the worker's
// environment never appears anywhere under the state dir (transcripts,
// receipts, audit log, AND the SQLite DB), and a spec that pastes a
// secret in is rejected at intake with an error telling the operator
// to use env vars instead.
func TestSecretRedaction(t *testing.T) {
	t.Setenv("CREWWATCH_CANARY", "CANARY-SECRET-987")
	t.Setenv("TEST_API_KEY", "tok-live-9f8e7d6c5b4a3f2e1d0c")
	// The remaining token shapes reach the worker the same way — via
	// env vars, never pasted into the spec (which AddGoal rejects).
	t.Setenv("BEARER_API_KEY", "BEARER-FAKE-TOKEN-1234567890abcdef")
	t.Setenv("SLACK_API_KEY", "xoxb-123456789012-abcdef")
	t.Setenv("AWS_API_KEY", "AKIAIOSFODNN7EXAMPLE")
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})

	// (a) AddGoal rejects a spec containing a secret, in the title or
	// in a script, with an error pointing at env vars.
	for _, bad := range []*Spec{
		{Title: "fix AKIAIOSFODNN7EXAMPLE", Repo: repo, Adapter: "script", AllowScript: true,
			Tasks: []TaskSpec{{Title: "x", VerifyCmd: "go test ./...", ScriptCmd: "true", MaxAttempts: 1}}},
		{Title: "fix Add", Repo: repo, Adapter: "script", AllowScript: true,
			Tasks: []TaskSpec{{Title: "x", VerifyCmd: "go test ./...", ScriptCmd: `echo AKIAIOSFODNN7EXAMPLE`, MaxAttempts: 1}}},
	} {
		if _, err := mgr.AddGoal(bad); err == nil {
			t.Fatalf("AddGoal accepted a spec containing a secret: %+v", bad)
		} else if !strings.Contains(err.Error(), "environment variables") {
			t.Fatalf("rejection must tell the operator to use env vars, got: %v", err)
		}
	}

	// (b) Secrets that reach the worker via its (allowlisted)
	// environment and are echoed into output must be redacted from
	// everything stored — including the SQLite DB file.
	leaky := `echo "my key is $TEST_API_KEY and $CREWWATCH_CANARY and Bearer $BEARER_API_KEY and $SLACK_API_KEY and $AWS_API_KEY"
python3 - <<'EOF'
p = "calc.go"
s = open(p).read().replace("return a - b", "return a + b")
open(p, "w").write(s)
EOF`
	_, err := mgr.AddGoal(&Spec{
		Title: "fix Add", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: []TaskSpec{{Title: "fix Add", Acceptance: "Add returns a+b", VerifyCmd: "go test ./...", ScriptCmd: leaky, MaxAttempts: 3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runIdle(t, mgr)
	// Grep the WHOLE state dir, including the SQLite DB file, for
	// every secret value the worker could have leaked. The exact-value
	// checks run on every file, binary included. The heuristic
	// ContainsSecret check runs only on text files: raw SQLite bytes
	// can carve out an exactly-40-char base64 window from a title
	// adjacent to a path ("fix Add" + "/tmp/.../001"), which is a
	// path fragment, not a secret — see TestRedactNewTokenShapes.
	// (ContainsSecret is only ever applied to text in production:
	// specs, transcripts, receipts, audit log.)
	secrets := []string{
		"CANARY-SECRET-987", "tok-live-9f8e7d6c5b4a3f2e1d0c",
		"BEARER-FAKE-TOKEN-1234567890abcdef", "xoxb-123456789012-abcdef",
		"AKIAIOSFODNN7EXAMPLE",
	}
	_ = filepath.Walk(mgr.Home, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, s := range secrets {
			if strings.Contains(string(raw), s) {
				t.Errorf("secret %q leaked into %s", s, path)
			}
		}
		if strings.HasSuffix(path, ".db") || strings.HasSuffix(path, ".db-wal") || strings.HasSuffix(path, ".db-shm") {
			return nil
		}
		if redact.ContainsSecret(string(raw)) {
			t.Errorf("secret pattern in %s", path)
		}
		return nil
	})
}

// TestConcurrentGoals is probe 11: two goals in flight do not interleave
// state or share a worktree.
func TestConcurrentGoals(t *testing.T) {
	mgr := newTestManager(t)
	fix := `python3 - <<'EOF'
p = "calc.go"
s = open(p).read().replace("return a - b", "return a + b")
open(p, "w").write(s)
EOF`
	repo1 := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	repo2 := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	var ids []string
	for _, repo := range []string{repo1, repo2} {
		g, err := mgr.AddGoal(&Spec{
			Title: "fix Add", Repo: repo, Adapter: "script", AllowScript: true,
			Tasks: []TaskSpec{{Title: "fix Add", Acceptance: "Add returns a+b", VerifyCmd: "go test ./...", ScriptCmd: fix, MaxAttempts: 3}},
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, g.ID)
	}
	runIdle(t, mgr)
	worktrees := map[string]bool{}
	for _, id := range ids {
		goal, _ := mgr.Store.GetGoal(id)
		if goal.Status != state.GoalDone {
			t.Fatalf("goal %s status %q, want done", id, goal.Status)
		}
		tasks, _ := mgr.Store.TasksForGoal(id)
		if worktrees[tasks[0].Worktree] {
			t.Fatalf("worktree %s shared between goals", tasks[0].Worktree)
		}
		worktrees[tasks[0].Worktree] = true
	}
}

// TestDeterministicReplay is probe 17: the same goal spec produces the
// same task DAG on re-run.
func TestDeterministicReplay(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	spec := &Spec{
		Title: "fix things", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: []TaskSpec{
			{Title: "first", Acceptance: "a", VerifyCmd: "go test ./...", ScriptCmd: "true", MaxAttempts: 1},
			{Title: "second", Acceptance: "b", VerifyCmd: "go test ./...", ScriptCmd: "true", MaxAttempts: 1},
		},
	}
	g1, err := mgr.AddGoal(spec)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := mgr.AddGoal(spec)
	if err != nil {
		t.Fatal(err)
	}
	t1, _ := mgr.Store.TasksForGoal(g1.ID)
	t2, _ := mgr.Store.TasksForGoal(g2.ID)
	if len(t1) != len(t2) {
		t.Fatalf("DAG sizes differ: %d vs %d", len(t1), len(t2))
	}
	for i := range t1 {
		if t1[i].Title != t2[i].Title || t1[i].VerifyCmd != t2[i].VerifyCmd {
			t.Fatalf("DAG differs at %d: %+v vs %+v", i, t1[i], t2[i])
		}
	}
}

// TestNoAutoMerge is probe 14: grep proves there is no code path from a
// verified task to a merge.
func TestNoAutoMerge(t *testing.T) {
	root := filepath.Join("..", "..")
	var bad []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.Contains(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		s := string(raw)
		for _, pat := range []string{"gh pr merge", "pr merge", "git push", "MergePullRequest", ".Merge("} {
			if strings.Contains(s, pat) {
				bad = append(bad, path+": "+pat)
			}
		}
		return nil
	})
	if len(bad) > 0 {
		t.Fatalf("auto-merge paths found: %v", bad)
	}
}

// TestDisclosures is probe 13 (README + help) and probe 18 (network
// posture stated in the README).
func TestDisclosures(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(readme)
	if !strings.Contains(s, "no sandbox in v1") {
		t.Fatal("README must disclose the no-sandbox residual")
	}
	if !strings.Contains(s, "full network access") {
		t.Fatal("README must state the network posture (probe 18)")
	}
	if !strings.Contains(s, "never merges") {
		t.Fatal("README must state the no-auto-merge rule")
	}
	if Disclosure == "" {
		t.Fatal("Disclosure constant must be non-empty (printed to stderr on every dispatch)")
	}
}
