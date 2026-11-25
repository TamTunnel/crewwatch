package manager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TamTunnel/crewwatch/internal/receipt"
	"github.com/TamTunnel/crewwatch/internal/state"
)

const fixAddScript = "python3 - <<'PYEOF'\np = \"calc.go\"\ns = open(p).read().replace(\"return a - b\", \"return a + b\")\nopen(p, \"w\").write(s)\nPYEOF\n"

// TestTestFileGuttingEscalates is B3: a worker that deletes the test
// file and writes an empty test gets a signed receipt for nothing —
// unless the manager escalates. Verification would pass (no failing
// tests left), so the test-file check is what blocks it.
func TestTestFileGuttingEscalates(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	gut := "rm calc_test.go\n" +
		"cat > empty_test.go <<'PYEOF'\npackage calc\n\nimport \"testing\"\n\nfunc TestNothing(t *testing.T) {}\nPYEOF\n" +
		fixAddScript
	g, err := mgr.AddGoal(&Spec{
		Title: "fix Add", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: []TaskSpec{{Title: "fix Add", Acceptance: "Add returns a+b", VerifyCmd: "go test ./...", ScriptCmd: gut, MaxAttempts: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runIdle(t, mgr)
	tasks, _ := mgr.Store.TasksForGoal(g.ID)
	if len(tasks) != 1 || tasks[0].Status != state.TaskEscalated {
		t.Fatalf("task status %v, want escalated (test files were gutted)", tasks)
	}
	receipts, _ := mgr.Store.ReceiptsForTask(tasks[0].ID)
	if len(receipts) != 0 {
		t.Fatalf("a test-gutting worker must get no receipt, got %d", len(receipts))
	}
}

// TestDecomposeIgnoresWorkerVerifyCmd is B4: a worker that proposes
// verify_cmd "echo verified" must not get it — decomposed tasks get
// the repo-detected default, and a task with no detectable verify_cmd
// is dropped with an audit event.
func TestDecomposeIgnoresWorkerVerifyCmd(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	stubDir := t.TempDir()
	stub := filepath.Join(stubDir, "opencode")
	script := "#!/bin/sh\n" +
		"echo '[{\"title\":\"fix Add\",\"acceptance\":\"Add returns a+b\",\"verify_cmd\":\"echo verified\"}]'\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREWWATCH_ADAPTER_OPENCODE_CMD", stub)
	g, err := mgr.AddGoal(&Spec{Title: "fix calc", Repo: repo, Adapter: "opencode"})
	if err != nil {
		t.Fatal(err)
	}
	runIdle(t, mgr)
	tasks, _ := mgr.Store.TasksForGoal(g.ID)
	if len(tasks) != 1 {
		t.Fatalf("tasks %d, want 1", len(tasks))
	}
	if tasks[0].VerifyCmd != "go test ./..." {
		t.Fatalf("decomposed verify_cmd %q, want repo default %q (never the worker's)", tasks[0].VerifyCmd, "go test ./...")
	}
	// The raw decomposition must be in the audit log.
	raw, _ := os.ReadFile(filepath.Join(mgr.Home, "audit.jsonl"))
	if !strings.Contains(string(raw), "decomposition_raw") {
		t.Fatal("raw decomposition JSON not logged to the audit trail")
	}
}

// TestDecomposeDropsUndetectableTasks is B4: decomposed tasks with no
// detectable verify_cmd are dropped with an audit event, never silently,
// and a goal whose decomposition is entirely dropped fails closed.
func TestDecomposeDropsUndetectableTasks(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"README.md": "not a code repo\n"})
	stubDir := t.TempDir()
	stub := filepath.Join(stubDir, "opencode")
	script := "#!/bin/sh\n" +
		"echo '[{\"title\":\"do thing\",\"acceptance\":\"do it\"}]'\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREWWATCH_ADAPTER_OPENCODE_CMD", stub)
	g, err := mgr.AddGoal(&Spec{Title: "do thing", Repo: repo, Adapter: "opencode"})
	if err != nil {
		t.Fatal(err)
	}
	runIdle(t, mgr)
	goal, _ := mgr.Store.GetGoal(g.ID)
	if goal.Status != state.GoalBlocked {
		t.Fatalf("goal status %q, want blocked (all tasks dropped)", goal.Status)
	}
	tasks, _ := mgr.Store.TasksForGoal(g.ID)
	if len(tasks) != 0 {
		t.Fatalf("tasks %d, want 0 (dropped, not created)", len(tasks))
	}
	raw, _ := os.ReadFile(filepath.Join(mgr.Home, "audit.jsonl"))
	if !strings.Contains(string(raw), "task_dropped") {
		t.Fatal("dropped task not logged to the audit trail")
	}
}

// TestCrossWorktreeEscape extends TestWorktreeEscape (probe 3): a
// worker writing into ANOTHER task's worktree is detected and escalated.
func TestCrossWorktreeEscape(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	// A sibling worktree dir, live before dispatch.
	sibling := filepath.Join(mgr.Home, "worktrees", "sibling-task")
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "marker.txt"), []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	escape := fmt.Sprintf("echo \"pwned\" >> %s/marker.txt\n", sibling) + fixAddScript
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
		t.Fatalf("task status %v, want escalated (cross-worktree write)", tasks)
	}
}

// TestWorktreeEscapeStealth re-probes the judge's stealth variants
// (probe 3): gitignored write, write-then-restore, .git/hooks plant,
// and a write outside the repo into the state home. Every variant
// must be detected and escalated (detection, not prevention).
func TestWorktreeEscapeStealth(t *testing.T) {
	variants := []struct {
		name   string
		script func(repo, home string) string
	}{
		{"gitignored write in main checkout", func(repo, home string) string {
			return fmt.Sprintf("echo pwned > %s/ignored.txt\n", repo) + fixAddScript
		}},
		{"write-then-restore a tracked file", func(repo, home string) string {
			return fmt.Sprintf("echo hacked >> %s/calc.go\ngit -C %s checkout -- calc.go\n", repo, repo) + fixAddScript
		}},
		{".git/hooks plant", func(repo, home string) string {
			return fmt.Sprintf("echo evil > %s/.git/hooks/pre-commit\n", repo) + fixAddScript
		}},
		{"write outside the repo into the state home", func(repo, home string) string {
			return fmt.Sprintf("echo pwned > %s/ESCAPE.txt\n", home) + fixAddScript
		}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			mgr := newTestManager(t)
			repo := makeRepo(t, map[string]string{
				"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest,
				".gitignore": "ignored.txt\n",
			})
			g, err := mgr.AddGoal(&Spec{
				Title: "fix Add", Repo: repo, Adapter: "script", AllowScript: true,
				Tasks: []TaskSpec{{Title: "fix Add", Acceptance: "Add returns a+b", VerifyCmd: "go test ./...", ScriptCmd: v.script(repo, mgr.Home), MaxAttempts: 1}},
			})
			if err != nil {
				t.Fatal(err)
			}
			runIdle(t, mgr)
			tasks, _ := mgr.Store.TasksForGoal(g.ID)
			if len(tasks) != 1 || tasks[0].Status != state.TaskEscalated {
				t.Fatalf("task status %v, want escalated (%s)", tasks, v.name)
			}
			receipts, _ := mgr.Store.ReceiptsForTask(tasks[0].ID)
			if len(receipts) != 0 {
				t.Fatalf("escaping worker must get no receipt, got %d", len(receipts))
			}
		})
	}
}

// TestDiffHashNewFiles is S2: a new-file-only change must not hash as
// the empty sha256.
func TestDiffHashNewFiles(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	wt, _, err := mgr.ensureWorktree(repo, &state.Task{ID: "task-diffhash"})
	if err != nil {
		t.Fatal(err)
	}
	if got := mgr.diffHash(wt); got != emptySHA256() {
		t.Fatalf("clean worktree diff hash %s, want empty sha256 %s", got, emptySHA256())
	}
	if err := os.WriteFile(filepath.Join(wt, "multiply.go"), []byte("package calc\n\nfunc Multiply(a, b int) int { return a * b }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := mgr.diffHash(wt); got == emptySHA256() {
		t.Fatal("new-file-only change hashed as the empty sha256")
	}
}

// TestWorkerExitCodeInReceipt is S3: a worker that fixes the code then
// exits 1 still closes on verification, but the receipt records the
// non-zero exit code.
func TestWorkerExitCodeInReceipt(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	fixThenFail := fixAddScript + "\nexit 1\n"
	g, err := mgr.AddGoal(&Spec{
		Title: "fix Add", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: []TaskSpec{{Title: "fix Add", Acceptance: "Add returns a+b", VerifyCmd: "go test ./...", ScriptCmd: fixThenFail, MaxAttempts: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	runIdle(t, mgr)
	tasks, _ := mgr.Store.TasksForGoal(g.ID)
	if tasks[0].Status != state.TaskDone {
		t.Fatalf("task status %q, want done (verification is king)", tasks[0].Status)
	}
	receipts, _ := mgr.Store.ReceiptsForTask(tasks[0].ID)
	if len(receipts) != 1 {
		t.Fatalf("receipts %d, want 1", len(receipts))
	}
	var r receipt.Receipt
	if err := json.Unmarshal([]byte(receipts[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Payload.WorkerExitCode != 1 {
		t.Fatalf("receipt worker_exit_code %d, want 1", r.Payload.WorkerExitCode)
	}
}

// TestScriptCmdRejected is S4: a spec containing script_cmd is
// rejected unless --allow-script (AddGoal AllowScript) is set.
func TestScriptCmdRejected(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n"})
	_, err := mgr.AddGoal(&Spec{
		Title: "x", Repo: repo, Adapter: "script",
		Tasks: []TaskSpec{{Title: "x", VerifyCmd: "go test ./...", ScriptCmd: "true", MaxAttempts: 1}},
	})
	if err == nil {
		t.Fatal("AddGoal accepted script_cmd without --allow-script")
	}
	if !strings.Contains(err.Error(), "--allow-script") {
		t.Fatalf("rejection must name --allow-script, got: %v", err)
	}
}

// TestAddGoalPreflight is F1: a verify_cmd naming a binary that is not
// on PATH fails fast at intake, instead of burning the attempt budget.
func TestAddGoalPreflight(t *testing.T) {
	mgr := newTestManager(t)
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n"})
	_, err := mgr.AddGoal(&Spec{
		Title: "x", Repo: repo, Adapter: "opencode",
		Tasks: []TaskSpec{{Title: "x", VerifyCmd: "definitely-not-a-real-binary-xyz test", MaxAttempts: 1}},
	})
	if err == nil {
		t.Fatal("AddGoal accepted a verify_cmd whose binary is not on PATH")
	}
	if !strings.Contains(err.Error(), "not found on PATH") {
		t.Fatalf("preflight error must say not found on PATH, got: %v", err)
	}
}
