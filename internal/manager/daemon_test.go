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
)

// buildBinary compiles the crewwatch binary into dir and returns its path.
func buildBinary(t *testing.T, dir string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "crewwatch")
	cmd := exec.Command("~/go/bin/go", "build", "-o", bin, "./cmd/crewwatch")
	// Resolve the go binary path (tilde is not expanded by exec).
	goBin := os.Getenv("HOME") + "/go/bin/go"
	cmd = exec.Command(goBin, "build", "-o", bin, "./cmd/crewwatch")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %s: %v", out, err)
	}
	return bin
}

func runBin(t *testing.T, home, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "CREWWATCH_HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("crewwatch %v: %s: %v", args, out, err)
	}
	return string(out)
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestCrashRecovery is probe 6: kill -9 the daemon mid-goal; on restart it
// resumes with no lost tasks and no duplicated dispatches.
func TestCrashRecovery(t *testing.T) {
	tmp := t.TempDir()
	bin := buildBinary(t, tmp)
	home := filepath.Join(tmp, "home")
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	slowFix := `sleep 15
python3 - <<'EOF'
p = "calc.go"
s = open(p).read().replace("return a - b", "return a + b")
open(p, "w").write(s)
EOF`
	spec := Spec{
		Title: "fix Add", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: []TaskSpec{{Title: "fix Add", Acceptance: "Add returns a+b", VerifyCmd: "go test ./...", ScriptCmd: slowFix, MaxAttempts: 3}},
	}
	raw, _ := json.Marshal(spec)
	specFile := filepath.Join(tmp, "spec.json")
	if err := os.WriteFile(specFile, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	out := runBin(t, home, bin, "goal", "add", "--spec", specFile, "--allow-script")
	goalID := strings.Fields(out)[1]

	// Start the daemon, wait until the worker is dispatched, then kill -9.
	daemon := exec.Command(bin, "daemon")
	daemon.Env = append(os.Environ(), "CREWWATCH_HOME="+home)
	daemon.Stdout = os.Stderr
	daemon.Stderr = os.Stderr
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 30*time.Second, "dispatch", func() bool {
		entries, _ := os.ReadDir(filepath.Join(home, "running"))
		return len(entries) > 0
	})
	if err := daemon.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = daemon.Process.Wait()

	// Restart: a single --once run must recover and finish the goal.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_ = ctx
	done := make(chan string, 1)
	go func() {
		done <- runBin(t, home, bin, "daemon", "--once")
	}()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatal("daemon --once did not finish after recovery")
	}

	status := runBin(t, home, bin, "status", goalID)
	if !strings.Contains(status, "[done]") {
		t.Fatalf("goal not done after recovery:\n%s", status)
	}
	// Attempt accounting: exactly one interrupted + one completed, one receipt.
	mgr, err := New(home)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	tasks, _ := mgr.Store.TasksForGoal(goalID)
	if len(tasks) != 1 {
		t.Fatalf("tasks %d", len(tasks))
	}
	atts, _ := mgr.Store.AttemptsForTask(tasks[0].ID)
	var interrupted, completed int
	for _, a := range atts {
		switch a.Status {
		case "interrupted":
			interrupted++
		case "completed":
			completed++
		}
	}
	if interrupted != 1 || completed != 1 {
		t.Fatalf("attempts: %d interrupted, %d completed (want 1 and 1)", interrupted, completed)
	}
	receipts, _ := mgr.Store.ReceiptsForTask(tasks[0].ID)
	if len(receipts) != 1 {
		t.Fatalf("receipts %d, want exactly 1 (no duplicate dispatch)", len(receipts))
	}
}

// TestCancellationIsClean is probe 16: cancelling a running goal stops
// all workers and leaves no orphaned worktrees or processes.
func TestCancellationIsClean(t *testing.T) {
	tmp := t.TempDir()
	bin := buildBinary(t, tmp)
	home := filepath.Join(tmp, "home")
	repo := makeRepo(t, map[string]string{"go.mod": "module calc\n\ngo 1.25.0\n", "calc.go": calcGo, "calc_test.go": calcTest})
	slow := `sleep 60
python3 - <<'EOF'
p = "calc.go"
s = open(p).read().replace("return a - b", "return a + b")
open(p, "w").write(s)
EOF`
	spec := Spec{
		Title: "slow goal", Repo: repo, Adapter: "script", AllowScript: true,
		Tasks: []TaskSpec{{Title: "slow task", Acceptance: "fix", VerifyCmd: "go test ./...", ScriptCmd: slow, MaxAttempts: 3}},
	}
	raw, _ := json.Marshal(spec)
	specFile := filepath.Join(tmp, "spec.json")
	if err := os.WriteFile(specFile, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	out := runBin(t, home, bin, "goal", "add", "--spec", specFile, "--allow-script")
	goalID := strings.Fields(out)[1]

	daemon := exec.Command(bin, "daemon")
	daemon.Env = append(os.Environ(), "CREWWATCH_HOME="+home)
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = daemon.Process.Kill()
		_, _ = daemon.Process.Wait()
	}()
	var workerPID string
	waitFor(t, 30*time.Second, "dispatch", func() bool {
		entries, _ := os.ReadDir(filepath.Join(home, "running"))
		if len(entries) == 0 {
			return false
		}
		raw, err := os.ReadFile(filepath.Join(home, "running", entries[0].Name()))
		if err != nil {
			return false
		}
		workerPID = strings.TrimSpace(string(raw))
		return workerPID != ""
	})

	runBin(t, home, bin, "goal", "cancel", goalID)
	time.Sleep(3 * time.Second) // settle

	status := runBin(t, home, bin, "status", goalID)
	if !strings.Contains(status, "[cancelled]") {
		t.Fatalf("goal not cancelled:\n%s", status)
	}
	// No orphaned worker process.
	if _, err := os.Stat("/proc/" + workerPID); err == nil {
		t.Fatalf("worker process %s still alive after cancel", workerPID)
	}
	// No orphaned worktrees.
	out2, err := exec.Command("git", "-C", repo, "worktree", "list", "--porcelain").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out2), "cw-") {
		t.Fatalf("orphaned worktree remains:\n%s", out2)
	}
	if entries, _ := os.ReadDir(filepath.Join(home, "worktrees")); len(entries) != 0 {
		t.Fatalf("worktree dirs remain: %v", entries)
	}
}

var _ = fmt.Sprintf
