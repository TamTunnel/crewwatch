package adapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubCLI writes a fake worker CLI into dir: a shell script that applies a
// canned edit (appends a line to target.txt) and prints a transcript.
func stubCLI(t *testing.T, dir, name string) {
	t.Helper()
	script := `#!/bin/sh
echo "worker ` + name + ` starting"
echo "prompt received: $*"
echo "fixed the thing" >> target.txt
echo '{"input_tokens": 100, "output_tokens": 50}'
echo "done"
`
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestTwoAdapterDispatch(t *testing.T) {
	// Probe 2: the same goal runs via OpenCode and via Qwen Code through
	// the adapter interface, with no manager changes between runs.
	binDir := t.TempDir()
	stubCLI(t, binDir, "opencode")
	stubCLI(t, binDir, "qwen")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	for _, name := range []string{"opencode", "qwen"} {
		work := t.TempDir()
		if err := os.WriteFile(filepath.Join(work, "target.txt"), []byte("start\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		ad, err := Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		res, err := ad.Dispatch(context.Background(), Request{
			TaskID: "t1", Title: "fix thing", WorkDir: work,
			Prompt: "fix the thing", Timeout: 30 * time.Second,
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("%s: exit %d, transcript %q", name, res.ExitCode, res.Transcript)
		}
		if res.Tokens != 150 {
			t.Fatalf("%s: tokens %d, want 150", name, res.Tokens)
		}
		raw, err := os.ReadFile(filepath.Join(work, "target.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "fixed the thing") {
			t.Fatalf("%s: edit not applied: %q", name, raw)
		}
	}
}

func TestUnknownAdapter(t *testing.T) {
	if _, err := Lookup("nosuch"); err == nil {
		t.Fatal("expected error for unknown adapter")
	}
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	// Probe 9: a hanging worker is killed with its whole process group —
	// no orphaned grandchildren.
	work := t.TempDir()
	grandchildPID := filepath.Join(work, "grandchild.pid")
	script := `#!/bin/sh
sleep 300 &
echo $! > ` + grandchildPID + `
sleep 300
`
	stub := filepath.Join(work, "hang.sh")
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ad := NewScriptAdapter(stub)
	res, err := ad.Dispatch(context.Background(), Request{
		TaskID: "t1", Title: "hang", WorkDir: work, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut {
		t.Fatal("expected timeout")
	}
	raw, err := os.ReadFile(grandchildPID)
	if err != nil {
		t.Fatal(err)
	}
	pid := strings.TrimSpace(string(raw))
	// The grandchild must be gone: its /proc entry must disappear.
	// The group kill is delivered synchronously but reaping by init is
	// async, so poll briefly rather than checking once.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat("/proc/" + pid); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild pid %s still alive after group kill", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestScriptAdapterFailure(t *testing.T) {
	ad := NewScriptAdapter("exit 3")
	res, err := ad.Dispatch(context.Background(), Request{
		TaskID: "t1", Title: "fail", WorkDir: t.TempDir(), Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit %d, want 3", res.ExitCode)
	}
}
