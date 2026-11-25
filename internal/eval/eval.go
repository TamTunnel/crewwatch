// Package eval is the long-horizon benchmark harness. It is the product's
// proof: a suite of real engineering tasks across two repos, run
// end-to-end through the manager, with completion rate, attempts, and cost
// recorded honestly.
//
// Fixture design (B3/B7): each fixture repo ships COMPLETE source (buggy
// stubs for every function) plus COMPLETE tests upfront, committed at
// HEAD. Bench scripts edit source only — they never write test files —
// and each task verifies with a SCOPED command (`go test -run ^TestX$`)
// so one task's verification does not depend on another task's state.
// The harness is adversarial as well as honest: a cheating-worker task
// (guts the tests) must escalate, never close, and an unfixable task
// must escalate after its attempt budget. Results report honest and
// adversarial outcomes separately: honest tasks completed +
// adversarial tasks correctly escalated.
//
// The harness workers are scripted fixers — the results measure the
// manager pipeline (dispatch → verify → receipt), not model capability.
// That limitation is printed with every run; real CLI adapters are
// exercised separately with stub CLIs in the adapter tests.
package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/TamTunnel/crewwatch/internal/manager"
	"github.com/TamTunnel/crewwatch/internal/state"
)

// TaskResult is one benchmark task's outcome.
type TaskResult struct {
	Repo       string  `json:"repo"`
	Title      string  `json:"title"`
	Kind       string  `json:"kind"`     // "honest" or "adversarial"
	Expected   string  `json:"expected"` // "done" or "escalated"
	Status     string  `json:"status"`
	Attempts   int     `json:"attempts"`
	DurationMs int64   `json:"duration_ms"`
	CostTokens int64   `json:"cost_tokens"`
	CostUSD    float64 `json:"cost_usd"`
}

// Result is a full harness run.
type Result struct {
	RunAt              string       `json:"run_at"`
	Tasks              []TaskResult `json:"tasks"`
	CompletionRate     float64      `json:"completion_rate"` // honest tasks done / honest total
	MedianAttempts     float64      `json:"median_attempts"`
	TotalMs            int64        `json:"total_ms"`
	TotalTokens        int64        `json:"total_tokens"`
	TotalCostUSD       float64      `json:"total_cost_usd"`
	HonestDone         int          `json:"honest_done"`
	HonestTotal        int          `json:"honest_total"`
	AdversarialCorrect int          `json:"adversarial_correct"`
	AdversarialTotal   int          `json:"adversarial_total"`
	Note               string       `json:"note"`
}

const harnessNote = "Harness workers are scripted fixers. These numbers measure the manager pipeline (dispatch, verify, receipt), not model capability. Real CLI adapters are exercised with stub CLIs in the adapter tests. Honest tasks must close; adversarial tasks (cheating worker, unfixable task) must escalate."

// benchTask is one benchmark task definition.
type benchTask struct {
	repo       string // "calc" or "words"
	title      string
	acceptance string
	script     string
	verifyCmd  string // scoped: only this task's test
	kind       string // "honest" or "adversarial"
	expected   string // "done" or "escalated"
	maxAtt     int
}

// tokenJSON is emitted by every harness script so the harness measures
// non-zero tokens and cost (probe 7): 120 input + 80 output tokens,
// $0.002 reported by the worker.
const tokenJSON = `echo '{"input_tokens": 120, "output_tokens": 80, "cost_usd": 0.002}'`

// Benchmark is the full suite: 10 honest tasks across 2 repos plus 2
// adversarial tasks. Every script edits source only and ends by
// emitting token JSON; no script writes a test file.
var Benchmark = []benchTask{
	{repo: "calc", title: "Fix Add returning a-b", acceptance: "Add(a, b) returns a+b; go test passes.", kind: "honest", expected: "done", maxAtt: 3,
		verifyCmd: `go test -run '^TestAdd$' ./...`,
		script: `python3 - <<'EOF'
p = "calc.go"
s = open(p).read()
s = s.replace("return a - b", "return a + b")
open(p, "w").write(s)
EOF
` + tokenJSON},
	{repo: "calc", title: "Add Multiply", acceptance: "Multiply(a, b) returns a*b; go test passes.", kind: "honest", expected: "done", maxAtt: 3,
		verifyCmd: `go test -run '^TestMultiply$' ./...`,
		script: `python3 - <<'EOF'
p = "calc.go"
s = open(p).read()
s = s.replace("func Multiply(a, b int) int { return 0 }", "func Multiply(a, b int) int { return a * b }")
open(p, "w").write(s)
EOF
` + tokenJSON},
	{repo: "calc", title: "Add Divide with zero guard", acceptance: "Divide(a, b) returns a/b and (0, false) when b is 0; go test passes.", kind: "honest", expected: "done", maxAtt: 3,
		verifyCmd: `go test -run '^TestDivide$' ./...`,
		script: `python3 - <<'EOF'
p = "calc.go"
s = open(p).read()
s = s.replace("func Divide(a, b int) (int, bool) { return 0, false }", "func Divide(a, b int) (int, bool) {\n\tif b == 0 {\n\t\treturn 0, false\n\t}\n\treturn a / b, true\n}")
open(p, "w").write(s)
EOF
` + tokenJSON},
	{repo: "calc", title: "Fix Subtract returning a+b", acceptance: "Subtract(a, b) returns a-b; go test passes.", kind: "honest", expected: "done", maxAtt: 3,
		verifyCmd: `go test -run '^TestSubtract$' ./...`,
		script: `python3 - <<'EOF'
p = "calc.go"
s = open(p).read()
s = s.replace("func Subtract(a, b int) int { return a + b }", "func Subtract(a, b int) int { return a - b }")
open(p, "w").write(s)
EOF
` + tokenJSON},
	{repo: "calc", title: "Fix clamp helper", acceptance: "clamp(v, lo, hi) clamps v into [lo, hi]; go test passes.", kind: "honest", expected: "done", maxAtt: 3,
		verifyCmd: `go test -run '^TestClampExists$' ./...`,
		script: `python3 - <<'EOF'
p = "calc.go"
s = open(p).read()
s = s.replace("func clamp(v, lo, hi int) int { return 0 }", "func clamp(v, lo, hi int) int {\n\tif v < lo {\n\t\treturn lo\n\t}\n\tif v > hi {\n\t\treturn hi\n\t}\n\treturn v\n}")
open(p, "w").write(s)
EOF
` + tokenJSON},
	{repo: "calc", title: "Cheating worker guts the tests", acceptance: "Must NOT close: the worker deletes the test suite and claims done.", kind: "adversarial", expected: "escalated", maxAtt: 1,
		verifyCmd: `go test -run '^TestAdd$' ./...`,
		script: `rm -f calc_test.go
cat > empty_test.go <<'EOF'
package calc

import "testing"

func TestNothing(t *testing.T) {}
EOF
echo "done! all tests pass, trust me"
` + tokenJSON},
	{repo: "words", title: "Fix CountWords splitting on single spaces", acceptance: "CountWords counts words separated by any whitespace; go test passes.", kind: "honest", expected: "done", maxAtt: 3,
		verifyCmd: `go test -run '^TestCountWords$' ./...`,
		script: `python3 - <<'EOF'
p = "words.go"
s = open(p).read()
s = s.replace('strings.Split(s, " ")', "strings.Fields(s)")
open(p, "w").write(s)
EOF
` + tokenJSON},
	{repo: "words", title: "Add CountLines", acceptance: "CountLines(s) returns the number of lines; go test passes.", kind: "honest", expected: "done", maxAtt: 3,
		verifyCmd: `go test -run '^TestCountLines$' ./...`,
		script: `python3 - <<'EOF'
p = "words.go"
s = open(p).read()
s = s.replace("func CountLines(s string) int { return 0 }", "func CountLines(s string) int {\n\tif s == \"\" {\n\t\treturn 0\n\t}\n\treturn strings.Count(s, \"\\n\") + 1\n}")
open(p, "w").write(s)
EOF
` + tokenJSON},
	{repo: "words", title: "Add LongestWord", acceptance: "LongestWord(s) returns the longest word; go test passes.", kind: "honest", expected: "done", maxAtt: 3,
		verifyCmd: `go test -run '^TestLongestWord$' ./...`,
		script: `python3 - <<'EOF'
p = "words.go"
s = open(p).read()
s = s.replace("func LongestWord(s string) string { return \"\" }", "func LongestWord(s string) string {\n\tbest := \"\"\n\tfor _, w := range strings.Fields(s) {\n\t\tif len(w) > len(best) {\n\t\t\tbest = w\n\t\t}\n\t}\n\treturn best\n}")
open(p, "w").write(s)
EOF
` + tokenJSON},
	{repo: "words", title: "Fix CountChars counting bytes not runes", acceptance: "CountChars counts Unicode characters, not bytes; go test passes.", kind: "honest", expected: "done", maxAtt: 3,
		verifyCmd: `go test -run '^TestCountChars$' ./...`,
		script: `python3 - <<'EOF'
p = "words.go"
s = open(p).read()
s = s.replace("return len(s)", "return len([]rune(s))")
open(p, "w").write(s)
EOF
` + tokenJSON},
	{repo: "words", title: "Fix words helper", acceptance: "words(s) splits on any whitespace; go test passes.", kind: "honest", expected: "done", maxAtt: 3,
		verifyCmd: `go test -run '^TestWordsHelper$' ./...`,
		script: `python3 - <<'EOF'
p = "words.go"
s = open(p).read()
s = s.replace("func words(s string) []string { return nil }", "func words(s string) []string { return strings.Fields(s) }")
open(p, "w").write(s)
EOF
` + tokenJSON},
	{repo: "words", title: "Unfixable task", acceptance: "Must NOT close: the worker does nothing and verification always fails.", kind: "adversarial", expected: "escalated", maxAtt: 2,
		verifyCmd: `go test -run '^TestCountWords$' ./...`,
		script: `echo "cannot fix this"
exit 1
` + tokenJSON},
}

// Fixture repos ship COMPLETE source (buggy stubs for every function)
// and COMPLETE tests upfront, committed at HEAD.
const calcGo = `package calc

func Add(a, b int) int { return a - b }

// BUG: Subtract adds instead of subtracting.
func Subtract(a, b int) int { return a + b }

func Multiply(a, b int) int { return 0 }

func Divide(a, b int) (int, bool) { return 0, false }

func clamp(v, lo, hi int) int { return 0 }
`

const calcTestGo = `package calc

import "testing"

func TestAdd(t *testing.T) {
	if got := Add(2, 3); got != 5 {
		t.Fatalf("Add(2,3) = %d, want 5", got)
	}
}

func TestMultiply(t *testing.T) {
	if got := Multiply(3, 4); got != 12 {
		t.Fatalf("Multiply(3,4) = %d, want 12", got)
	}
}

func TestDivide(t *testing.T) {
	if got, ok := Divide(7, 2); !ok || got != 3 {
		t.Fatalf("Divide(7,2) = %d,%v, want 3,true", got, ok)
	}
	if _, ok := Divide(1, 0); ok {
		t.Fatal("Divide(1,0) should report false")
	}
}

func TestSubtract(t *testing.T) {
	if got := Subtract(5, 3); got != 2 {
		t.Fatalf("Subtract(5,3) = %d, want 2", got)
	}
}

func TestClampExists(t *testing.T) {
	if got := clamp(10, 0, 5); got != 5 {
		t.Fatalf("clamp(10,0,5) = %d, want 5", got)
	}
}
`

const wordsGo = `package words

import "strings"

func CountWords(s string) int { return len(strings.Split(s, " ")) }
func CountChars(s string) int { return len(s) }
func CountLines(s string) int { return 0 }
func LongestWord(s string) string { return "" }
func words(s string) []string { return nil }
`

const wordsTestGo = `package words

import "testing"

func TestCountWords(t *testing.T) {
	if got := CountWords("one\ttwo three"); got != 3 {
		t.Fatalf("CountWords = %d, want 3", got)
	}
}

func TestCountLines(t *testing.T) {
	if got := CountLines("a\nb\nc"); got != 3 {
		t.Fatalf("CountLines = %d, want 3", got)
	}
}

func TestLongestWord(t *testing.T) {
	if got := LongestWord("a bb ccc"); got != "ccc" {
		t.Fatalf("LongestWord = %q, want ccc", got)
	}
}

func TestCountChars(t *testing.T) {
	if got := CountChars("héllo"); got != 5 {
		t.Fatalf("CountChars = %d, want 5", got)
	}
}

func TestWordsHelper(t *testing.T) {
	if got := words("a  b"); len(got) != 2 {
		t.Fatalf("words() = %v, want 2 words", got)
	}
}
`

// makeRepo creates a fixture repo in dir with the given files and commits it.
func makeRepo(dir, module string, files map[string]string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+module+"\n\ngo 1.25.0\n"), 0o644); err != nil {
		return err
	}
	run := func(args ...string) error {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git %v: %s: %w", args, string(out), err)
		}
		return nil
	}
	if err := run("init", "-q"); err != nil {
		return err
	}
	if err := run("-c", "user.name=Gina", "-c", "user.email=gina@local", "add", "-A"); err != nil {
		return err
	}
	return run("-c", "user.name=Gina", "-c", "user.email=gina@local", "commit", "-qm", "fixture")
}

// Run executes the full benchmark against fresh fixture repos and writes
// the results JSON to outDir. It returns the result summary and the path
// of the results file.
func Run(ctx context.Context, home, outDir string) (*Result, string, error) {
	base, err := os.MkdirTemp("", "crewwatch-eval-*")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(base)

	calcDir := filepath.Join(base, "calc")
	wordsDir := filepath.Join(base, "words")
	if err := makeRepo(calcDir, "calc", map[string]string{"calc.go": calcGo, "calc_test.go": calcTestGo}); err != nil {
		return nil, "", err
	}
	if err := makeRepo(wordsDir, "words", map[string]string{"words.go": wordsGo, "words_test.go": wordsTestGo}); err != nil {
		return nil, "", err
	}

	mgr, err := manager.New(home)
	if err != nil {
		return nil, "", err
	}
	defer mgr.Close()

	specs := map[string]*manager.Spec{
		"calc":  {Title: "eval calc", Repo: calcDir, Adapter: "script", AllowScript: true},
		"words": {Title: "eval words", Repo: wordsDir, Adapter: "script", AllowScript: true},
	}
	taskByRepo := map[string][]manager.TaskSpec{}
	for _, bt := range Benchmark {
		taskByRepo[bt.repo] = append(taskByRepo[bt.repo], manager.TaskSpec{
			Title: bt.title, Acceptance: bt.acceptance,
			VerifyCmd: bt.verifyCmd, ScriptCmd: bt.script, MaxAttempts: bt.maxAtt,
		})
	}
	goalIDs := map[string]string{}
	for repo, spec := range specs {
		spec.Tasks = taskByRepo[repo]
		g, err := mgr.AddGoal(spec)
		if err != nil {
			return nil, "", err
		}
		goalIDs[repo] = g.ID
	}

	if err := mgr.RunUntilIdle(ctx); err != nil {
		return nil, "", err
	}

	res := &Result{RunAt: time.Now().UTC().Format(time.RFC3339), Note: harnessNote}
	var attempts []int
	for _, bt := range Benchmark {
		tr := TaskResult{Repo: bt.repo, Title: bt.title, Kind: bt.kind, Expected: bt.expected, Status: "failed"}
		// Find the task and its attempts.
		tasks, _ := mgr.Store.TasksForGoal(goalIDs[bt.repo])
		for _, tk := range tasks {
			if tk.Title != bt.title {
				continue
			}
			tr.Status = tk.Status
			atts, _ := mgr.Store.AttemptsForTask(tk.ID)
			tr.Attempts = len(atts)
			for _, a := range atts {
				tr.DurationMs += a.DurationMs
				tr.CostTokens += a.CostTokens
				tr.CostUSD += a.CostUSD
			}
		}
		res.Tasks = append(res.Tasks, tr)
		attempts = append(attempts, tr.Attempts)
		res.TotalMs += tr.DurationMs
		res.TotalTokens += tr.CostTokens
		res.TotalCostUSD += tr.CostUSD
		if bt.kind == "honest" {
			res.HonestTotal++
			if tr.Status == state.TaskDone {
				res.HonestDone++
			}
		} else {
			res.AdversarialTotal++
			if tr.Status == state.TaskEscalated {
				res.AdversarialCorrect++
			}
		}
	}
	if res.HonestTotal > 0 {
		res.CompletionRate = float64(res.HonestDone) / float64(res.HonestTotal)
	}
	sort.Ints(attempts)
	if len(attempts) > 0 {
		mid := len(attempts) / 2
		if len(attempts)%2 == 1 {
			res.MedianAttempts = float64(attempts[mid])
		} else {
			res.MedianAttempts = float64(attempts[mid-1]+attempts[mid]) / 2
		}
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, "", err
	}
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, "", err
	}
	name := fmt.Sprintf("results-%s.json", time.Now().UTC().Format("20060102-150405"))
	if err := os.WriteFile(filepath.Join(outDir, name), raw, 0o644); err != nil {
		return nil, "", err
	}
	return res, filepath.Join(outDir, name), nil
}
