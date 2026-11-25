// Package eval is the long-horizon benchmark harness. It is the product's
// proof: a suite of real engineering tasks across two repos, run
// end-to-end through the manager, with completion rate, attempts, and cost
// recorded honestly. The harness workers are scripted fixers — the results
// measure the manager pipeline (dispatch → verify → receipt), not model
// capability. That limitation is printed with every run; real CLI adapters
// are exercised separately with stub CLIs in the adapter tests.
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
	Repo       string `json:"repo"`
	Title      string `json:"title"`
	Status     string `json:"status"`
	Attempts   int    `json:"attempts"`
	DurationMs int64  `json:"duration_ms"`
	CostTokens int64  `json:"cost_tokens"`
}

// Result is a full harness run.
type Result struct {
	RunAt          string       `json:"run_at"`
	Tasks          []TaskResult `json:"tasks"`
	CompletionRate float64      `json:"completion_rate"`
	MedianAttempts float64      `json:"median_attempts"`
	TotalMs        int64        `json:"total_ms"`
	TotalTokens    int64        `json:"total_tokens"`
	Note           string       `json:"note"`
}

const harnessNote = "Harness workers are scripted fixers. These numbers measure the manager pipeline (dispatch, verify, receipt), not model capability. Real CLI adapters are exercised with stub CLIs in the adapter tests."

// benchTask is one benchmark task definition.
type benchTask struct {
	repo       string // "calc" or "words"
	title      string
	acceptance string
	script     string
}

// Benchmark is the full suite: 10 tasks across 2 repos. Each task's
// script applies the fix AND writes that task's test file, so every task
// is independently verifiable: the repo compiles and its tests pass
// after each single task.
var Benchmark = []benchTask{
	{repo: "calc", title: "Fix Add returning a-b", acceptance: "Add(a, b) returns a+b; go test ./... passes.", script: `python3 - <<'EOF'
p = "calc.go"
s = open(p).read()
s = s.replace("return a - b", "return a + b")
open(p, "w").write(s)
EOF
cat > add_test.go <<'EOF'
package calc

import "testing"

func TestAdd(t *testing.T) {
	if got := Add(2, 3); got != 5 {
		t.Fatalf("Add(2,3) = %d, want 5", got)
	}
}
EOF`},
	{repo: "calc", title: "Add Multiply", acceptance: "Multiply(a, b) returns a*b; go test ./... passes.", script: `cat >> calc.go <<'EOF'

func Multiply(a, b int) int { return a * b }
EOF
cat > multiply_test.go <<'EOF'
package calc

import "testing"

func TestMultiply(t *testing.T) {
	if got := Multiply(3, 4); got != 12 {
		t.Fatalf("Multiply(3,4) = %d, want 12", got)
	}
}
EOF`},
	{repo: "calc", title: "Add Divide with zero guard", acceptance: "Divide(a, b) returns a/b and (0, false) when b is 0; go test ./... passes.", script: `cat >> calc.go <<'EOF'

func Divide(a, b int) (int, bool) {
	if b == 0 {
		return 0, false
	}
	return a / b, true
}
EOF
cat > divide_test.go <<'EOF'
package calc

import "testing"

func TestDivide(t *testing.T) {
	if got, ok := Divide(7, 2); !ok || got != 3 {
		t.Fatalf("Divide(7,2) = %d,%v, want 3,true", got, ok)
	}
	if _, ok := Divide(1, 0); ok {
		t.Fatal("Divide(1,0) should report false")
	}
}
EOF`},
	{repo: "calc", title: "Fix Subtract returning a+b", acceptance: "Subtract(a, b) returns a-b; go test ./... passes.", script: `python3 - <<'EOF'
p = "calc.go"
s = open(p).read()
s = s.replace("func Subtract(a, b int) int { return a + b }", "func Subtract(a, b int) int { return a - b }")
open(p, "w").write(s)
EOF
cat > subtract_test.go <<'EOF'
package calc

import "testing"

func TestSubtract(t *testing.T) {
	if got := Subtract(5, 3); got != 2 {
		t.Fatalf("Subtract(5,3) = %d, want 2", got)
	}
}
EOF`},
	{repo: "calc", title: "Refactor bounds check into a helper", acceptance: "A clamp helper exists in calc.go; go test ./... passes.", script: `python3 - <<'EOF'
p = "calc.go"
s = open(p).read()
s = s.replace("func Add(a, b int) int {", "func clamp(v, lo, hi int) int {\n\tif v < lo {\n\t\treturn lo\n\t}\n\tif v > hi {\n\t\treturn hi\n\t}\n\treturn v\n}\n\nfunc Add(a, b int) int {")
open(p, "w").write(s)
EOF
cat > clamp_test.go <<'EOF'
package calc

import "testing"

func TestClampExists(t *testing.T) {
	if got := clamp(10, 0, 5); got != 5 {
		t.Fatalf("clamp(10,0,5) = %d, want 5", got)
	}
}
EOF`},
	{repo: "words", title: "Fix CountWords splitting on single spaces", acceptance: "CountWords counts words separated by any whitespace; go test ./... passes.", script: `python3 - <<'EOF'
p = "words.go"
s = open(p).read()
s = s.replace('strings.Split(s, " ")', "strings.Fields(s)")
open(p, "w").write(s)
EOF
cat > countwords_test.go <<'EOF'
package words

import "testing"

func TestCountWords(t *testing.T) {
	if got := CountWords("one  two\tthree"); got != 3 {
		t.Fatalf("CountWords = %d, want 3", got)
	}
}
EOF`},
	{repo: "words", title: "Add CountLines", acceptance: "CountLines(s) returns the number of lines; go test ./... passes.", script: `cat >> words.go <<'EOF'

func CountLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}
EOF
cat > countlines_test.go <<'EOF'
package words

import "testing"

func TestCountLines(t *testing.T) {
	if got := CountLines("a\nb\nc"); got != 3 {
		t.Fatalf("CountLines = %d, want 3", got)
	}
}
EOF`},
	{repo: "words", title: "Add LongestWord", acceptance: "LongestWord(s) returns the longest word; go test ./... passes.", script: `cat >> words.go <<'EOF'

func LongestWord(s string) string {
	best := ""
	for _, w := range strings.Fields(s) {
		if len(w) > len(best) {
			best = w
		}
	}
	return best
}
EOF
cat > longestword_test.go <<'EOF'
package words

import "testing"

func TestLongestWord(t *testing.T) {
	if got := LongestWord("a bb ccc"); got != "ccc" {
		t.Fatalf("LongestWord = %q, want ccc", got)
	}
}
EOF`},
	{repo: "words", title: "Fix CountChars counting bytes not runes", acceptance: "CountChars counts Unicode characters, not bytes; go test ./... passes.", script: `python3 - <<'EOF'
p = "words.go"
s = open(p).read()
s = s.replace("return len(s)", "return len([]rune(s))")
open(p, "w").write(s)
EOF
cat > countchars_test.go <<'EOF'
package words

import "testing"

func TestCountChars(t *testing.T) {
	if got := CountChars("héllo"); got != 5 {
		t.Fatalf("CountChars = %d, want 5", got)
	}
}
EOF`},
	{repo: "words", title: "Refactor shared tokenizer into a helper", acceptance: "A words helper exists in words.go; go test ./... passes.", script: `python3 - <<'EOF'
p = "words.go"
s = open(p).read()
s = s.replace("func CountWords(s string) int {", "func words(s string) []string { return strings.Fields(s) }\n\nfunc CountWords(s string) int {")
open(p, "w").write(s)
EOF
cat > words_test.go <<'EOF'
package words

import "testing"

func TestWordsHelper(t *testing.T) {
	if got := words("a  b"); len(got) != 2 {
		t.Fatalf("words() = %v, want 2 words", got)
	}
}
EOF`},
}

const calcGo = `package calc

func Add(a, b int) int { return a - b }

// BUG: Subtract adds instead of subtracting.
func Subtract(a, b int) int { return a + b }
`

const wordsGo = `package words

import "strings"

func CountWords(s string) int { return len(strings.Split(s, " ")) }
func CountChars(s string) int { return len(s) }
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
	if err := makeRepo(calcDir, "calc", map[string]string{"calc.go": calcGo}); err != nil {
		return nil, "", err
	}
	if err := makeRepo(wordsDir, "words", map[string]string{"words.go": wordsGo}); err != nil {
		return nil, "", err
	}

	mgr, err := manager.New(home)
	if err != nil {
		return nil, "", err
	}
	defer mgr.Close()

	specs := map[string]*manager.Spec{
		"calc":  {Title: "eval calc", Repo: calcDir, Adapter: "script"},
		"words": {Title: "eval words", Repo: wordsDir, Adapter: "script"},
	}
	taskByRepo := map[string][]manager.TaskSpec{}
	for _, bt := range Benchmark {
		taskByRepo[bt.repo] = append(taskByRepo[bt.repo], manager.TaskSpec{
			Title: bt.title, Acceptance: bt.acceptance,
			VerifyCmd: "go test ./...", ScriptCmd: bt.script, MaxAttempts: 3,
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
		tr := TaskResult{Repo: bt.repo, Title: bt.title, Status: "failed"}
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
			}
		}
		res.Tasks = append(res.Tasks, tr)
		attempts = append(attempts, tr.Attempts)
		res.TotalMs += tr.DurationMs
		res.TotalTokens += tr.CostTokens
	}
	done := 0
	for _, tr := range res.Tasks {
		if tr.Status == state.TaskDone {
			done++
		}
	}
	res.CompletionRate = float64(done) / float64(len(res.Tasks))
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
