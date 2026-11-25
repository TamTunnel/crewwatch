// Command crewwatch is the Crewwatch manager agent: a persistent manager
// that owns an engineering goal end-to-end on local coding agents,
// verifies every result with the repo's own checks, and issues signed
// receipts. It never merges and never pushes — a verified task waits in
// its worktree for a human.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TamTunnel/crewwatch/internal/audit"
	"github.com/TamTunnel/crewwatch/internal/eval"
	"github.com/TamTunnel/crewwatch/internal/manager"
	"github.com/TamTunnel/crewwatch/internal/receipt"
	"github.com/TamTunnel/crewwatch/internal/state"
)

const version = "0.1.0"

const helpText = `crewwatch — persistent manager agent for engineering goals.

Usage:
  crewwatch daemon [--home DIR] [--once]   run the manager daemon
  crewwatch goal add --spec FILE           add a goal from a JSON spec
  crewwatch goal list                      list goals
  crewwatch goal cancel <goal-id>          stop a goal, kill its workers
  crewwatch status [goal-id]               show goals, tasks, attempts
  crewwatch verify <receipt.json>          verify one receipt offline
  crewwatch verify --all                   verify every stored receipt
  crewwatch audit verify                   verify the hash-chained audit log
  crewwatch eval [--out DIR]               run the benchmark harness
  crewwatch version
  crewwatch help

Workers run with your credentials and filesystem access (no sandbox in v1).
Crewwatch never merges and never pushes: verified tasks wait in their
worktree for a human to review. A task closes only when the repo's own
verification passes — a worker's claim of "done" is never sufficient.

State lives in ~/.crewwatch (override with --home or CREWWATCH_HOME).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(helpText)
		os.Exit(0)
	}
	home := resolveHome()
	args := os.Args[1:]
	// --home may appear anywhere; strip it out.
	rest := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--home" && i+1 < len(args) {
			home = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(args[i], "--home=") {
			home = strings.TrimPrefix(args[i], "--home=")
			continue
		}
		rest = append(rest, args[i])
	}
	args = rest

	var err error
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(helpText)
	case "version", "-v", "--version":
		fmt.Printf("crewwatch %s\n", version)
	case "daemon":
		once := false
		for _, a := range args[1:] {
			if a == "--once" {
				once = true
			}
		}
		err = cmdDaemon(home, once)
	case "goal":
		err = cmdGoal(home, args[1:])
	case "status":
		err = cmdStatus(home, args[1:])
	case "verify":
		err = cmdVerify(home, args[1:])
	case "audit":
		err = cmdAudit(home, args[1:])
	case "eval":
		err = cmdEval(home, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "crewwatch: unknown command %q\n\n%s", args[0], helpText)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "crewwatch: %v\n", err)
		os.Exit(1)
	}
}

func resolveHome() string {
	if h := os.Getenv("CREWWATCH_HOME"); h != "" {
		return h
	}
	hd, err := os.UserHomeDir()
	if err != nil {
		return ".crewwatch"
	}
	return filepath.Join(hd, ".crewwatch")
}

func openManager(home string) (*manager.Manager, error) {
	return manager.New(home)
}

// cmdDaemon runs the manager loop. --once ticks until idle, then exits.
func cmdDaemon(home string, once bool) error {
	lockPath := filepath.Join(home, "daemon.lock")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another crewwatch daemon is already running for %s", home)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	mgr, err := openManager(home)
	if err != nil {
		return err
	}
	defer mgr.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if once {
		return mgr.RunUntilIdle(ctx)
	}
	fmt.Fprintf(os.Stderr, "crewwatch daemon running (home %s)\n", home)
	mgr.Run(ctx)
	return nil
}

func cmdGoal(home string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: crewwatch goal add|list|cancel")
	}
	switch args[0] {
	case "add":
		var specFile string
		for i := 1; i < len(args); i++ {
			if args[i] == "--spec" && i+1 < len(args) {
				specFile = args[i+1]
				i++
			}
		}
		if specFile == "" {
			return fmt.Errorf("usage: crewwatch goal add --spec FILE")
		}
		raw, err := os.ReadFile(specFile)
		if err != nil {
			return err
		}
		var spec manager.Spec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return fmt.Errorf("bad spec %s: %w", specFile, err)
		}
		mgr, err := openManager(home)
		if err != nil {
			return err
		}
		defer mgr.Close()
		g, err := mgr.AddGoal(&spec)
		if err != nil {
			return err
		}
		fmt.Printf("goal %s\n  title: %s\n  repo: %s\n  tasks: %d\n", g.ID, g.Title, g.Repo, len(spec.Tasks))
		return nil
	case "list":
		mgr, err := openManager(home)
		if err != nil {
			return err
		}
		defer mgr.Close()
		goals, err := mgr.Store.ListGoals()
		if err != nil {
			return err
		}
		if len(goals) == 0 {
			fmt.Println("no goals")
			return nil
		}
		for _, g := range goals {
			fmt.Printf("%s  %-10s %s\n", g.ID, g.Status, g.Title)
			if g.Error != "" {
				fmt.Printf("    error: %s\n", g.Error)
			}
		}
		return nil
	case "cancel":
		if len(args) < 2 {
			return fmt.Errorf("usage: crewwatch goal cancel <goal-id>")
		}
		mgr, err := openManager(home)
		if err != nil {
			return err
		}
		defer mgr.Close()
		if err := mgr.CancelGoal(args[1]); err != nil {
			return err
		}
		fmt.Printf("goal %s cancelled\n", args[1])
		return nil
	default:
		return fmt.Errorf("usage: crewwatch goal add|list|cancel")
	}
}

func cmdStatus(home string, args []string) error {
	mgr, err := openManager(home)
	if err != nil {
		return err
	}
	defer mgr.Close()
	goals, err := mgr.Store.ListGoals()
	if err != nil {
		return err
	}
	if len(args) > 0 {
		var found *state.Goal
		for _, g := range goals {
			if g.ID == args[0] {
				found = g
			}
		}
		if found == nil {
			return fmt.Errorf("no goal %q", args[0])
		}
		goals = []*state.Goal{found}
	}
	for _, g := range goals {
		fmt.Printf("goal %s [%s] %s\n  repo: %s\n", g.ID, g.Status, g.Title, g.Repo)
		if g.Error != "" {
			fmt.Printf("  error: %s\n", g.Error)
		}
		tasks, err := mgr.Store.TasksForGoal(g.ID)
		if err != nil {
			return err
		}
		for _, t := range tasks {
			atts, _ := mgr.Store.AttemptsForTask(t.ID)
			fmt.Printf("  task %s [%s] %s (adapter %s, %d/%d attempts)\n", t.ID, t.Status, t.Title, t.Adapter, len(atts), t.MaxAttempts)
			if t.Worktree != "" {
				fmt.Printf("    worktree: %s (branch %s)\n", t.Worktree, t.Branch)
			}
			for _, a := range atts {
				fmt.Printf("    attempt %s [%s] exit=%d dur=%dms tokens=%d\n", a.ID, a.Status, a.ExitCode, a.DurationMs, a.CostTokens)
			}
			receipts, _ := mgr.Store.ReceiptsForTask(t.ID)
			for _, r := range receipts {
				var rec receipt.Receipt
				if err := json.Unmarshal([]byte(r), &rec); err == nil {
					fmt.Printf("    receipt %s (verified)\n", rec.Payload.ReceiptID)
				}
			}
		}
	}
	return nil
}

func cmdVerify(home string, args []string) error {
	if len(args) > 0 && args[0] == "--all" {
		mgr, err := openManager(home)
		if err != nil {
			return err
		}
		defer mgr.Close()
		all, err := mgr.Store.AllReceipts()
		if err != nil {
			return err
		}
		if len(all) == 0 {
			fmt.Println("no receipts stored")
			return nil
		}
		bad := 0
		for _, raw := range all {
			var r receipt.Receipt
			if err := json.Unmarshal([]byte(raw), &r); err != nil {
				fmt.Printf("INVALID (unparseable): %v\n", err)
				bad++
				continue
			}
			if err := receipt.Verify(&r); err != nil {
				fmt.Printf("INVALID %s: %v\n", r.Payload.ReceiptID, err)
				bad++
			} else {
				fmt.Printf("VALID %s (task %s)\n", r.Payload.ReceiptID, r.Payload.TaskID)
			}
		}
		if bad > 0 {
			return fmt.Errorf("%d of %d receipts failed verification", bad, len(all))
		}
		fmt.Printf("all %d receipts valid\n", len(all))
		return nil
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: crewwatch verify <receipt.json> | crewwatch verify --all")
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var r receipt.Receipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("bad receipt file: %w", err)
	}
	if err := receipt.Verify(&r); err != nil {
		return fmt.Errorf("INVALID: %w", err)
	}
	fmt.Printf("VALID %s\n  task: %s (%s)\n  worker: %s, attempts: %d, diff: %s\n",
		r.Payload.ReceiptID, r.Payload.TaskID, r.Payload.Title,
		r.Payload.WorkerAdapter, r.Payload.Attempts, r.Payload.DiffSHA256)
	return nil
}

func cmdAudit(home string, args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("usage: crewwatch audit verify")
	}
	if err := audit.Verify(filepath.Join(home, "audit.jsonl")); err != nil {
		return fmt.Errorf("audit log INVALID: %w", err)
	}
	fmt.Println("audit log valid")
	return nil
}

func cmdEval(home string, args []string) error {
	outDir := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--out" && i+1 < len(args) {
			outDir = args[i+1]
			i++
		}
	}
	if outDir == "" {
		outDir = filepath.Join(home, "eval")
	}
	// The harness uses a throwaway home so it never touches live state.
	tmpHome, err := os.MkdirTemp("", "crewwatch-eval-home-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpHome)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	res, path, err := eval.Run(ctx, tmpHome, outDir)
	if err != nil {
		return err
	}
	fmt.Printf("eval complete: %d/%d tasks done (%.0f%%)\n", countDone(res), len(res.Tasks), res.CompletionRate*100)
	fmt.Printf("median attempts: %.1f, total tokens: %d, total time: %dms\n", res.MedianAttempts, res.TotalTokens, res.TotalMs)
	fmt.Printf("results: %s\n", path)
	fmt.Printf("note: %s\n", res.Note)
	return nil
}

func countDone(res *eval.Result) int {
	n := 0
	for _, t := range res.Tasks {
		if t.Status == state.TaskDone {
			n++
		}
	}
	return n
}
