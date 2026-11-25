// Package state owns Crewwatch's durable state in SQLite: goals, tasks,
// attempts, receipts, and the adapter registry. All transitions go through
// this package so crash recovery and attempt accounting stay consistent.
package state

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Statuses.
const (
	GoalPending   = "pending"
	GoalRunning   = "running"
	GoalBlocked   = "blocked"
	GoalDone      = "done"
	GoalCancelled = "cancelled"

	TaskPending    = "pending"
	TaskDispatched = "dispatched"
	TaskVerifying  = "verifying"
	TaskDone       = "done"
	TaskFailed     = "failed"
	TaskEscalated  = "escalated"
	TaskCancelled  = "cancelled"

	AttemptRunning     = "running"
	AttemptCompleted   = "completed"
	AttemptFailed      = "failed"
	AttemptInterrupted = "interrupted"
	AttemptTimeout     = "timeout"
)

// Goal is a top-level engineering objective.
type Goal struct {
	ID        string
	Title     string
	Repo      string
	SpecJSON  string
	Status    string
	Error     string
	CreatedAt int64
	UpdatedAt int64
}

// Task is one unit of work inside a goal.
type Task struct {
	ID          string
	GoalID      string
	Title       string
	Acceptance  string
	VerifyCmd   string
	ScriptCmd   string // non-empty only for harness/test tasks (script adapter)
	MaxAttempts int
	Status      string
	Adapter     string
	Worktree    string
	Branch      string
	CreatedAt   int64
	UpdatedAt   int64
}

// Attempt is one worker run against a task.
type Attempt struct {
	ID            string
	TaskID        string
	Adapter       string
	Status        string
	StartedAt     int64
	EndedAt       int64
	ExitCode      int
	DiffHash      string
	CostTokens    int64
	CostUSD       float64
	DurationMs    int64
	TranscriptRef string
}

// Store is a SQLite-backed state store.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the state database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS goals(
		id TEXT PRIMARY KEY, title TEXT NOT NULL, repo TEXT NOT NULL,
		spec_json TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
		error TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
	CREATE TABLE IF NOT EXISTS tasks(
		id TEXT PRIMARY KEY, goal_id TEXT NOT NULL REFERENCES goals(id),
		title TEXT NOT NULL, acceptance TEXT NOT NULL DEFAULT '',
		verify_cmd TEXT NOT NULL DEFAULT '', script_cmd TEXT NOT NULL DEFAULT '',
		max_attempts INTEGER NOT NULL DEFAULT 3, status TEXT NOT NULL,
		adapter TEXT NOT NULL DEFAULT '', worktree TEXT NOT NULL DEFAULT '',
		branch TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
	CREATE TABLE IF NOT EXISTS attempts(
		id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
		adapter TEXT NOT NULL, status TEXT NOT NULL,
		started_at INTEGER NOT NULL, ended_at INTEGER NOT NULL DEFAULT 0,
		exit_code INTEGER NOT NULL DEFAULT 0, diff_hash TEXT NOT NULL DEFAULT '',
		cost_tokens INTEGER NOT NULL DEFAULT 0, cost_usd REAL NOT NULL DEFAULT 0,
		duration_ms INTEGER NOT NULL DEFAULT 0, transcript_ref TEXT NOT NULL DEFAULT '');
	CREATE TABLE IF NOT EXISTS receipts(
		id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
		receipt_json TEXT NOT NULL, signature TEXT NOT NULL,
		sha256 TEXT NOT NULL, created_at INTEGER NOT NULL);
	CREATE TABLE IF NOT EXISTS adapters(
		name TEXT PRIMARY KEY, cli TEXT NOT NULL, args_json TEXT NOT NULL DEFAULT '[]',
		capabilities_json TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 1);
	CREATE INDEX IF NOT EXISTS idx_tasks_goal ON tasks(goal_id, status);
	CREATE INDEX IF NOT EXISTS idx_attempts_task ON attempts(task_id, started_at);
	`)
	return err
}

func now() int64 { return time.Now().Unix() }

// --- goals ---

func (s *Store) CreateGoal(g *Goal) error {
	g.CreatedAt, g.UpdatedAt = now(), now()
	_, err := s.db.Exec(`INSERT INTO goals(id,title,repo,spec_json,status,error,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?)`, g.ID, g.Title, g.Repo, g.SpecJSON, g.Status, g.Error, g.CreatedAt, g.UpdatedAt)
	return err
}

func (s *Store) GetGoal(id string) (*Goal, error) {
	g := &Goal{}
	err := s.db.QueryRow(`SELECT id,title,repo,spec_json,status,error,created_at,updated_at FROM goals WHERE id=?`,
		id).Scan(&g.ID, &g.Title, &g.Repo, &g.SpecJSON, &g.Status, &g.Error, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (s *Store) ListGoals() ([]*Goal, error) {
	rows, err := s.db.Query(`SELECT id,title,repo,spec_json,status,error,created_at,updated_at FROM goals ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Goal
	for rows.Next() {
		g := &Goal{}
		if err := rows.Scan(&g.ID, &g.Title, &g.Repo, &g.SpecJSON, &g.Status, &g.Error, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) SetGoalStatus(id, status, errMsg string) error {
	_, err := s.db.Exec(`UPDATE goals SET status=?, error=?, updated_at=? WHERE id=?`, status, errMsg, now(), id)
	return err
}

// --- tasks ---

func (s *Store) CreateTask(t *Task) error {
	t.CreatedAt, t.UpdatedAt = now(), now()
	_, err := s.db.Exec(`INSERT INTO tasks(id,goal_id,title,acceptance,verify_cmd,script_cmd,max_attempts,status,adapter,worktree,branch,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, t.ID, t.GoalID, t.Title, t.Acceptance, t.VerifyCmd, t.ScriptCmd,
		t.MaxAttempts, t.Status, t.Adapter, t.Worktree, t.Branch, t.CreatedAt, t.UpdatedAt)
	return err
}

func (s *Store) GetTask(id string) (*Task, error) {
	t := &Task{}
	err := s.db.QueryRow(`SELECT id,goal_id,title,acceptance,verify_cmd,script_cmd,max_attempts,status,adapter,worktree,branch,created_at,updated_at
		FROM tasks WHERE id=?`, id).Scan(&t.ID, &t.GoalID, &t.Title, &t.Acceptance, &t.VerifyCmd, &t.ScriptCmd,
		&t.MaxAttempts, &t.Status, &t.Adapter, &t.Worktree, &t.Branch, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Store) TasksForGoal(goalID string) ([]*Task, error) {
	rows, err := s.db.Query(`SELECT id,goal_id,title,acceptance,verify_cmd,script_cmd,max_attempts,status,adapter,worktree,branch,created_at,updated_at
		FROM tasks WHERE goal_id=? ORDER BY created_at`, goalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t := &Task{}
		if err := rows.Scan(&t.ID, &t.GoalID, &t.Title, &t.Acceptance, &t.VerifyCmd, &t.ScriptCmd,
			&t.MaxAttempts, &t.Status, &t.Adapter, &t.Worktree, &t.Branch, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// NextPendingTask returns the oldest pending task of a running goal, if any.
func (s *Store) NextPendingTask() (*Task, error) {
	t := &Task{}
	err := s.db.QueryRow(`SELECT t.id,t.goal_id,t.title,t.acceptance,t.verify_cmd,t.script_cmd,t.max_attempts,t.status,t.adapter,t.worktree,t.branch,t.created_at,t.updated_at
		FROM tasks t JOIN goals g ON g.id=t.goal_id
		WHERE t.status=? AND g.status=? ORDER BY t.created_at LIMIT 1`, TaskPending, GoalRunning).
		Scan(&t.ID, &t.GoalID, &t.Title, &t.Acceptance, &t.VerifyCmd, &t.ScriptCmd,
			&t.MaxAttempts, &t.Status, &t.Adapter, &t.Worktree, &t.Branch, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// NextPendingGoal returns the oldest running goal with no tasks yet.
func (s *Store) NextPendingGoal() (*Goal, error) {
	g := &Goal{}
	err := s.db.QueryRow(`SELECT g.id,g.title,g.repo,g.spec_json,g.status,g.error,g.created_at,g.updated_at
		FROM goals g WHERE g.status=? AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.goal_id=g.id)
		ORDER BY g.created_at LIMIT 1`, GoalRunning).
		Scan(&g.ID, &g.Title, &g.Repo, &g.SpecJSON, &g.Status, &g.Error, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (s *Store) SetTaskStatus(id, status string) error {
	_, err := s.db.Exec(`UPDATE tasks SET status=?, updated_at=? WHERE id=?`, status, now(), id)
	return err
}

func (s *Store) SetTaskWorktree(id, worktree, branch, adapter string) error {
	_, err := s.db.Exec(`UPDATE tasks SET worktree=?, branch=?, adapter=?, updated_at=? WHERE id=?`,
		worktree, branch, adapter, now(), id)
	return err
}

// StaleTasks returns tasks left in dispatched/verifying by a dead daemon.
func (s *Store) StaleTasks() ([]*Task, error) {
	rows, err := s.db.Query(`SELECT id,goal_id,title,acceptance,verify_cmd,script_cmd,max_attempts,status,adapter,worktree,branch,created_at,updated_at
		FROM tasks WHERE status IN (?,?) ORDER BY created_at`, TaskDispatched, TaskVerifying)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t := &Task{}
		if err := rows.Scan(&t.ID, &t.GoalID, &t.Title, &t.Acceptance, &t.VerifyCmd, &t.ScriptCmd,
			&t.MaxAttempts, &t.Status, &t.Adapter, &t.Worktree, &t.Branch, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountAttempts returns how many attempts exist for a task, by status.
func (s *Store) CountAttempts(taskID, status string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM attempts WHERE task_id=? AND status=?`, taskID, status).Scan(&n)
	return n, err
}

// --- attempts ---

func (s *Store) CreateAttempt(a *Attempt) error {
	_, err := s.db.Exec(`INSERT INTO attempts(id,task_id,adapter,status,started_at,ended_at,exit_code,diff_hash,cost_tokens,cost_usd,duration_ms,transcript_ref)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, a.ID, a.TaskID, a.Adapter, a.Status, a.StartedAt, a.EndedAt,
		a.ExitCode, a.DiffHash, a.CostTokens, a.CostUSD, a.DurationMs, a.TranscriptRef)
	return err
}

func (s *Store) FinishAttempt(a *Attempt) error {
	_, err := s.db.Exec(`UPDATE attempts SET status=?, ended_at=?, exit_code=?, diff_hash=?, cost_tokens=?, cost_usd=?, duration_ms=?, transcript_ref=?
		WHERE id=?`, a.Status, a.EndedAt, a.ExitCode, a.DiffHash, a.CostTokens, a.CostUSD, a.DurationMs, a.TranscriptRef, a.ID)
	return err
}

func (s *Store) AttemptsForTask(taskID string) ([]*Attempt, error) {
	rows, err := s.db.Query(`SELECT id,task_id,adapter,status,started_at,ended_at,exit_code,diff_hash,cost_tokens,cost_usd,duration_ms,transcript_ref
		FROM attempts WHERE task_id=? ORDER BY started_at`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Attempt
	for rows.Next() {
		a := &Attempt{}
		if err := rows.Scan(&a.ID, &a.TaskID, &a.Adapter, &a.Status, &a.StartedAt, &a.EndedAt, &a.ExitCode,
			&a.DiffHash, &a.CostTokens, &a.CostUSD, &a.DurationMs, &a.TranscriptRef); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RunningAttempts returns attempts still marked running (for crash recovery).
func (s *Store) RunningAttempts() ([]*Attempt, error) {
	rows, err := s.db.Query(`SELECT id,task_id,adapter,status,started_at,ended_at,exit_code,diff_hash,cost_tokens,cost_usd,duration_ms,transcript_ref
		FROM attempts WHERE status=?`, AttemptRunning)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Attempt
	for rows.Next() {
		a := &Attempt{}
		if err := rows.Scan(&a.ID, &a.TaskID, &a.Adapter, &a.Status, &a.StartedAt, &a.EndedAt, &a.ExitCode,
			&a.DiffHash, &a.CostTokens, &a.CostUSD, &a.DurationMs, &a.TranscriptRef); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- receipts ---

func (s *Store) SaveReceipt(taskID, receiptJSON, signature, sha string) error {
	_, err := s.db.Exec(`INSERT INTO receipts(id,task_id,receipt_json,signature,sha256,created_at) VALUES(?,?,?,?,?,?)`,
		sha, taskID, receiptJSON, signature, sha, now())
	return err
}

func (s *Store) ReceiptsForTask(taskID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT receipt_json FROM receipts WHERE task_id=? ORDER BY created_at`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) AllReceipts() ([]string, error) {
	rows, err := s.db.Query(`SELECT receipt_json FROM receipts ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// --- adapters ---

func (s *Store) RegisterAdapter(name, cli, argsJSON, capsJSON string, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.Exec(`INSERT INTO adapters(name,cli,args_json,capabilities_json,enabled) VALUES(?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET cli=excluded.cli, args_json=excluded.args_json,
		capabilities_json=excluded.capabilities_json, enabled=excluded.enabled`,
		name, cli, argsJSON, capsJSON, en)
	return err
}

func (s *Store) GetAdapter(name string) (cli, argsJSON, capsJSON string, enabled bool, err error) {
	var en int
	err = s.db.QueryRow(`SELECT cli,args_json,capabilities_json,enabled FROM adapters WHERE name=?`, name).
		Scan(&cli, &argsJSON, &capsJSON, &en)
	if err != nil {
		return "", "", "", false, err
	}
	return cli, argsJSON, capsJSON, en == 1, nil
}

// DB exposes the underlying handle for tests that need raw queries.
func (s *Store) DB() *sql.DB { return s.db }

var _ = fmt.Sprintf
