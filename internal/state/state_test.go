package state

import (
	"path/filepath"
	"testing"
)

func TestGoalTaskAttemptRoundTrip(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	g := &Goal{ID: "goal-1", Title: "fix", Repo: "/tmp/x", Status: GoalRunning}
	if err := s.CreateGoal(g); err != nil {
		t.Fatal(err)
	}
	tk := &Task{ID: "task-1", GoalID: "goal-1", Title: "t1", VerifyCmd: "go test ./...", MaxAttempts: 3, Status: TaskPending, Adapter: "script"}
	if err := s.CreateTask(tk); err != nil {
		t.Fatal(err)
	}
	next, err := s.NextPendingTask()
	if err != nil || next == nil || next.ID != "task-1" {
		t.Fatalf("NextPendingTask = %+v, err %v", next, err)
	}
	a := &Attempt{ID: "att-1", TaskID: "task-1", Adapter: "script", Status: AttemptRunning, StartedAt: 100}
	if err := s.CreateAttempt(a); err != nil {
		t.Fatal(err)
	}
	a.Status = AttemptCompleted
	a.EndedAt = 101
	a.DurationMs = 50
	if err := s.FinishAttempt(a); err != nil {
		t.Fatal(err)
	}
	atts, err := s.AttemptsForTask("task-1")
	if err != nil || len(atts) != 1 || atts[0].DurationMs != 50 {
		t.Fatalf("attempts = %+v, err %v", atts, err)
	}
	n, err := s.CountAttempts("task-1", AttemptCompleted)
	if err != nil || n != 1 {
		t.Fatalf("count = %d, err %v", n, err)
	}
	if err := s.SetTaskStatus("task-1", TaskDone); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveReceipt("task-1", `{"payload":{}}`, "sig", "sha1"); err != nil {
		t.Fatal(err)
	}
	rs, err := s.ReceiptsForTask("task-1")
	if err != nil || len(rs) != 1 {
		t.Fatalf("receipts = %v, err %v", rs, err)
	}
}
