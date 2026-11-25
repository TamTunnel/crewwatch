# Crewwatch

A persistent manager agent that owns an engineering goal end-to-end on
free local coding agents — and proves what it did.

## The problem

Devin Bots proved the manager-agent pattern works, then gated it behind
a $200/month Max subscription. The open alternatives orchestrate agents
but never answer the question that matters: **did the work actually get
done, and can you prove it?** A manager that trusts a worker's
self-report is a loop that ships garbage. Nobody in this field publishes
honest long-horizon numbers about what their cheaper stack completes.

## The solution, in plain terms

You give Crewwatch a goal — "fix the login bug", "add CSV export" — and
it breaks the goal into small tasks, hands each task to a coding agent
on your own machine (OpenCode, Qwen Code, Claude Code, Codex, Gemini
CLI), and checks the result itself by running the repo's own tests. A
task only counts as done when those tests pass. Every finished task gets
a signed receipt: what was done, which worker did it, how many tries it
took, and what it cost. If a task can't be fixed, Crewwatch stops after
a set number of tries and hands it back to you — it never loops forever,
and it never merges anything itself. You review the finished work in its
own branch and decide what lands.

## Quick start

```sh
# Build
go build -o build/crewwatch ./cmd/crewwatch

# Add a goal (JSON spec; see examples/goal.json)
./build/crewwatch goal add --spec examples/goal.json

# Run the daemon (leave it running; it picks up goals and works them)
./build/crewwatch daemon

# Check progress
./build/crewwatch status

# Verify a receipt offline
./build/crewwatch verify ~/.crewwatch/receipts/<id>.json

# Run the benchmark harness
./build/crewwatch eval --out eval/results
```

State lives in `~/.crewwatch` (override with `--home` or
`CREWWATCH_HOME`): SQLite state, the hash-chained audit log, transcripts,
receipts, and the signing key (`key.pem`, mode 0600).

A goal spec looks like this:

```json
{
  "title": "Fix the calculator bugs",
  "repo": "/home/you/projects/calc",
  "adapter": "opencode",
  "timeout_secs": 600,
  "tasks": [
    {
      "title": "Fix Add returning a-b",
      "acceptance": "Add(a, b) returns a+b; go test ./... passes.",
      "verify_cmd": "go test ./...",
      "max_attempts": 3
    }
  ]
}
```

Omit `tasks` and Crewwatch asks the adapter to decompose the goal; if
it cannot be decomposed, the goal fails closed with zero dispatches.
Omit `verify_cmd` and it is detected from the repo (`go test ./...` for
Go modules, `npm test` for Node). A task with no verifiable check is
never dispatched.

Worker adapters are pinned commands. The defaults assume the CLIs'
non-interactive modes (`opencode run`, `qwen -p`, `claude -p`,
`codex exec`, `gemini -p`); override one with
`CREWWATCH_ADAPTER_<NAME>_CMD`, e.g.
`CREWWATCH_ADAPTER_QWEN_CMD="qwen --yolo -p"`.

## Architecture

Single Go binary (daemon + CLI), stdlib-first, one dependency:
SQLite via `modernc.org/sqlite` — crash-safe transactional state is the
core promise (resume-after-kill), and a JSONL store cannot give atomic
task transitions.

- **Manager daemon** (`internal/manager`): owns the goal lifecycle.
  Single process, SQLite state, polls for work. Survives restart and
  resumes in-flight goals; a task left mid-flight by a killed daemon is
  marked interrupted and re-dispatched — attempt counts prove no
  duplicated dispatches.
- **Goal → task DAG**: each task has a written acceptance criterion, a
  verification command, and a bounded attempt budget. A goal that cannot
  be decomposed fails closed.
- **Worker adapters** (`internal/adapter`): one per CLI. Contract:
  `dispatch(task, worktree) → result{diff, transcript, exit}`. Workers
  run in their own git worktree of the target repo and are killed as a
  whole process group on timeout. "Hermes" is not an adapter: it is a
  model family, not a CLI — pin a runner or drop it.
- **Verifier**: runs the repo's own test suite in the worktree. Task
  closes only when the verifier passes; a worker's "done" is never
  sufficient. Verification must also produce evidence (non-empty output
  or a non-empty diff), or the task escalates.
- **Receipts** (`internal/receipt`): every closed task emits a signed,
  content-addressed receipt (`crewwatch/1`, Ed25519 over JCS-canonical
  JSON). `verify` works offline. Flipping one byte fails verification.
- **Audit log** (`internal/audit`): hash-chained JSONL alongside
  SQLite; every manager decision is appended.
- **Human gate**: verified tasks wait in their worktree (branch
  `cw-<task-id>`) for a human to review. Crewwatch never merges and
  never pushes.
- **Eval harness** (`internal/eval`, `crewwatch eval`): a benchmark of
  10 real tasks across 2 repos, run end-to-end, with completion rate,
  median attempts, and cost recorded in `eval/results/`. The harness
  workers are scripted fixers — the numbers measure the manager
  pipeline, not model capability. Real CLI adapters are exercised with
  stub CLIs in the adapter tests.

## Honest limits

- **Long-horizon reliability is unproven.** Manager agents drift, loop,
  and burn tokens. The harness exists to measure this, not to hide it.
  Early completion rates may be poor; they are published anyway.
- **Free local models are weaker than frontier models.** The cost pitch
  is real; the capability ceiling is lower than Devin's.
- **Green tests ≠ correct.** Verification via the repo's own tests only
  works if the repo has tests, and tests can pass on wrong code. The
  verifier is necessary, not sufficient.
- **Workers run with your credentials and filesystem access (no sandbox in v1).** A worker can read your home directory and environment — the
  same accepted residual as Triangulate's B6. This is disclosed here, in
  `--help`, and on stderr on every dispatch. A real sandbox is a v1.1
  assessment. The manager does detect a worker writing outside its
  worktree (the main checkout is snapshotted before dispatch) and
  escalates the task — but that is detection, not prevention.
- **Workers have full network access in v1.** There is no egress
  allowlist. If you need one, that is a v1.1 feature, not a config flag
  that exists today.
- **Worker CLI interfaces are unstable.** Flags change, JSON output
  changes, CLIs add interactive prompts. Adapters break; the manager
  fails closed on unparseable output, never guesses.
- **Cognition can move the price.** If Devin opens Bots to Pro or cuts
  Max, the price moat shrinks to zero. Verification + the eval harness
  is the only durable moat.
- **Orca already ships the adjacent product.** Any claim of "first open
  local multi-agent manager" would be false.

## FAQs

**Does Crewwatch merge my PRs?**
No. It never merges and never pushes. Finished work waits in a
worktree for you to review and land.

**What if a worker says it is done but the tests fail?**
The task is marked failed, not done. It retries (up to its attempt
budget) with the failure in the prompt, then escalates to you.

**What if the daemon is killed mid-task?**
On restart it marks the interrupted attempt, returns the task to
pending, and re-dispatches. Attempt counts prove nothing was
dispatched twice.

**Which coding agents does it support?**
OpenCode, Qwen Code, Claude Code, Codex, and Gemini CLI via adapters.
They must be installed and authenticated on your machine; Crewwatch
shells out to them. The `script` adapter exists for the eval harness
and tests only.

**How do I check a receipt?**
`crewwatch verify <receipt.json>` — offline, no daemon needed.
`crewwatch verify --all` checks every stored receipt.

**Where is the eval evidence?**
`eval/results/` holds the recorded harness runs. The harness is the
ship gate: no measured completion rate, no ship.

## License

Apache 2.0. See [LICENSE](LICENSE).
