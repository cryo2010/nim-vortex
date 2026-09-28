---
name: vortex-stress
description: >-
  Start and monitor a vortex Dockerized stress soak from a plain-English prompt, fanning the
  protocol × server matrix out to one parallel opus agent per cell.
  prompt (string): stress run details. Understood hints:
  workload = requests|websockets|sse|stream upload|stream download;
  protocol = h1|h2|h3|all; server = sync|async|async-await|chronos|chronos-await|all;
  duration = e.g. "8 hours", "30m", "90s"; plus optional clients/concurrency/compression/stream bytes.
  Example: "/vortex-stress Stress websockets for 8 hours over all protocols on the chronos server".
disable-model-invocation: true
arguments: prompt
allowed-tools: Bash, Read, Edit, Write, Agent, Monitor
---

# vortex-stress

Orchestrate the following task: $ARGUMENTS. Turn the task into a matrix of pinned `nimble stress<Workload>` soaks. Fan out to agents (up to eight in parallel) to run the soak, monitor it and report any failures back to you. Each agent should handle one combination of server/protocol/workload (e.g. chronos/h2/sse). Once an agent reports a failure, let the other agents finish, fix the issues serially, and then restart the fanned out stress run. Drive an autonomous **fail → fix → restart** loop until one complete round passes clean on every cell. Then print a report.

`$prompt` is the whole invocation text (also `$ARGUMENTS`). If it is empty, ask the user what to
stress and stop.

## 1. Parse the prompt into a cell matrix

Read `$prompt` and pick exactly one workload task, then only the `VORTEX_*` knobs the prompt
actually names. Rely on harness defaults for everything unnamed (do not invent values).

**Workload → nimble task** (first keyword match wins):

| Prompt says… | Task |
| --- | --- |
| request(s), http, verbs, GET/POST/PUT, echo | `stressRequests` |
| websocket, websockets, ws | `stressWs` |
| sse, server-sent, events | `stressSse` |
| upload, stream up | `stressStreamUpload` |
| download, stream down | `stressStreamDownload` |
| (unspecified) | `stress` |

Follow the described **workload**, not any task name the user happens to type. "Stress
websockets" → `stressWs` even if the user wrote `stressRequests`. (`nimble stress` runs a short
smoke of all five; use it only if the prompt clearly asks for an all-workloads smoke.)

Some simple ways to distribute the work are by workload, server and/or protocol.

**Env knobs** (set only when named in the prompt):

- `VORTEX_PROTO` = `all` | `h1` | `h2` | `h3` — from "all protocols"→`all`, "h2"/"http/2"→`h2`,
  "http/3"/"h3"/"quic"→`h3`, "http/1"/"h1"→`h1`. Default (unset) is `h2`. (`all` = h1 + h2 + h3.)
- `VORTEX_SERVER` = `sync` | `async` | `async-await` | `chronos` | `chronos-await` | `all` — the
  handler runtime, from "chronos server"→`chronos`, "async"→`async`, "sync"→`sync`, "all
  runtimes"/"all servers"→`all`. `async` = `vortex/asyncdispatch`, `chronos` = `vortex/chronos`;
  the `-await` variants use the await-style API. Default (unset) is `sync`.
- `VORTEX_SECONDS` = duration in seconds. Parse natural language: "8 hours"→`28800`,
  "90 minutes"/"90m"→`5400`, "30m"→`1800`, "90s"/"90 seconds"→`90`. Default `60`.
- `VORTEX_REPORT_SECONDS` = **derived, always set it**: `clamp(round(VORTEX_SECONDS / 32), 60, 900)`.
  (28800/32 = 900; short runs floor at 60.) The harness default is a flat 60, which floods a
  multi-hour soak with report lines — deriving it keeps the cadence sane.
- `VORTEX_CHAOS` = `all` | `none` | CSV of `slowread,slowwrite,idle,abort,vanish`: the chaos
  sidecar, a second, **unverified** misbehaving client per cell (slow readers, stalling uploads,
  idle holds, mid-transfer aborts, vanishing connections) running alongside the verified canary.
  **Default (unset) is `all`, chaos on by default; do not set it unless the prompt says so.**
  "no chaos"/"without chaos"/"chaos-free"/"clean soak"→`none`; a prompt naming specific
  misbehaviors ("only slow readers and vanishing clients")→the matching CSV. Each style also has
  workload-targeted variants picked automatically by the workload (e.g. vanishing SSE clients
  under `stressSse`), nothing to configure. Verdicts are canary-first: the sidecar can only add
  failures (e.g. an fd leak), never mask one.
- Optional pass-throughs, only if the prompt names them: `VORTEX_CLIENTS`, `VORTEX_CONCURRENCY`,
  `VORTEX_REQ_COMPRESSION`, `VORTEX_RESP_COMPRESSION` (`none`|`gzip`|`br`|`zstd`),
  `VORTEX_STREAM_BYTES` (streaming transfer size, default 1 GiB), `VORTEX_CHAOS_CONC` (sidecar
  workers, default 8), `VORTEX_CHAOS_SEED` (a fixed seed replays an identical chaos schedule;
  set it when reproducing a chaos-correlated failure).

**Expand the matrix into cells.** The skill — not run.sh — walks the matrix: expand
`VORTEX_PROTO=all` → `h1 h2 h3` and `VORTEX_SERVER=all` → `sync async async-await chronos
chronos-await`, then take the cross product. `all × all` = 15 cells (h1/sync, h1/async, …,
h3/chronos-await); a fully pinned prompt ("h2 on chronos") is a 1-cell matrix — same flow, one
agent. Each cell gets:

- `VORTEX_PROTO` and `VORTEX_SERVER` pinned to its single value.
- `VORTEX_RUN_ID` = `vx-<workload>-<proto>-<server>` (e.g. `vx-ws-h3-chronos`). Every docker
  resource (network, server/chaos containers, image tags) derives from it, so distinct run IDs
  make the parallel cells collision-free (no host ports are published; everything rides the
  per-run docker network).
- The same `VORTEX_SECONDS`, `VORTEX_REPORT_SECONDS`, and any pass-throughs.

Reference (don't re-derive): the tasks live in `vortex.nimble`; the proto→build-flags matrix and
the per-cell run live in `conformance/stress/run.sh`; the full knob table with defaults and the
pass/fail banner semantics are in `conformance/stress/README.md`.

**Echo the cell list and one exemplar command before launching**, e.g.:

```
15 cells: {h1,h2,h3} × {sync,async,async-await,chronos,chronos-await}, e.g.
VORTEX_PROTO=h1 VORTEX_SERVER=sync VORTEX_SECONDS=480 VORTEX_REPORT_SECONDS=60 VORTEX_RUN_ID=vx-ws-h1-sync nimble stressWs
```

Only include the env vars you actually set (plus the always-set `VORTEX_REPORT_SECONDS` and
`VORTEX_RUN_ID`). Keep the invariant `<env> nimble stress<Workload>`.

## 2. Fan out: one opus agent per cell

Launch **one Agent per cell** (`subagent_type: claude`, `model: opus`), **all in a single
message** so they run concurrently. Before launching, mind the worktree: the docker builds
**copy the live worktree** — run only on a committed, consistent tree, and do **not** edit
`.nim` source while any cell is building (torn-read compile errors — the
`stress-builds-from-worktree` navi memory; with all cells launching at once, every build is in
flight in the first minutes). Non-source scratch files (logs, `*.md`) are safe to write. The
per-cell image tags are distinct but share docker's layer cache, so concurrent builds dedupe;
the first round of builds can still take minutes — that's expected.

Each cell agent's prompt must contain:

- **Its exact pinned command**, e.g.
  `VORTEX_PROTO=h1 VORTEX_SERVER=sync VORTEX_SECONDS=480 VORTEX_REPORT_SECONDS=60 VORTEX_RUN_ID=vx-ws-h1-sync nimble stressWs`,
  run from the repo root with **Bash `run_in_background`**, redirected to
  `<scratchpad>/<workload>-<proto>-<server>.log` (2>&1).
- **Monitoring instructions** (the piped log is the source of truth: run.sh orchestrates on the
  host, the server container is detached and clients run `--rm`, so banners and report lines
  land in the piped log, not any container's logs). Start a **Bash `run_in_background`**
  until-loop that tails the cell log and **exits on a terminal state**, printing which
  signature it hit:
  - **PASS**: `== <workload>: all cells passed ==` (run.sh prints it even for a pinned 1-cell
    matrix), or for the all-workloads smoke `== stress smoke: all workloads passed ==`.
  - **FAIL**: any of `== <workload>: FAILURES`, `== stress smoke: FAILURES`,
    `FAIL <workload>:`, `FAILED (exit`, `mismatch`, `checksum`, `Traceback`, `panic`,
    `assert`, `Killed`, `server did not start`, `chaos sidecar FAILED`, `FAIL chaos:`
  - Guard against a silently frozen pipe: if the log stops growing, confirm liveness with
    `docker ps --filter name=vortex-stress-server-<VORTEX_RUN_ID>`; a frozen pipe with no live
    container means the run really stopped — treat as FAIL.
  - Chaos-sidecar log shape (present unless `VORTEX_CHAOS=none`): the cell ends with a
    `--- chaos sidecar ---` block holding tally lines (`ok: vanish=6 … | err: …`) and
    `== chaos sidecar passed (fds N -> M) ==`. Expect a quiet gap of up to ~30 s of finishing
    slow behaviors plus a 15 s (40 s on h3) drain pause between the canary's pass line and that
    block: it is the fd-leak reaping window, not a hang. A sidecar failure (e.g. `FAIL chaos:
    fd leak (baseline N, final M, slack 8)`) fails the cell only when the canary passed.
- **On FAIL, preserve evidence before teardown**: while containers are up, grab
  `docker logs vortex-stress-server-<VORTEX_RUN_ID>` and
  `docker logs vortex-stress-chaos-<VORTEX_RUN_ID>` into the scratchpad, and snapshot the cell
  log's tail. Then clean up the cell's resources (ignore errors — run.sh's own trap may have
  removed them): `docker rm -f vortex-stress-server-<id> vortex-stress-chaos-<id>`,
  `docker network rm vortex-stress-<id>`,
  `docker rmi -f vortex-stress-server-img-<id> vortex-stress-client-img-<id>`.
- **Hard rules**: never edit source, never commit, never attempt a fix — run, observe, report.
- **Return a structured verdict**: the cell (workload × proto × server), PASS or FAIL, the
  terminal signature line, a one-line failure reason (if any), the final
  `RSS … | heap … | fds …` report line, and the scratchpad paths of any preserved evidence.

## 3. Parent monitoring

Cell agents notify on completion — collect verdicts as they finish. Also set a `ScheduleWakeup`
(~1200s) fallback heartbeat in case a cell hangs. On each wake, if cells are still running,
sample the latest `[wl proto server] 200x… | RSS … | heap … | t=…s` lines across the per-cell
logs in the scratchpad and check `docker ps --filter name=vortex-stress-server-` so you can
show progress, per-cell liveness, and the memory-flatness trend.

**Wait for every cell to reach a terminal state before acting on failures.** The round restarts
whole-matrix anyway, letting in-flight cells finish collects the full failure set in one
iteration — and it guarantees no builds are copying the worktree when fix agents start editing
`.nim`.

## 4. All cells PASS → report and finish

Go to section 6.

## 5. On failures → fix, then restart the whole matrix

1. **Evidence is already preserved** by the failing cell agents (section 2); their verdicts
   carry the cell, cause, and evidence paths.
2. **Ensure the session fix branch** (create once, lazily, on the first failure; reuse it for
   every later fix): `git checkout -b fix/stress-<workload>-<shortslug>` off `main`. If it
   already exists this session, stay on it.
3. **Dispatch an opus fix Agent** (`subagent_type: claude`, `model: opus`) per distinct
   failure, **serially — one at a time**: fix agents share the worktree and each validates
   with its own build, so they must not overlap each other (or any still-running soak). Give
   each the failing cell, the verdict, and the preserved evidence paths. Tell the agent to:
   - Root-cause and fix the issue in the vortex source. When the failure is
     throughput-sensitive (streaming/h2 timeouts), weigh host contention from the parallel
     soaks as a possible cause before assuming a code bug.
   - **Validate with a short, focused run** before committing: same workload, pinned to the
     failing `VORTEX_PROTO` and `VORTEX_SERVER`, `VORTEX_SECONDS=120`, its own `VORTEX_RUN_ID`.
     Do **not** edit `.nim` while a stress build is copying the worktree
     (`stress-builds-from-worktree` memory) — only build when no run is active.
   - Commit on the session branch: **one commit per fix**, semantic message, **no AI
     attribution** of any kind (`no-claude-attribution` memory). Do **not** push.
   - Return the root cause (one line) and the commit sha.
4. **Restart the entire fan-out** — all cells, full duration — from section 2, and resume
   monitoring at section 3.
5. **Repeat** until a complete round ends with every cell reporting PASS.

## 6. Final report

Print a markdown summary:

- The matrix, the exemplar command, rounds run, and total wall-clock.
- A per-cell result table: cell, pass/fail per round, final RSS/heap from the cell's last
  report line (confirm memory stayed flat everywhere).
- Iterations: how many failures were fixed; per failure: the cell, a one-line root cause, and
  the commit sha.
- Branch name + `git log --oneline main..<branch>`.
- A clear **PASS** statement, and a reminder that the fixes sit on `<branch>` (unpushed) for
  review.

If no failures occurred, say so: one clean round, no branch created.
