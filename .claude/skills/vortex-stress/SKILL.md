---
name: vortex-stress
description: >-
  Start and monitor a vortex Dockerized stress soak from a plain-English prompt.
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

Turn a plain-English request (`$prompt`) into a `nimble stress<Workload>` Docker soak, run it,
watch it, and drive an autonomous **fail → fix → restart** loop until one complete run passes
clean. Then print a report.

`$prompt` is the whole invocation text (also `$ARGUMENTS`). If it is empty, ask the user what to
stress and stop.

## 1. Parse the prompt into a command

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

Follow the described **workload**, not any task name the user happens to type. "Stress
websockets" → `stressWs` even if the user wrote `stressRequests`. (`nimble stress` runs a short
smoke of all five; use it only if the prompt clearly asks for an all-workloads smoke.)

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
- `VORTEX_RUN_ID` = **always set it** to a stable slug like `vx-<workload>` (e.g. `vx-ws`). It
  names the docker network / server container / image tags, so you can find and post-mortem the
  run deterministically instead of chasing run.sh's PID. It also lets independent soaks run in
  parallel without clobbering each other.
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

Reference (don't re-derive): the tasks live in `vortex.nimble:221-245`; the orchestration, the
proto→build-flags matrix, and the per-cell run live in `conformance/stress/run.sh`; the full knob
table with defaults and the pass/fail banner semantics are in `conformance/stress/README.md`.

**Echo the exact command before running it**, on its own line for observability, e.g.:

```
VORTEX_PROTO=all VORTEX_SECONDS=28800 VORTEX_REPORT_SECONDS=900 VORTEX_SERVER=chronos VORTEX_RUN_ID=vx-ws nimble stressWs
```

Only include the env vars you actually set (plus the always-set `VORTEX_REPORT_SECONDS` and
`VORTEX_RUN_ID`). Keep the invariant `<env> nimble stress<Workload>`.

## 2. Launch the soak

- No separate image to pick: run.sh builds a client image once, then builds a server image
  **per cell** (protocol × server-runtime) from the current worktree. h3 reuses the h2 server
  image (only the `STRESS_HTTP3` runtime toggle differs), so an `all` run does not double-build.
  The first client + server build can take minutes — that's expected.
- Because the build **Docker-copies the live worktree**, run only on a committed, consistent
  tree, and do **not** edit `.nim` source while a build is in flight (torn-read compile errors —
  the `stress-builds-from-worktree` navi memory). Non-source scratch files (logs, `*.md`) are
  safe to write during a build.
- Run the built command with **Bash `run_in_background`**, redirecting to
  `<scratchpad>/<workload>.log` (2>&1).

## 3. Monitor the piped log, with a docker liveness guard

Unlike a single-container soak, vortex's `run.sh` orchestrates the whole matrix **on the host**:
the server runs as a detached container and each client runs `--rm`, so the PASS/FAIL banners and
the `[wl proto server] 200x… | RSS … | heap … | t=…s` report lines are written to **run.sh's
stdout — the piped `<workload>.log`**, not to any one container's logs. So here the piped log
*is* the source of truth (the inverse of the navi soak).

Guard against the pipe silently freezing (the driver getting reaped/reparented on a multi-hour
run — see the `monitor-stress-soaks-via-docker-logs` navi memory): a frozen pipe with no live
containers means the run really stopped. Confirm liveness with
`docker ps --filter name=vortex-stress-server-<VORTEX_RUN_ID>` (and the client image
`vortex-stress-client-img-<VORTEX_RUN_ID>`).

Start a **Bash `run_in_background`** until-loop that tails `<workload>.log` and **exits on a
terminal state**, so the harness wakes this skill exactly at the decision point:

- **PASS**: line matching `== <workload>: all cells passed ==`
- **FAIL**: any of `== <workload>: FAILURES`, `FAIL <workload>:`, `FAILED (exit`, `mismatch`,
  `checksum`, `Traceback`, `panic`, `assert`, `Killed`, `server did not start`,
  `chaos sidecar FAILED`, `FAIL chaos:`

Chaos-sidecar log shape (present unless `VORTEX_CHAOS=none`): each cell ends with a
`--- chaos sidecar ---` block holding its tally lines (`ok: vanish=6 sse:vanish=4 … | err: …`)
and `== chaos sidecar passed (fds N -> M) ==`. Expect a quiet gap of up to ~30 s of finishing
slow behaviors plus a 15 s (40 s on h3) drain pause between the canary's per-cell pass line and
that block: it is the fd-leak reaping window, not a hang. A sidecar failure (e.g. `FAIL chaos:
fd leak (baseline N, final M, slack 8)`) fails the cell only when the canary passed.

Have the loop print which terminal signature it hit and exit. Also set a `ScheduleWakeup`
(~1200s) as a fallback heartbeat in case the run hangs and the log stops growing. On each wake,
if still running, sample the latest report lines (`… 200x… | RSS … | heap … | t=…s`) so you can
show progress and the memory-flatness trend, and confirm a container is still up.

## 4. On PASS → report and finish

Go to section 6.

## 5. On FAIL → stop, fix, restart (the core loop)

1. **Preserve evidence before teardown.** run.sh tears the server container down per-cell (and
   again on exit), so grab it while it's up: `docker logs vortex-stress-server-<VORTEX_RUN_ID> >
   <scratchpad>/srv-logs-<n>.txt 2>&1`. The failing cell (workload × proto × server) and the
   client's `FAIL <workload>: <reason>` cause are already in `<workload>.log` — snapshot its tail
   into the scratchpad too.
2. **Stop the run**: kill the background nimble job, then clean up the run's containers/network/
   images: `docker rm -f vortex-stress-server-<VORTEX_RUN_ID>
   vortex-stress-chaos-<VORTEX_RUN_ID>`, `docker network rm vortex-stress-<VORTEX_RUN_ID>`, and
   `docker rmi -f vortex-stress-server-img-<VORTEX_RUN_ID>
   vortex-stress-client-img-<VORTEX_RUN_ID>` (ignore errors — run.sh's own trap may have removed
   them). The chaos sidecar's own log is already dumped into `<workload>.log` per cell; if the
   run died before that dump, grab `docker logs vortex-stress-chaos-<VORTEX_RUN_ID>` while
   preserving evidence in step 1.
3. **Ensure the session fix branch** (create once, lazily, on the first failure; reuse it for
   every later fix): `git checkout -b fix/stress-<workload>-<shortslug>` off `main`. If it
   already exists this session, stay on it.
4. **Dispatch an opus Agent** (`subagent_type: claude`, `model: opus`) per failure with the
   failing cell, the log tail, and the preserved server logs. Tell the agent to:
   - Root-cause and fix the issue in the vortex source.
   - **Validate with a short, focused run** before committing: same workload, pinned to the
     failing `VORTEX_PROTO` and `VORTEX_SERVER`, `VORTEX_SECONDS=120`, its own `VORTEX_RUN_ID`.
     Do **not** edit `.nim` while a stress build is copying the worktree
     (`stress-builds-from-worktree` memory) — only build when no run is active.
   - Commit on the session branch: **one commit per fix**, semantic message, **no AI
     attribution** of any kind (`no-claude-attribution` memory). Do **not** push.
   - Return the root cause (one line) and the commit sha.
5. **Restart the full run** with the original parameters (full duration and matrix) from
   section 2, and resume monitoring at section 3.
6. **Repeat** until a complete run reaches the PASS banner with no `FAIL`/mismatch.

## 6. Final report

Print a markdown summary:

- The exact command(s) run and total wall-clock.
- Iterations: how many failures were fixed; per failure: the cell, a one-line root cause, and
  the commit sha.
- Branch name + `git log --oneline main..<branch>`.
- Final RSS/heap trend from the last report lines (confirm memory stayed flat).
- A clear **PASS** statement, and a reminder that the fixes sit on `<branch>` (unpushed) for
  review.

If no failures occurred, say so: one clean run, no branch created.
