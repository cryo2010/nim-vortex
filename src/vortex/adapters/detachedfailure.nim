## A raise the async adapters' pump caught from a dispatcher poll (#423).
## Internal to the adapters (both backends import it); not part of the API.
##
## A task a handler detached (`asyncCheck` on asyncdispatch, `asyncSpawn` on
## chronos) and never awaits has nowhere to send its error but the
## dispatcher's own callback: asyncCheck re-raises the failed future's error
## there, and asyncSpawn raises a FutureDefect for a failed (or cancelled) task.
## Both surface inside the pump's poll, on the loop thread. Before #423 nothing
## between the pump and the loop thread's entry caught them, so one failing
## detached task ended its loop thread and closed its listener. The pump now
## catches each poll's raise, reports it here and carries on, the way a failing
## per-connection handler costs only its own connection.
##
## chronos has a second source of such a raise: its async transform does not
## catch a Defect (it re-raises it eagerly, even under `handleException`), so a
## Defect an `{.async.}` body raises after an `await` leaves the continuation's
## callback, inside the same poll, and that body's future never completes. The
## pump cannot tell which future it was, so it reports that one under its own
## line (noteAsyncDefect).

import std/[monotimes, strutils]
from ../eventloop import opLog

# One line per loop thread and kind at most every `logSec`, with the running
# count, so a task that fails on every request cannot flood the operator log;
# the first failure of each kind is always reported (the accept-path drops
# follow the same rule).
const logSec = 5

const maxSummary = 500
  ## Characters of the error message kept in the log line: a runtime's message
  ## can carry a whole formatted traceback or a payload, and the line is meant
  ## to be read in a log.

type Tally = object
  count: int
  loggedAt: int64                       # MonoTime ticks (ns); 0 = never logged

var detached {.threadvar.}: Tally
var asyncDefects {.threadvar.}: Tally

proc failureSummary*(e: ref Exception): string =
  ## The error on one line: its message up to the traceback the runtimes append
  ## (asyncdispatch's "Async traceback:", chronos's and a raised Defect's
  ## "Stack trace:" header), at most maxSummary characters. Exported for the
  ## adapter suite only.
  for line in e.msg.splitLines:
    let l = line.strip
    if l.startsWith("Async traceback") or l.startsWith("Stack trace"): break
    if l.len > 0:
      if result.len > 0: result.add ' '
      result.add l
    if result.len > maxSummary:
      result.setLen(maxSummary)
      result.add "..."
      break
  if result.len == 0: result = $e.name

proc due(t: var Tally): bool =
  ## Count one, and say whether this one is logged (see logSec).
  inc t.count
  let now = getMonoTime().ticks
  if t.loggedAt != 0 and now - t.loggedAt < logSec * 1_000_000_000: return false
  t.loggedAt = max(now, 1)
  true

proc noteDetachedFailure*(e: ref Exception) {.gcsafe.} =
  ## Report a detached task's failure the pump caught from a poll (#423).
  {.gcsafe.}:
    if not due(detached): return
    opLog("async adapter: a detached task failed (the loop carries on): " &
      failureSummary(e) & " [" & $detached.count & " on this loop thread so far]")

proc noteAsyncDefect*(e: ref Exception) {.gcsafe.} =
  ## Report a Defect chronos let out of an async body's continuation (#423):
  ## not a detached task's FutureDefect, so it came from a watched handler or a
  ## task the app awaits, whose future now never completes.
  {.gcsafe.}:
    if not due(asyncDefects): return
    opLog("async adapter: an async body raised a Defect past an await " &
      "(the loop carries on): " & $e.name & ": " & failureSummary(e) &
      " -- chronos does not catch Defects, so that body's future never " &
      "completes and a request it was answering gets no response until its " &
      "timeout; catch it in the body, or run the code in a doAsync: block, " &
      "which answers 500 [" & $asyncDefects.count &
      " on this loop thread so far]")
