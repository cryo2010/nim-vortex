## Per-event-loop-thread token-bucket rate limiting (OWASP API4:2023
## Unrestricted Resource Consumption). Keyed by an opaque string, typically
## `req.remoteAddress`.
##
## State is per loop thread (a threadvar), matching vortex's per-core loop
## design and keeping it lock-free. With `numThreads > 1` the limit is therefore
## per thread: a client whose connections spread across loops (SO_REUSEPORT
## hashes by 4-tuple) can get up to `rate x numThreads`. For a strict global
## limit, run `numThreads = 1` or enforce the limit at your proxy. Call
## `rateLimit` at the top of the handler (on the loop thread), before any
## `req.blocking:` -- inside a worker it would use that worker's own table.

import std/[tables, monotimes, times]

type
  Bucket = object
    tokens: float
    last: MonoTime

var buckets {.threadvar.}: Table[string, Bucket]
var lastPrune {.threadvar.}: MonoTime

const pruneIntervalSec = 60

proc rateLimit*(key: string, ratePerSec: float, burst: int): bool =
  ## Consume one token for `key`. Returns true if the request is allowed, false
  ## if `key` is over its limit (answer 429 then). `ratePerSec` is the steady
  ## refill rate and `burst` the bucket capacity (the most requests a key may
  ## make in a spike). `ratePerSec <= 0` or `burst <= 0` disables it (always
  ## true). A key costs nothing until first seen; idle keys are pruned.
  if ratePerSec <= 0 or burst <= 0: return true
  let now = getMonoTime()
  let cap = float(burst)
  # Lazy prune: drop full (idle) buckets so memory stays bounded under many keys.
  if buckets.len > 0 and (now - lastPrune).inSeconds >= pruneIntervalSec:
    lastPrune = now
    var stale: seq[string]
    for k, b in buckets:
      let refilled = b.tokens +
        ratePerSec * float((now - b.last).inMilliseconds) / 1000.0
      if refilled >= cap: stale.add k
    for k in stale: buckets.del k
  var b = buckets.getOrDefault(key, Bucket(tokens: cap, last: now))
  let elapsed = float((now - b.last).inMilliseconds) / 1000.0
  b.tokens = min(cap, b.tokens + ratePerSec * elapsed)
  b.last = now
  result = b.tokens >= 1.0
  if result: b.tokens -= 1.0
  buckets[key] = b
