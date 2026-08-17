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
const maxBuckets = 100_000
  ## Hard cap on distinct keys tracked per loop thread (R5). A distinct-key
  ## flood -- spoofable `req.remoteAddress`, or a client rotating through an
  ## IPv6 /64 -- used to grow the table without bound within the 60s prune
  ## window. When the table is full, a throttled prune reclaims idle buckets;
  ## if it is still full, a new (unseen) key is allowed through but not tracked,
  ## so the limiter can never become a memory-DoS amplifier. Keys already
  ## tracked keep being limited. At ~100 bytes/entry the ceiling is a few
  ## MB/thread.

proc pruneStale(now: MonoTime, ratePerSec, cap: float) =
  ## Forget buckets that have refilled back to full: an idle, brimming bucket is
  ## indistinguishable from a fresh one, so dropping it changes nothing.
  lastPrune = now
  var stale: seq[string]
  for k, b in buckets:
    let refilled = b.tokens +
      ratePerSec * float((now - b.last).inMilliseconds) / 1000.0
    if refilled >= cap: stale.add k
  for k in stale: buckets.del k

proc rateLimit*(key: string, ratePerSec: float, burst: int): bool =
  ## Consume one token for `key`. Returns true if the request is allowed, false
  ## if `key` is over its limit (answer 429 then). `ratePerSec` is the steady
  ## refill rate and `burst` the bucket capacity (the most requests a key may
  ## make in a spike). `ratePerSec <= 0` or `burst <= 0` disables it (always
  ## true). A key costs nothing until first seen; idle keys are pruned and the
  ## table is size-capped, so a distinct-key flood cannot exhaust memory.
  if ratePerSec <= 0 or burst <= 0: return true
  let now = getMonoTime()
  let cap = float(burst)
  # Lazy prune: drop full (idle) buckets so memory stays bounded under many keys.
  if buckets.len > 0 and (now - lastPrune).inSeconds >= pruneIntervalSec:
    pruneStale(now, ratePerSec, cap)
  # Hard size cap (R5): a distinct-key flood must not grow the table without
  # bound between the periodic prunes. When an unseen key would overflow the
  # cap, try one throttled prune (at most ~1/s, so this stays O(1) amortized
  # under a flood); if the table is still full, allow the key but do not track
  # it -- failing open here is safer than letting the limiter eat memory.
  if buckets.len >= maxBuckets and not buckets.hasKey(key):
    if (now - lastPrune).inMilliseconds >= 1000:
      pruneStale(now, ratePerSec, cap)
    if buckets.len >= maxBuckets:
      return true
  var b = buckets.getOrDefault(key, Bucket(tokens: cap, last: now))
  let elapsed = float((now - b.last).inMilliseconds) / 1000.0
  b.tokens = min(cap, b.tokens + ratePerSec * elapsed)
  b.last = now
  result = b.tokens >= 1.0
  if result: b.tokens -= 1.0
  buckets[key] = b

proc rateLimitTrackedKeys*(): int =
  ## Number of keys the calling thread's limiter is currently tracking. For
  ## metrics and tests; the table is bounded by an internal size cap so a
  ## distinct-key flood cannot grow it without limit.
  buckets.len
