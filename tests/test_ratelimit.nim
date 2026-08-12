## SEC3: per-client token-bucket rate limiting (OWASP API4:2023).

import std/[unittest, net, httpcore, sequtils]
import std/httpclient except Response
import vortex/[settings, request, server, ratelimit]

proc handler(req: Request, res: Response) {.gcsafe.} =
  # ~0 refill so burst is the only budget in the test window; burst 3 per IP.
  if not rateLimit(req.remoteAddress, 0.0001, 3):
    res.send(Http429, "slow down")
  else:
    res.send(Http200, "ok")

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

suite "rate limiting (SEC3)":
  test "burst is allowed, then denied (token bucket)":
    check rateLimit("a", 0.0001, 3)
    check rateLimit("a", 0.0001, 3)
    check rateLimit("a", 0.0001, 3)
    check not rateLimit("a", 0.0001, 3)     # 4th over burst 3

  test "separate keys have independent buckets":
    check rateLimit("b", 0.0001, 1)
    check not rateLimit("b", 0.0001, 1)
    check rateLimit("c", 0.0001, 1)          # different key, fresh bucket

  test "disabled when rate or burst <= 0":
    for i in 0 ..< 50:
      check rateLimit("d", 0, 0)

  test "handler enforces the per-IP burst end to end":
    var c = newHttpClient()                  # keep-alive: one loop thread
    defer: c.close()
    var codes: seq[int]
    for i in 0 ..< 6:
      codes.add c.get(base & "/x").code.int
    check codes.count(200) == 3
    check codes.count(429) == 3

srv.close()
echo "rate limit ok"
