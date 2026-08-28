## ThreadSanitizer regression: concurrent per-request router traversal.
##
## The route trie and its handler closures are built once, then shared read-only
## across the loop threads for the process lifetime (GC-pinned). If `route()` /
## `match()` / `streamPredicate` take *owning* copies of those shared refs per
## request (`let node = root.match(...)`, `var h = node.handlers[m]`, a
## `for child in node.children` loop var), ORC increfs/decrefs one non-atomic
## refcount concurrently from several loop threads and corrupts the cycle
## collector -- an intermittent `SIGSEGV` under load (fixed in routing.nim by
## traversing with `ptr` / `{.cursor.}`).
##
## Unlike test_thread_race (which only cycles start/shutdown), this drives real
## concurrent requests against a MULTI-THREADED server so the racing traversal
## actually runs on >=2 loop threads at once. Built under `-fsanitize=thread` by
## `nimble testrace`; TSan aborts (non-zero) on any data race, failing the task.
import vortex
import std/[net, posix, os, strutils]

proc rootH(req: Request, res: Response) {.gcsafe.} = res.send(Http200, "root")
proc aH(req: Request, res: Response) {.gcsafe.} = res.send(Http200, "a")
proc itemH(req: Request, res: Response) {.gcsafe.} = res.send(Http200, req.param("id"))
proc deepH(req: Request, res: Response) {.gcsafe.} = res.send(Http200, "deep")

# A mix that makes match() traverse shared nodes: exact, param, nested, and a
# 404 (walks the whole trie without matching). Every request touches the root.
const paths = ["/", "/a", "/a/42", "/b/c/d", "/nope"]

proc oneReq(port: Port, path: string) =
  var s = newSocket(buffered = false)
  try:
    s.connect("127.0.0.1", port)
    s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    var buf = newString(4096)
    while posix.recv(s.getFd, addr buf[0], buf.len, cint(0)) > 0: discard
  except CatchableError: discard
  finally: s.close()

proc hammer(arg: tuple[port: Port, reps: int]) {.thread.} =
  for _ in 0 ..< arg.reps:
    for p in paths: oneReq(arg.port, p)

when isMainModule:
  var router = newRouter()
  router.get("/", rootH)
  router.get("/a", aH)
  router.get("/a/:id", itemH)
  router.get("/b/c/d", deepH)
  router.post("/up", rootH, streaming = true)   # a streaming route -> streamPredicate runs per request
  let srv = newVortex(router.toHandler,
                      initVortexConfig(numThreads = 4, reusePort = true),
                      router.streamPredicate).start(0)
  # Load is env-tunable (RR_CLIENTS / RR_REPS) so CI can dial it and a quick
  # smoke can dial it down; the defaults keep enough concurrent same-node
  # traffic that TSan reliably observes any reintroduced refcount race.
  let nClients = parseInt(getEnv("RR_CLIENTS", "8"))
  let reps = parseInt(getEnv("RR_REPS", "60"))
  var clients = newSeq[Thread[tuple[port: Port, reps: int]]](nClients)
  for i in 0 ..< nClients:
    createThread(clients[i], hammer, (srv.port, reps))
  joinThreads(clients)
  srv.close()
  echo "router race regression ok"
