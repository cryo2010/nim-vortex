## Concurrent TLS certificate reloads. `reloadTls` is documented as callable
## from any ordinary thread, so two of them may run it at once (a SIGHUP loop
## plus an admin endpoint): the SSL_CTX swap and the bookkeeping around it must
## serialise rather than interleave, or one context is freed twice and another
## leaks (#360). A burst of reloads must likewise never release a context a
## loop thread is about to hand to `SSL_new` (#364).
##
## A race cannot be asserted directly, so these are stress tests: they hammer
## the paths from several threads and must survive with every reload reporting
## success. `NIM_SANITIZE=1 nim c -r tests/test_tls_reload_race.nim` turns a
## double free or use-after-free into an ASan abort instead of leaving it to
## chance.

import std/[unittest, os, atomics, net, nativesockets, httpcore, strutils]
import std/httpclient except Response
import vortex/[settings, request, server]
import vortex/transport/tls
import ./helper

let rdir = getTempDir() / "vortex_tls_race_" & $getCurrentProcessId()
removeDir(rdir); createDir(rdir)
let rCert = rdir / "cert.pem"
let rKey = rdir / "key.pem"
genCert(rCert, rKey, "race.vortex")

# Shared with the threads as a plain pointer, and reloaded with empty arguments
# (re-read the configured paths), so no GC'd state crosses a thread boundary:
# whatever these tests catch is the TLS config's own race and nothing else.
var raceCfg: ptr TlsConfig
var reloadFails: Atomic[int]
var sessionFails: Atomic[int]
var bursting: Atomic[bool]

proc reloaderThread(reps: int) {.thread.} =
  # reloadTlsConfig is not gcsafe (it copies the stored material strings); the
  # lock it takes internally is what makes calling it from two threads safe.
  {.cast(gcsafe).}:
    for _ in 0 ..< reps:
      if not reloadTlsConfig(raceCfg): reloadFails.atomicInc()

proc sessionThread(minReps: int) {.thread.} =
  ## Hammer newTlsSession on one unconnected fd (so SSL_new is the only thing
  ## under test, no handshake) for as long as the reload burst runs. This is the
  ## load-then-SSL_new window the retire ring could not protect: it freed the
  ## oldest retained ctx once a fifth reload arrived inside the grace window.
  {.cast(gcsafe).}:
    let fd = createNativeSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    if fd == osInvalidSocket:
      sessionFails.atomicInc()
      return
    var n = 0
    while n < minReps or bursting.load():
      let ssl = newTlsSession(raceCfg, cint(fd))
      if ssl == nil: sessionFails.atomicInc()
      else: freeTlsSession(ssl)
      inc n
    fd.close()

suite "concurrent TLS certificate reload":
  test "four threads reloading at once keep the config intact":
    raceCfg = newTlsConfig(rCert, rKey)
    var th: array[4, Thread[int]]
    for i in 0 ..< th.len: createThread(th[i], reloaderThread, 60)
    joinThreads(th)
    check reloadFails.load == 0
    # Every reload rebuilt the ctx from the same files, so the surviving ctx
    # still serves that certificate, and freeing the config (with whatever the
    # bookkeeping left behind) must not fault either.
    check "race.vortex" in ctxCertSubject(raceCfg)
    freeTlsConfig(raceCfg)

  test "sessions created during a reload burst are all valid":
    raceCfg = newTlsConfig(rCert, rKey)
    reloadFails.store(0)
    var rth: Thread[int]
    var sth: array[3, Thread[int]]
    bursting.store(true)
    createThread(rth, reloaderThread, 120)   # far more than the 4 old slots
    for i in 0 ..< sth.len: createThread(sth[i], sessionThread, 200)
    joinThread(rth)
    bursting.store(false)
    joinThreads(sth)
    check reloadFails.load == 0
    check sessionFails.load == 0
    freeTlsConfig(raceCfg)

removeDir(rdir)

# --- a reload burst against a live server ------------------------------------
# End to end: the reloads come through the public API while loop threads run
# newTlsSession for each accepted connection. The burst is much longer than the
# four retire slots and lands well inside the 5 s grace window the ring used, so
# it is exactly the case where the ring was forced to free a context it had
# promised to keep. A connection that handshook before the burst must still
# complete its request afterwards.

let bdir = getTempDir() / "vortex_tls_burst_" & $getCurrentProcessId()
removeDir(bdir); createDir(bdir)
let bCert = bdir / "cert.pem"
let bKey = bdir / "key.pem"
genCert(bCert, bKey, "burst.vortex")

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

proc opener(arg: tuple[port: Port, reps: int]) {.thread.} =
  ## Connect and drop, over and over: every accept makes a loop thread create a
  ## TLS session on whatever ctx the burst has just published.
  for _ in 0 ..< arg.reps:
    var s = newSocket(buffered = false)
    try: s.connect("127.0.0.1", arg.port)
    except CatchableError: discard
    s.close()

suite "TLS reload burst with connections in flight":
  test "a connection made before the burst still completes after it":
    var srv = newVortex(RequestHandler(handler), initVortexConfig(
      numThreads = 4, reusePort = true, http3 = false,
      certFile = bCert, keyFile = bKey)).start(0)
    let port = srv.port
    # Handshake now, on the pre-burst ctx, and keep the connection open.
    var live = newSocket(buffered = true)
    newContext(verifyMode = CVerifyNone).wrapSocket(live)
    live.connect("127.0.0.1", port)
    var th: array[3, Thread[tuple[port: Port, reps: int]]]
    for i in 0 ..< th.len: createThread(th[i], opener, (port, 40))
    for _ in 0 ..< 40: check srv.reloadTls()
    joinThreads(th)
    live.send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    # Bounded, so a session left on a released ctx fails the test instead of
    # hanging it.
    check live.recvLine(timeout = 10_000) == "HTTP/1.1 200 OK"
    live.close()
    # And a fresh handshake against the post-burst ctx works.
    var c = newHttpClient(sslContext = newContext(verifyMode = CVerifyNone))
    check c.getContent("https://127.0.0.1:" & $port & "/") == "ok"
    c.close()
    srv.close()

removeDir(bdir)
echo "tls reload race ok"
