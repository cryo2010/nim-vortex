## Concurrent TLS certificate reloads. `reloadTls` is documented as callable
## from any ordinary thread, so two of them may run it at once (a SIGHUP loop
## plus an admin endpoint): the SSL_CTX swap and the bookkeeping that retires
## the displaced ctx must serialise rather than interleave, or one context is
## freed twice and another leaks (#360).
##
## A race cannot be asserted directly, so this is a stress test: it hammers the
## path from several threads and must survive with every reload reporting
## success. `NIM_SANITIZE=1 nim c -r tests/test_tls_reload_race.nim` turns a
## double free into an ASan abort instead of leaving it to chance.

import std/[unittest, os, atomics, strutils]
import vortex/transport/tls
import ./helper

let rdir = getTempDir() / "vortex_tls_race_" & $getCurrentProcessId()
removeDir(rdir); createDir(rdir)
let rCert = rdir / "cert.pem"
let rKey = rdir / "key.pem"
genCert(rCert, rKey, "race.vortex")

# Shared with the threads as a plain pointer, and reloaded with empty arguments
# (re-read the configured paths), so no GC'd state crosses a thread boundary:
# whatever this test catches is the TLS config's own race and nothing else.
var raceCfg: ptr TlsConfig
var reloadFails: Atomic[int]

proc reloaderThread(reps: int) {.thread.} =
  # reloadTlsConfig is not gcsafe (it copies the stored material strings); the
  # lock it takes internally is what makes calling it from two threads safe.
  {.cast(gcsafe).}:
    for _ in 0 ..< reps:
      if not reloadTlsConfig(raceCfg): reloadFails.atomicInc()

suite "concurrent TLS certificate reload":
  test "four threads reloading at once keep the config intact":
    raceCfg = newTlsConfig(rCert, rKey)
    var th: array[4, Thread[int]]
    for i in 0 ..< th.len: createThread(th[i], reloaderThread, 60)
    joinThreads(th)
    check reloadFails.load == 0
    # Every reload rebuilt the ctx from the same files, so the surviving ctx
    # still serves that certificate, and freeing the config (with whatever the
    # retire bookkeeping left behind) must not fault either.
    check "race.vortex" in ctxCertSubject(raceCfg)
    freeTlsConfig(raceCfg)

removeDir(rdir)
echo "tls reload race ok"
