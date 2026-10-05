## OpenSSL error-queue hygiene in the TLS transport. Since #388 the accept path
## logs `TLS session setup failed: <tlsLastErrorMsg()>`, which made two
## pre-existing sloppinesses operator-visible:
##
## * `ERR_error_string(e, nil)` formats into OpenSSL's single process-wide
##   `static char buf[256]` (documented as not thread-safe), so two loop threads
##   formatting a reason at the same time could each report the other's.
## * `newTlsSession` never cleared the per-thread queue, and the handshake/read/
##   write wrappers leave their reason on it when a connection fails, so a
##   session-setup failure could be reported with the reason an *earlier*
##   connection on the same loop thread failed with.
##
## Both are white-box: the test pushes errors with known codes straight onto the
## queue (ERR_new + ERR_set_error, what OpenSSL's own ERR_raise macro expands
## to) so the message it expects back is exact.

import std/[unittest, os, atomics, strutils, nativesockets]
import vortex/transport/tls
import ./helper

const cryptoLibName =
  when defined(macosx):
    "(/opt/homebrew/opt/openssl@3/lib/|/usr/local/opt/openssl@3/lib/|)libcrypto.3.dylib"
  else:
    "libcrypto.so(.3|)"

{.push importc, cdecl, dynlib: cryptoLibName.}
proc ERR_new()
proc ERR_clear_error()
{.pop.}
proc ERR_set_error(lib: cint, reason: cint, fmt: cstring)
  {.importc, cdecl, varargs, dynlib: cryptoLibName.}

const
  ERR_LIB_SSL = cint(20)        # <openssl/err.h>
  reasonA = cint(100)
  reasonB = cint(200)
  reps = 200_000                # ~0.1 s for the pair; the race needs volume

proc errCode(reason: cint): string =
  ## The `error:XXXXXXXX:` code OpenSSL prints for a (lib, reason) pair.
  toHex(culong((ERR_LIB_SSL shl 23) or reason), 8)

proc raiseErr(reason: cint) =
  ERR_new()
  ERR_set_error(ERR_LIB_SSL, reason, nil)

var wrong: Atomic[int]

proc formatter(reason: cint) {.thread.} =
  ## Queue an error with this thread's own code and read it straight back, over
  ## and over. Every message must carry this thread's code: a message carrying
  ## the other thread's is the static-buffer race.
  {.cast(gcsafe).}:
    let want = errCode(reason)
    for _ in 0 ..< reps:
      raiseErr(reason)
      if want notin tlsLastErrorMsg(): wrong.atomicInc()

suite "TLS error formatting is thread-safe":
  test "two threads reading a reason at once each get their own":
    var th: array[2, Thread[cint]]
    createThread(th[0], formatter, reasonA)
    createThread(th[1], formatter, reasonB)
    joinThreads(th)
    check wrong.load == 0

suite "a new TLS session starts from an empty error queue":
  test "a leftover reason is not reported for the next connection":
    let (cert, key) = makeCertPair("vortex_tlserrq_", "errq.vortex")
    defer: removeDir(cert.parentDir)
    let cfg = newTlsConfig(cert, key)
    defer: freeTlsConfig(cfg)
    let fd = createNativeSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    check fd != osInvalidSocket
    defer: fd.close()
    # Stand in for a previous connection on this thread that failed its
    # handshake and left the reason queued.
    raiseErr(reasonA)
    let ssl = newTlsSession(cfg, cint(fd))
    check ssl != nil
    freeTlsSession(ssl)
    # The accept path asks for a reason only when setup failed, but it asks on
    # this thread: whatever it would read must not be the stale one.
    check tlsLastErrorMsg() == "unknown TLS error"
    ERR_clear_error()

echo "tls error queue ok"
