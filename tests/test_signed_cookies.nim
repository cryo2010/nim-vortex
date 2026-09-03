## Signed (tamper-proof) cookies: setSignedCookie writes an HMAC signed value
## (HMAC-SHA256 by default; SHA-1/SHA-512 selectable). The HMAC runs through
## OpenSSL in the default build and nimcrypto under -d:plainHttp; both produce
## identical tags, so a signed cookie round-trips across build modes.
## req.cookies.signed(name, secret, algo) returns the value only if the
## signature verifies under that algo. Tampering, a wrong secret, or a
## mismatched algo yield none.

import std/[unittest, net, options, strutils, tables]
import std/httpclient except Response
import vortex/[settings, request, server, routing]

const secret = "s3cret-key"

proc pick(a: string): CookieMac =
  case a
  of "512": macSha512
  of "1": macSha1
  else: macSha256

proc hSet(req: Request, res: Response) {.gcsafe.} =
  let algo = pick(req.query.getOrDefault("algo"))
  let (k, v) = setSignedCookie("sid", "user-42", secret, algo, secure = false)
  res.send(Http200, "ok", @[(k, v)])

proc hRead(req: Request, res: Response) {.gcsafe.} =
  let algo = pick(req.query.getOrDefault("algo"))
  let s = req.cookies.signed("sid", secret, algo)
  res.send(Http200, if s.isSome: "val=" & s.get else: "invalid")

var rt = newRouter()
rt.get("/set", hSet)
rt.get("/read", hRead)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

proc setCookiePair(algo = ""): string =
  ## Fetch a Set-Cookie from /set and return the `sid=value.sig` pair.
  var c = newHttpClient(); defer: c.close()
  let q = if algo.len > 0: "?algo=" & algo else: ""
  ($c.get(base & "/set" & q).headers["set-cookie"]).split(';')[0]

proc readWith(cookie: string, algo = ""): string =
  var c = newHttpClient(); defer: c.close()
  c.headers = newHttpHeaders({"Cookie": cookie})
  let q = if algo.len > 0: "?algo=" & algo else: ""
  c.getContent(base & "/read" & q)

suite "signed cookies (HMAC)":
  test "default HMAC-SHA256 round-trips":
    check readWith(setCookiePair()) == "val=user-42"

  test "HMAC-SHA512 round-trips":
    check readWith(setCookiePair("512"), "512") == "val=user-42"

  test "HMAC-SHA1 still round-trips (interop)":
    check readWith(setCookiePair("1"), "1") == "val=user-42"

  test "a tampered value fails verification":
    check readWith("sid=user-99.AAAAAAAAAAAAAAAAAAAAAAAAAAA") == "invalid"

  test "flipping the value while keeping the signature fails":
    let pair = setCookiePair()                 # sid=user-42.<sig>
    let sig = pair.rsplit('.', 1)[1]
    check readWith("sid=user-43." & sig) == "invalid"

  test "an unsigned cookie is not accepted as signed":
    check readWith("sid=user-42") == "invalid"

  test "verifying with the wrong algorithm fails":
    check readWith(setCookiePair(), "512") == "invalid"   # signed 256, read 512

srv.close()
echo "signed cookies ok"
