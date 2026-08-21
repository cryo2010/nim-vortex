## Signed (tamper-proof) cookies: setSignedCookie writes an HMAC-SHA1 signed
## value; req.cookies.signed(name, secret) returns it only if the signature
## verifies. A tampered value or wrong secret yields none.

import std/[unittest, net, options, strutils]
import std/httpclient except Response
import vortex/[settings, request, server, routing]

const secret = "s3cret-key"

proc hSet(req: Request, res: Response) {.gcsafe.} =
  let (k, v) = setSignedCookie("sid", "user-42", secret, secure = false)
  res.send(Http200, "ok", @[(k, v)])

proc hRead(req: Request, res: Response) {.gcsafe.} =
  let s = req.cookies.signed("sid", secret)
  res.send(Http200, if s.isSome: "val=" & s.get else: "invalid")

var rt = newRouter()
rt.get("/set", hSet)
rt.get("/read", hRead)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

proc readWithCookie(cookie: string): string =
  var c = newHttpClient(); defer: c.close()
  c.headers = newHttpHeaders({"Cookie": cookie})
  c.getContent(base & "/read")

suite "signed cookies":
  test "round-trip: a signed cookie verifies and returns its value":
    var c = newHttpClient(); defer: c.close()
    let setHdr = $c.get(base & "/set").headers["set-cookie"]
    check "sid=user-42." in setHdr           # value.signature form
    # extract the sid=... pair and replay it as a Cookie header
    let pair = setHdr.split(';')[0]
    check readWithCookie(pair) == "val=user-42"

  test "a tampered value fails verification":
    # keep a plausible-looking value but a bogus signature
    check readWithCookie("sid=user-99.AAAAAAAAAAAAAAAAAAAAAAAAAAA") == "invalid"

  test "flipping the value while keeping the original signature fails":
    var c = newHttpClient(); defer: c.close()
    let setHdr = $c.get(base & "/set").headers["set-cookie"]
    let pair = setHdr.split(';')[0]           # sid=user-42.<sig>
    let sig = pair.rsplit('.', 1)[1]
    check readWithCookie("sid=user-43." & sig) == "invalid"

  test "an unsigned cookie is not accepted as signed":
    check readWithCookie("sid=user-42") == "invalid"

srv.close()
echo "signed cookies ok"
