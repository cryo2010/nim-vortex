## multipart/form-data: the pure parser (RFC 7578) and req.multipart end to end
## with a real curl -F upload (text field + file part).

import std/[unittest, net, strutils, os, osproc, options, httpcore]
import vortex/[settings, request, server, routing]
import vortex/multipart

suite "multipart parser (pure)":
  const bnd = "X-BOUNDARY"
  const body =
    "preamble to ignore\r\n" &
    "--X-BOUNDARY\r\n" &
    "Content-Disposition: form-data; name=\"title\"\r\n\r\n" &
    "Hello World\r\n" &
    "--X-BOUNDARY\r\n" &
    "Content-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\n" &
    "Content-Type: text/plain\r\n\r\n" &
    "file\r\ncontents\r\n" &                    # body may contain CRLF
    "--X-BOUNDARY--\r\n"

  test "boundary extraction (bare + quoted)":
    check multipartBoundary("multipart/form-data; boundary=X-BOUNDARY") == "X-BOUNDARY"
    check multipartBoundary("multipart/form-data; boundary=\"a b\"") == "a b"
    check multipartBoundary("application/json") == ""

  test "fields and files are separated with the right metadata":
    let f = parseMultipart(body, bnd)
    check f.fields.len == 1
    check f.field("title") == "Hello World"
    check f.files.len == 1
    let doc = f.file("doc")
    check doc.isSome
    check doc.get.filename == "a.txt"
    check doc.get.contentType == "text/plain"
    check doc.get.content == "file\r\ncontents"    # interior CRLF preserved
    check f.file("missing").isNone

  test "empty body / wrong boundary yields nothing":
    check parseMultipart("", bnd).files.len == 0
    check parseMultipart(body, "OTHER").fields.len == 0

proc handleUpload(req: Request, res: Response) {.gcsafe.} =
  let m = req.multipart
  let doc = m.file("doc")
  res.send(Http200, m.field("title") & "|" &
    (if doc.isSome: doc.get.filename & ":" & doc.get.contentType & ":" &
                    doc.get.content
     else: "nofile"))

let rt = newRouter()
rt.post("/upload", handleUpload)
var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

suite "req.multipart end to end (curl -F)":
  let curlBin = findExe("curl")
  let tmp = getTempDir() / ("vortex_mp_" & $getCurrentProcessId() & ".txt")
  writeFile(tmp, "the file body")

  test "text field + file upload reach the handler":
    if curlBin.len == 0: skip()
    else:
      let (output, rc) = execCmdEx(curlBin & " -s " &
        "-F title=Greetings " &
        "-F \"doc=@" & tmp & ";type=text/plain\" " & base & "/upload")
      check rc == 0
      check output.strip == "Greetings|" & tmp.extractFilename &
                            ":text/plain:the file body"

  removeFile(tmp)

srv.close()
echo "multipart ok"
