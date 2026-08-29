## multipart/form-data: the pure parser (RFC 7578) and the req.form / req.files
## accessors (req.headers-shaped) end to end with a real curl -F upload.

import std/[unittest, net, strutils, os, osproc, httpcore]
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
    let m = parseMultipart(body, bnd)
    check m.fields == @[("title", "Hello World")]
    check m.files.len == 1
    check m.files[0].name == "doc"
    check m.files[0].filename == "a.txt"
    check m.files[0].contentType == "text/plain"
    check m.files[0].content == "file\r\ncontents"   # interior CRLF preserved

  test "empty body / wrong boundary yields nothing":
    check parseMultipart("", bnd).files.len == 0
    check parseMultipart(body, "OTHER").fields.len == 0

suite "FormFields / UploadedFiles accessors (req.headers-shaped)":
  test "form: [] is first-or-empty, `in`, iterate":
    let f = FormFields(s: @[("a", "1"), ("a", "2"), ("b", "3")])
    check f["a"] == "1"                          # first wins
    check f["missing"] == ""                     # "" when absent (like headers)
    check "b" in f
    check "z" notin f
    check f.len == 3
    var seen: seq[string]
    for (k, v) in f: seen.add k & "=" & v
    check seen == @["a=1", "a=2", "b=3"]

  test "files: [] raises when absent, `in`, iterate":
    let u = UploadedFiles(s: @[UploadedFile(name: "doc", filename: "a.txt")])
    check "doc" in u
    check "nope" notin u
    check u["doc"].filename == "a.txt"
    expect KeyError: discard u["nope"]

proc handleUpload(req: Request, res: Response) {.gcsafe.} =
  let form = req.form
  let files = req.files
  let present = "doc" in files
  let doc = if present: files["doc"] else: UploadedFile()
  res.send(Http200, form["title"] & "|" & $present & "|" &
    doc.filename & ":" & doc.contentType & ":" & doc.content)

let rt = newRouter()
rt.post("/upload", handleUpload)
var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

suite "req.form / req.files end to end (curl -F)":
  let curlBin = findExe("curl")
  let tmp = getTempDir() / ("vortex_mp_" & $getCurrentProcessId() & ".txt")
  writeFile(tmp, "the file body")

  test "text field via req.form + file via req.files reach the handler":
    if curlBin.len == 0: skip()
    else:
      let (output, rc) = execCmdEx(curlBin & " -s " &
        "-F title=Greetings " &
        "-F \"doc=@" & tmp & ";type=text/plain\" " & base & "/upload")
      check rc == 0
      check output.strip == "Greetings|true|" & tmp.extractFilename &
                            ":text/plain:the file body"

  test "a missing file key is absent (checked with `in`, no exception)":
    if curlBin.len == 0: skip()
    else:
      let (output, rc) = execCmdEx(curlBin & " -s -F title=NoFile " & base & "/upload")
      check rc == 0
      check output.strip == "NoFile|false|::"     # empty UploadedFile() fields

  removeFile(tmp)

srv.close()
echo "multipart ok"
