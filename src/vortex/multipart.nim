## multipart/form-data parsing (RFC 7578) for request bodies: text fields and
## file uploads. Pure and buffered -- it works on a whole body string, so it is
## unit-testable and suits forms / modest uploads (bounded by maxBodySize). For
## large uploads, stream with req.onBody / req.read and parse incrementally.

import std/[strutils, options]

type
  MultipartFile* = object
    name*: string          ## the form field name
    filename*: string      ## the client-supplied filename
    contentType*: string   ## the part's Content-Type
    content*: string       ## the raw file bytes

  MultipartForm* = object
    fields*: seq[(string, string)]   ## text parts (name, value), in order
    files*: seq[MultipartFile]       ## file parts (a filename was present)

proc multipartBoundary*(contentType: string): string =
  ## The `boundary` parameter of a multipart Content-Type (quotes stripped);
  ## "" if absent.
  for part in contentType.split(';'):
    let p = part.strip
    if p.toLowerAscii.startsWith("boundary="):
      result = p[9 .. ^1].strip
      if result.len >= 2 and result[0] == '"' and result[^1] == '"':
        result = result[1 ..< result.len-1]
      return

proc dispositionParams(hv: string): seq[(string, string)] =
  ## Split `form-data; name="a"; filename="b"` into (key, value) pairs (keys
  ## lowercased, surrounding quotes stripped). A ';' inside a quoted value is not
  ## handled (rare in practice); such a field name/filename would split early.
  for part in hv.split(';'):
    let eq = part.find('=')
    if eq < 0: continue
    let k = part[0 ..< eq].strip.toLowerAscii
    var v = part[eq+1 .. ^1].strip
    if v.len >= 2 and v[0] == '"' and v[^1] == '"': v = v[1 ..< v.len-1]
    result.add (k, v)

proc parsePart(form: var MultipartForm, part: string) =
  let sep = part.find("\r\n\r\n")
  if sep < 0: return                          # no header/body separator
  let content = part[sep+4 .. ^1]
  var name, filename, ctype: string
  var hasFilename = false
  for line in part[0 ..< sep].split("\r\n"):
    let c = line.find(':')
    if c < 0: continue
    let hn = line[0 ..< c].strip.toLowerAscii
    let hv = line[c+1 .. ^1].strip
    if hn == "content-disposition":
      for (k, v) in dispositionParams(hv):
        if k == "name": name = v
        elif k == "filename": (filename = v; hasFilename = true)
    elif hn == "content-type":
      ctype = hv
  if name.len == 0 and not hasFilename: return   # not a form-data part
  if hasFilename:
    form.files.add MultipartFile(name: name, filename: filename,
      contentType: (if ctype.len > 0: ctype else: "application/octet-stream"),
      content: content)
  else:
    form.fields.add (name, content)

proc parseMultipart*(body, boundary: string): MultipartForm =
  ## Parse a multipart/form-data `body` given its `boundary` into fields + files.
  ## Lenient: a missing preamble/epilogue or LF-only line endings are tolerated;
  ## a part without a form-data Content-Disposition name is skipped.
  if boundary.len == 0 or body.len == 0: return
  let delim = "--" & boundary
  var idx = body.find(delim)
  if idx < 0: return
  idx += delim.len
  while idx <= body.len:
    if idx + 1 < body.len and body[idx] == '-' and body[idx+1] == '-':
      break                                    # closing delimiter "--boundary--"
    if idx + 1 <= body.len and idx + 1 < body.len and
        body[idx] == '\r' and body[idx+1] == '\n':
      idx += 2
    elif idx < body.len and body[idx] == '\n':
      idx += 1
    let nextRaw = body.find("\r\n" & delim, idx)
    var partEnd, afterDelim: int
    if nextRaw >= 0:
      partEnd = nextRaw
      afterDelim = nextRaw + 2 + delim.len
    else:
      let nb = body.find(delim, idx)
      if nb < 0: break
      partEnd = nb
      afterDelim = nb + delim.len
    if partEnd > idx:
      result.parsePart(body[idx ..< partEnd])
    idx = afterDelim

proc field*(form: MultipartForm, name: string): string =
  ## First text field value for `name`, or "" if none.
  for (n, v) in form.fields:
    if n == name: return v

proc file*(form: MultipartForm, name: string): Option[MultipartFile] =
  ## First file part for field `name`, or none.
  for f in form.files:
    if f.name == name: return some(f)
