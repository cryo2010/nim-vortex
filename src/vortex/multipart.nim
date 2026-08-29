## multipart/form-data parsing (RFC 7578) plus the shared shape behind req.form /
## req.files. Pure and buffered (works on a whole body string), so it is
## unit-testable and suits forms / modest uploads; large uploads should stream
## via req.onBody / req.read and parse incrementally.
##
## req.form and req.files mirror req.headers: `[]` looks a key up, `in` tests
## presence, and you can iterate. A missing form field is "" (like a header); a
## missing file raises KeyError (there is no empty file), so check
## `"x" in req.files` first or handle the exception.

import std/strutils

type
  UploadedFile* = object
    name*: string          ## the form field name (the <input name>)
    filename*: string      ## the client-supplied filename
    contentType*: string   ## the part's Content-Type
    content*: string       ## the raw file bytes

  MultipartForm* = object  ## raw parse result behind req.form / req.files
    fields*: seq[(string, string)]
    files*: seq[UploadedFile]

  FormFields* = object
    ## Submitted form fields (application/x-www-form-urlencoded, or the text
    ## parts of multipart/form-data). Same shape as req.headers:
    ## `req.form["name"]` is the first value ("" if absent), `"name" in req.form`
    ## tests presence, `for (k, v) in req.form` iterates all. Field names are
    ## case-sensitive (unlike headers).
    s*: seq[(string, string)]

  UploadedFiles* = object
    ## Uploaded files of a multipart/form-data body, keyed by the form field
    ## name (the <input name>, not the filename). `req.files["avatar"]` is the
    ## first file for that field and RAISES KeyError if absent (check
    ## `"avatar" in req.files` or catch); `for f in req.files` iterates all.
    s*: seq[UploadedFile]

# --- req.form / req.files accessors (req.headers-shaped) ---------------------

proc `[]`*(f: FormFields, name: string): string =
  ## First value for `name`, or "" if absent (like req.headers[name]).
  for (n, v) in f.s:
    if n == name: return v

proc contains*(f: FormFields, name: string): bool =
  for (n, _) in f.s:
    if n == name: return true

iterator items*(f: FormFields): (string, string) =
  for p in f.s: yield p

proc len*(f: FormFields): int {.inline.} = f.s.len

proc `[]`*(u: UploadedFiles, name: string): UploadedFile =
  ## First uploaded file for form field `name`. Raises KeyError if there is
  ## none -- test `name in req.files` first, or handle the exception.
  for f in u.s:
    if f.name == name: return f
  raise newException(KeyError, "no uploaded file for form field: " & name)

proc contains*(u: UploadedFiles, name: string): bool =
  for f in u.s:
    if f.name == name: return true

iterator items*(u: UploadedFiles): UploadedFile =
  for f in u.s: yield f

proc len*(u: UploadedFiles): int {.inline.} = u.s.len

# --- parsing ----------------------------------------------------------------

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
    form.files.add UploadedFile(name: name, filename: filename,
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
    if idx + 1 < body.len and body[idx] == '\r' and body[idx+1] == '\n':
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
