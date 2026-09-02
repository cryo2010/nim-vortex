## Consolidated bench report. Reads the per-cell RESULT files written by run.sh
## ($1 = results dir) and prints ONE table per workload:
##
##   workload=requests (unit req/s)
##     framework    proto  req/s     p50ms  p90ms  p99ms  err%  RSS
##     nim/vortex   h1     512300    0.42   0.80   2.10   0.00  28MB
##     go/net-http  h3     n/a
##
## The RESULT files carry the short framework id (vortex|go|rust) as the stable
## machine key (image tags, server dirs, filenames); the table displays it as
## `<language>/<package>` so every row compares like with like.
import std/[os, strutils, tables, algorithm]

if paramCount() < 1: quit("usage: report <results-dir>", 1)
let dir = paramStr(1)

type Cell = object
  fw, proto, workload, unit, status: string
  thru, p50, p90, p99, maxms, errpct: float
  rss: int

proc parseLine(s: string): Cell =
  var kv = initTable[string, string]()
  for tok in s.splitWhitespace():
    let i = tok.find('=')
    if i > 0: kv[tok[0 ..< i]] = tok[i + 1 .. ^1]
  proc f(k: string): float = (try: parseFloat(kv.getOrDefault(k, "0")) except: 0.0)
  result.fw = kv.getOrDefault("framework", "?")
  result.proto = kv.getOrDefault("proto", "?")
  result.workload = kv.getOrDefault("workload", "?")
  result.unit = kv.getOrDefault("unit", "-")
  result.status = kv.getOrDefault("status", "ok")
  result.thru = f("throughput"); result.p50 = f("p50_ms"); result.p90 = f("p90_ms")
  result.p99 = f("p99_ms"); result.maxms = f("max_ms")
  result.rss = (try: parseInt(kv.getOrDefault("rss_bytes", "0")) except: 0)
  let ops = f("ops"); let err = f("err"); let non2xx = f("non2xx")
  result.errpct = if ops + err > 0: (err + non2xx) / (ops + err) * 100.0 else: 0.0

var cells: seq[Cell]
for f in walkFiles(dir / "*.line"):
  let s = readFile(f).strip()
  if s.len > 0: cells.add parseLine(s)

const fwOrder = ["vortex", "go", "rust"]
const protoOrder = ["h1", "h2", "h3"]
proc rank(c: Cell): int =
  var fi = fwOrder.find(c.fw); if fi < 0: fi = 9
  var pi = protoOrder.find(c.proto); if pi < 0: pi = 9
  fi * 10 + pi

const fwW = 13   # widest label (`go/net-http`) + padding
proc label(fw: string): string =
  ## Short framework id -> `<language>/<package>` display label, so the table
  ## compares stacks consistently instead of mixing package and language names.
  case fw
  of "vortex": "nim/vortex"
  of "go": "go/net-http"       # Go stdlib net/http (+ quic-go for h3)
  of "rust": "rust/salvo"
  else: fw

proc pad(s: string, w: int): string = s & " ".repeat(max(0, w - s.len))
proc num(x: float, d: int): string = formatFloat(x, ffDecimal, d)

var byWorkload = initOrderedTable[string, seq[Cell]]()
for c in cells: byWorkload.mgetOrPut(c.workload, @[]).add c

echo ""
echo "================= cross-language bench ================="
for wl, cs0 in byWorkload:
  var cs = cs0
  cs.sort(proc(a, b: Cell): int = cmp(rank(a), rank(b)))
  let unit = (if cs.len > 0 and cs[0].unit != "-": cs[0].unit else: "op/s")
  echo ""
  echo "workload=", wl, "  (", unit, ")"
  echo "  ", pad("framework", fwW), pad("proto", 6), pad(unit, 12),
       pad("p50ms", 9), pad("p90ms", 9), pad("p99ms", 9), pad("err%", 7), "RSS"
  for c in cs:
    if c.status in ["skip", "nomeasure"]:
      echo "  ", pad(label(c.fw), fwW), pad(c.proto, 6),
           pad((if c.status == "skip": "n/a" else: "FAIL"), 12)
    else:
      echo "  ", pad(label(c.fw), fwW), pad(c.proto, 6), pad(num(c.thru, 0), 12),
           pad(num(c.p50, 2), 9), pad(num(c.p90, 2), 9), pad(num(c.p99, 2), 9),
           pad(num(c.errpct, 2), 7), $(c.rss div (1024 * 1024)) & "MB"
echo ""
