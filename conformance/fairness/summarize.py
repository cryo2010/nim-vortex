#!/usr/bin/env python3
# Summarize an h2load --output-file JSON into a one-line fairness/throughput
# record. The fairness signal is the spread of per-request completion times
# across the concurrently multiplexed streams: a fair (round-robin) write
# scheduler finishes equal-size streams close together (low p99/max/sd, max/min
# near 1), while draining one stream fully at a time staggers them (high spread).
import json, sys

label = sys.argv[2] if len(sys.argv) > 2 else ""
d = json.load(open(sys.argv[1]))
m = d["measurements"]
r = m["performance"]["request"]          # seconds
reqs = m["requests"]
ms = lambda s: s * 1000.0

mn, mx = r["min"], r["max"]
spread = (mx / mn) if mn > 0 else float("nan")
print(
    f"{label:<22} "
    f"reqs={reqs['succeeded']}/{reqs['total']} fail={reqs['failed']+reqs['errored']+reqs['timeout']} "
    f"| {m['request_per_second']:.0f} req/s {m['bytes_per_second']/1e9:.2f} GB/s "
    f"| req-time ms: p50={ms(r['median']):.1f} p95={ms(r['p95']):.1f} "
    f"p99={ms(r['p99']):.1f} max={ms(mx):.1f} sd={ms(r['sd']):.2f} "
    f"| spread(max/min)={spread:.1f}x"
)
