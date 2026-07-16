## WebSocket idle keepalive for h2/h3 streams: the per-stream sweep logic
## (ping after the idle interval, close after the pong timeout) and the
## registration rule (h2/h3 tracked, h1 not -- it uses the connection deadline
## wheel). The framing itself is covered by the h2/h3 WebSocket suites; this
## drives the sweep directly since a live idle-ping round trip needs a
## frame-inspecting multiplexed client.

import std/unittest
import vortex/connection
import vortex/websocket/codec

var flushLog {.threadvar.}: string
proc testFlush(core: ptr LoopCore, c: ptr Connection, w: WsConn)
              {.nimcall, gcsafe.} =
  flushLog.add w.outBuf
  w.outBuf.setLen 0

proc mkWs(now: int64): WsConn =
  WsConn(fd: -1, flush: testFlush, lastRx: now)   # fd < 0 => h3-like (c may be nil)

suite "WebSocket idle sweep (h2/h3)":
  test "pings after the idle interval, then times out with no reply":
    var core = LoopCore(wsPingInterval: 5, wsPongTimeout: 3, nowSec: 100)
    let w = mkWs(100)
    flushLog = ""
    core.nowSec = 104                        # idle 4s < 5: no ping
    check not wsSweepIdle(addr core, nil, w)
    check flushLog.len == 0
    core.nowSec = 105                        # idle 5s: ping
    check not wsSweepIdle(addr core, nil, w)
    check w.pingSent
    check flushLog.len == 2                  # a bare ping frame
    check (flushLog[0].ord and 0x0f) == 0x9  # opcode Ping
    core.nowSec = 107                        # 2s since ping < 3: still alive
    check not wsSweepIdle(addr core, nil, w)
    core.nowSec = 108                        # 3s since ping: peer gone
    check wsSweepIdle(addr core, nil, w)     # true => stop tracking
    check w.closeNotified

  test "a frame before the pong deadline keeps it alive":
    var core = LoopCore(wsPingInterval: 5, wsPongTimeout: 3, nowSec: 100)
    let w = mkWs(100)
    flushLog = ""
    core.nowSec = 105
    discard wsSweepIdle(addr core, nil, w)   # ping
    check w.pingSent
    w.lastRx = 106                           # inbound frame resets activity
    w.pingSent = false                       #   (as wsFeed does)
    core.nowSec = 110                        # past the old pong deadline
    check not wsSweepIdle(addr core, nil, w) # not timed out
    check not w.closeNotified
    core.nowSec = 111                        # a full interval since 106: re-ping
    check not wsSweepIdle(addr core, nil, w)
    check w.pingSent

  test "already-closed ws is reaped":
    var core = LoopCore(wsPingInterval: 5, wsPongTimeout: 3, nowSec: 100)
    let w = mkWs(100)
    w.closeNotified = true
    check wsSweepIdle(addr core, nil, w)     # true => drop from tracking

  test "disabled when wsPingInterval is 0":
    var core = LoopCore(wsPingInterval: 0, wsPongTimeout: 3, nowSec: 100)
    let w = mkWs(0)
    core.nowSec = 10_000
    check not wsSweepIdle(addr core, nil, w)
    check not w.pingSent

suite "WebSocket idle registration":
  test "wsSetup tracks h2/h3 streams but not h1":
    var core = LoopCore(nowSec: 5)
    discard wsSetup(addr core, 3, 0, 1024, 0, "", "", [])   # h1: fd>=0, stream 0
    check core.wsIdle.len == 0
    discard wsSetup(addr core, 3, 0, 1024, 7, "", "", [])   # h2: stream != 0
    check core.wsIdle.len == 1
    discard wsSetup(addr core, -2, 0, 1024, 0, "", "", [])  # h3: fd < 0
    check core.wsIdle.len == 2

echo "ws idle ok"
