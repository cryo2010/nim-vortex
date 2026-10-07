# Per-suite build knob, layered on tests/config.nims (which still applies: Nim
# reads the directory's config.nims and then this file-specific script).
#
# Compile the shim's test-only frame-log hook, so `ngPingsSent()` reports the
# ACK-less QUIC PING frames the server transmits (and `ngPingsSentWithAck()`
# the rest), and this suite can pin the keep-alive arming itself rather than
# only the transport parameter it is derived from (#347). Nothing outside this
# suite builds with it: a normal build installs no ngtcp2 log callback at all.
switch("define", "vortexH3FrameLog")
