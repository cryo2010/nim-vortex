# Per-suite build knob, layered on tests/config.nims (which still applies: Nim
# reads the directory's config.nims and then this file-specific script).
#
# Shrink the connection table's block size so the growth-under-a-pinned-slot
# path (#343) is reachable with a couple of dozen connections instead of needing
# an fd rlimit above 1024. Nothing else in the suite depends on the value.
switch("define", "vortexConnBlock=8")
