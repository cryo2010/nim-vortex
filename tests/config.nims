switch("path", "$projectDir/../src")
# orc by default; CI's memory-manager matrix overrides via NIM_MM (e.g. arc).
switch("mm", getEnv("NIM_MM", "orc"))
switch("threads", "on")
# std/httpclient needs -d:ssl to speak HTTPS in the TLS tests.
switch("define", "ssl")

# Optional Address/UndefinedBehavior sanitizer run (NIM_SANITIZE=1): route
# allocations through malloc so ASan can see the heap, then instrument. Extends
# the fuzzer's ASan coverage from the parser targets to the whole server.
if getEnv("NIM_SANITIZE").len > 0:
  switch("define", "useMalloc")
  switch("passC", "-fsanitize=address,undefined -fno-omit-frame-pointer")
  switch("passL", "-fsanitize=address,undefined")
