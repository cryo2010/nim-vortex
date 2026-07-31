switch("path", "$projectDir/../src")
# orc by default; CI's memory-manager matrix overrides via NIM_MM (e.g. arc).
switch("mm", getEnv("NIM_MM", "orc"))
switch("threads", "on")
# std/httpclient needs -d:ssl to speak HTTPS in the TLS tests.
switch("define", "ssl")

# Optional compression build (NIM_COMPRESS=1): enable gzip/brotli/zstd so the
# compression tests run in the default suite (and under the sanitizer) instead
# of skipping. Each module adds its own `passL` for the system lib, so only the
# defines are needed here. CI's test/sanitize jobs set it (and install the
# libs + CLIs); a plain local `nimble test` stays lean and those tests skip.
if getEnv("NIM_COMPRESS").len > 0:
  switch("define", "httpGzip")
  switch("define", "httpBrotli")
  switch("define", "httpZstd")

# Optional Address/UndefinedBehavior sanitizer run (NIM_SANITIZE=1): route
# allocations through malloc so ASan can see the heap, then instrument. Extends
# the fuzzer's ASan coverage from the parser targets to the whole server.
if getEnv("NIM_SANITIZE").len > 0:
  switch("define", "useMalloc")
  switch("passC", "-fsanitize=address,undefined -fno-omit-frame-pointer")
  switch("passL", "-fsanitize=address,undefined")
