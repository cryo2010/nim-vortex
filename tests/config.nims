switch("path", "$projectDir/../src")
# orc by default; CI's memory-manager matrix overrides via NIM_MM (e.g. arc).
switch("mm", getEnv("NIM_MM", "orc"))
switch("threads", "on")
# std/httpclient needs -d:ssl to speak HTTPS in the TLS tests.
switch("define", "ssl")
