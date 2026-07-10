switch("path", "$projectDir/../src")
switch("mm", "orc")
switch("threads", "on")
# std/httpclient needs -d:ssl to speak HTTPS in the TLS tests.
switch("define", "ssl")
