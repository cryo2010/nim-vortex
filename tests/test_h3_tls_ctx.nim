## White-box tests for the QUIC TLS context the ngtcp2 shim builds.
##
## These cover invariants no HTTP/3 client can observe: how many times the
## ngtcp2 ossl backend was initialized (#357), and how long the certificate
## chain a repeated load installs ends up being (#354). The harness
## tests/vq_h3_tls_ctx.cpp compiles the shim's own translation unit to reach its
## internals, so this suite must NOT import the vortex h3 backend -- the shim's
## extern "C" ABI is linked exactly once here.

import std/[unittest, os, osproc]

when not defined(plainHttp):
  {.passC: "-I" & currentSourcePath().parentDir.parentDir /
           "src/vortex/http3/ngtcp2".}
  {.passL: "-lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -lssl -lcrypto -lstdc++".}
  {.compile: "vq_h3_tls_ctx.cpp".}

  proc vqTestOsslInitRuns(): cint {.importc: "vq_test_ossl_init_runs", cdecl.}
  proc vqTestOsslInitOk(): cint {.importc: "vq_test_ossl_init_ok", cdecl.}
  proc vqTestChainLenAfterLoads(pem: cstring, times: cint): cint
    {.importc: "vq_test_chain_len_after_loads", cdecl.}
  proc vqTestP12ChainLenAfterLoads(der: ptr uint8, len: csize_t, pw: cstring,
                                   times: cint): cint
    {.importc: "vq_test_p12_chain_len_after_loads", cdecl.}

  suite "ngtcp2 ossl backend initialization (#357)":
    test "the backend initializes successfully":
      check vqTestOsslInitOk() == 1

    test "concurrent engine creation initializes the backend exactly once":
      # ngtcp2_crypto_ossl_init allocates an OpenSSL ex_data index into a
      # library global and is not thread safe, but vq_engine_new runs on every
      # loop thread. Calling it per engine leaked an index per extra loop and
      # left a window where a session configured under one index was read back
      # under another: a null crypto context and a failed handshake, only at
      # startup and only under a thread race. There is no way to provoke that
      # race from a client, so the invariant itself is what is pinned here.
      check vqTestOsslInitRuns() == 1

  # A two-level chain (ChainCA -> leaf) and the same material as a PKCS#12
  # bundle carrying the CA, so both loaders have one chain certificate to add.
  let dir = getTempDir() / "vortex_h3tlsctx_" & $getCurrentProcessId()
  removeDir(dir); createDir(dir)

  proc must(cmd: string) =
    let (o, rc) = execCmdEx(cmd)
    doAssert rc == 0, cmd & "\n" & o

  let openssl = findExe("openssl")
  if openssl.len == 0:
    echo "SKIP: need openssl for the chain fixtures"
    quit 0
  must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
       "/ca.key -out " & dir & "/ca.pem -days 2 -subj /CN=ChainCA")
  must("openssl req -newkey rsa:2048 -nodes -keyout " & dir &
       "/leaf.key -out " & dir & "/leaf.csr -subj /CN=localhost")
  must("openssl x509 -req -in " & dir & "/leaf.csr -CA " & dir &
       "/ca.pem -CAkey " & dir & "/ca.key -CAcreateserial -out " & dir &
       "/leaf.pem -days 2")
  must("openssl pkcs12 -export -out " & dir & "/bundle.p12 -inkey " & dir &
       "/leaf.key -in " & dir & "/leaf.pem -certfile " & dir &
       "/ca.pem -passout pass:")
  let chainPem = readFile(dir / "leaf.pem") & readFile(dir / "ca.pem")
  var p12 = readFile(dir / "bundle.p12")

  suite "QUIC certificate chain across reloads (#354)":
    test "one load of leaf + intermediate sends one chain certificate":
      check vqTestChainLenAfterLoads(chainPem.cstring, 1) == 1

    test "loading the same chain again does not stack the intermediates":
      # SSL_CTX_use_certificate leaves the chain alone, so appending the new
      # intermediates without clearing first grew what h3 clients receive on
      # every reload: after a CA rotation they got the new leaf plus the old,
      # no-longer-valid intermediates.
      check vqTestChainLenAfterLoads(chainPem.cstring, 2) == 1
      check vqTestChainLenAfterLoads(chainPem.cstring, 5) == 1

    test "a PKCS#12 bundle's CA certificates do not stack either":
      let der = cast[ptr uint8](addr p12[0])
      check vqTestP12ChainLenAfterLoads(der, csize_t(p12.len), "".cstring, 1) == 1
      check vqTestP12ChainLenAfterLoads(der, csize_t(p12.len), "".cstring, 4) == 1

  removeDir(dir)
