## White-box tests for the QUIC TLS context the ngtcp2 shim builds.
##
## These cover invariants no HTTP/3 client can observe: how many times the
## ngtcp2 ossl backend was initialized (#357), how long the certificate chain a
## repeated load installs ends up being (#354), and what a refused certificate
## reload leaves the engine serving (#352 -- a reload that fails only on the
## QUIC side is one server.reloadTls rejects before it ever signals the loops,
## so there is no way in from Nim). The harness
## tests/vq_h3_tls_ctx.cpp compiles the shim's own translation unit to reach its
## internals, so this suite must NOT import the vortex h3 backend -- the shim's
## extern "C" ABI is linked exactly once here.

import std/[unittest, os, osproc, strutils]

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
  proc vqTestEngineNew(certPem, keyPem, host, hostCertFile,
                       hostKeyFile: cstring): pointer
    {.importc: "vq_test_engine_new", cdecl.}
  proc vqTestEngineUsable(e: pointer): cint
    {.importc: "vq_test_engine_usable", cdecl.}
  proc vqTestEngineSubject(e: pointer, buf: cstring, len: csize_t)
    {.importc: "vq_test_engine_subject", cdecl.}
  proc vqTestEngineHostSubject(e: pointer, buf: cstring, len: csize_t)
    {.importc: "vq_test_engine_host_subject", cdecl.}
  # The real reload ABI, driven directly.
  proc vqEngineReloadCert(e: pointer, certPem, keyPem: cstring): cint
    {.importc: "vq_engine_reload_cert", cdecl.}
  proc vqEngineLastError(e: pointer): cstring
    {.importc: "vq_engine_last_error", cdecl.}
  proc vqEngineFree(e: pointer) {.importc: "vq_engine_free", cdecl.}

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

  # A second, unrelated pair for the reload cases, plus a third key that parses
  # cleanly but belongs to neither certificate.
  must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
       "/beta.key -out " & dir & "/beta.pem -days 2 -subj /CN=beta.vortex")
  must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
       "/stray.key -out " & dir & "/stray.pem -days 2 -subj /CN=stray.vortex")
  must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
       "/api.key -out " & dir & "/api.pem -days 2 -subj /CN=api.example.com")
  let startCert = readFile(dir / "leaf.pem")      # CN=localhost
  let startKey = readFile(dir / "leaf.key")
  let newCert = readFile(dir / "beta.pem")        # CN=beta.vortex
  let newKey = readFile(dir / "beta.key")
  let strayKey = readFile(dir / "stray.key")      # parses, matches neither

  proc subject(e: pointer): string =
    var buf = newString(512)
    vqTestEngineSubject(e, buf.cstring, csize_t(buf.len))
    $cast[cstring](addr buf[0])

  proc hostSubject(e: pointer): string =
    var buf = newString(512)
    vqTestEngineHostSubject(e, buf.cstring, csize_t(buf.len))
    $cast[cstring](addr buf[0])

  proc reload(e: pointer, cert, key: string): bool =
    vqEngineReloadCert(e, cert.cstring, key.cstring) == 0

  suite "QUIC certificate reload is all or nothing (#352)":
    ## The reload used to write into the live SSL_CTX, certificate first then
    ## key, with no validation. OpenSSL's ssl_set_cert frees the existing
    ## private key when the new leaf does not match it, and ssl_set_pkey frees
    ## the existing certificate when the new key does not match, so a bad
    ## reload left the engine holding one half of a pair and every h3 handshake
    ## on that loop failed, permanently, while the caller was told the old
    ## certificate was still serving.
    test "a key that does not match the certificate is refused":
      let e = vqTestEngineNew(startCert.cstring, startKey.cstring, "", "", "")
      check e != nil
      defer: vqEngineFree(e)
      check "localhost" in subject(e)
      check not reload(e, newCert, strayKey)
      # SSL_CTX_use_PrivateKey rejects the pair itself, so the reason OpenSSL
      # queued reaches the caller; makeCtx's own check_private_key is the
      # backstop for the halves that load but do not go together.
      check "mismatch" in $vqEngineLastError(e)
      check vqTestEngineUsable(e) == 1      # pre-fix: 0, h3 dead for good
      check "localhost" in subject(e)       # pre-fix: the new leaf, keyless

    test "a key that does not parse is refused":
      let e = vqTestEngineNew(startCert.cstring, startKey.cstring, "", "", "")
      check e != nil
      defer: vqEngineFree(e)
      check not reload(e, newCert, "-----BEGIN NOT A KEY-----\nzzzz\n")
      check "cannot load TLS certificate/key" in $vqEngineLastError(e)
      check vqTestEngineUsable(e) == 1
      check "localhost" in subject(e)

    test "a certificate with no key is refused":
      let e = vqTestEngineNew(startCert.cstring, startKey.cstring, "", "", "")
      check e != nil
      defer: vqEngineFree(e)
      check not reload(e, newCert, "")
      check vqTestEngineUsable(e) == 1
      check "localhost" in subject(e)

    test "a matching pair is installed and reported as a success":
      let e = vqTestEngineNew(startCert.cstring, startKey.cstring, "", "", "")
      check e != nil
      defer: vqEngineFree(e)
      check reload(e, newCert, newKey)
      check $vqEngineLastError(e) == ""
      check "beta.vortex" in subject(e)
      check vqTestEngineUsable(e) == 1

    test "a per-host context that will not rebuild fails the whole reload":
      # The per-host rebuild is part of the same transaction, so a per-host
      # certificate file that went bad between reloads must not leave the
      # default context half-swapped.
      let e = vqTestEngineNew(startCert.cstring, startKey.cstring,
                              "api.example.com".cstring,
                              (dir / "api.pem").cstring,
                              (dir / "api.key").cstring)
      check e != nil
      defer: vqEngineFree(e)
      check "api.example.com" in hostSubject(e)
      writeFile(dir / "api.pem", "-----BEGIN CERTIFICATE-----\nzzzz\n")
      check not reload(e, newCert, newKey)
      check "api.example.com" in $vqEngineLastError(e)
      check "localhost" in subject(e)            # default context untouched
      check "api.example.com" in hostSubject(e)  # and so is the per-host one
      check vqTestEngineUsable(e) == 1

  removeDir(dir)
