## White-box tests for the QUIC TLS context the ngtcp2 shim builds.
##
## These cover invariants no HTTP/3 client can observe: how many times the
## ngtcp2 ossl backend was initialized (#357), how long the certificate chain a
## repeated load installs ends up being (#354), and what a certificate reload
## installs or refuses (#352, #353 -- a reload that fails only on the QUIC side
## is one server.reloadTls rejects before it ever signals the loops, so there is
## no way in from Nim). The harness tests/vq_h3_tls_ctx.cpp compiles the shim's
## own translation unit to reach its internals, so this suite must NOT import
## the vortex h3 backend -- the shim's extern "C" ABI is linked exactly once
## here.

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
  proc vqTestEngineNewC(certFile, keyFile, certPem, keyPem, pkcs12File,
                        keyPassword, host, hostCertFile,
                        hostKeyFile: cstring): pointer
    {.importc: "vq_test_engine_new", cdecl.}
  proc vqTestEngineUsable(e: pointer): cint
    {.importc: "vq_test_engine_usable", cdecl.}
  proc vqTestEngineSubject(e: pointer, buf: cstring, len: csize_t)
    {.importc: "vq_test_engine_subject", cdecl.}
  proc vqTestEngineHostSubject(e: pointer, buf: cstring, len: csize_t)
    {.importc: "vq_test_engine_host_subject", cdecl.}
  # The real reload ABI, driven directly.
  proc vqEngineReloadCert(e: pointer, certFile, keyFile: cstring): cint
    {.importc: "vq_engine_reload_cert", cdecl.}
  proc vqEngineLastError(e: pointer): cstring
    {.importc: "vq_engine_last_error", cdecl.}
  proc vqEngineFree(e: pointer) {.importc: "vq_engine_free", cdecl.}
  proc vqTestTicketKeyName(buf: cstring, len: csize_t)
    {.importc: "vq_test_ticket_key_name", cdecl.}
  proc vqTestEngineNoTicket(e: pointer): cint
    {.importc: "vq_test_engine_no_ticket", cdecl.}
  proc vqTestTicketKeyCycle(): cint
    {.importc: "vq_test_ticket_key_cycle", cdecl.}

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

  let dir = getTempDir() / "vortex_h3tlsctx_" & $getCurrentProcessId()
  removeDir(dir); createDir(dir)

  proc must(cmd: string) =
    let (o, rc) = execCmdEx(cmd)
    doAssert rc == 0, cmd & "\n" & o

  if findExe("openssl").len == 0:
    echo "SKIP: need openssl for the certificate fixtures"
    quit 0

  # A two-level chain (ChainCA -> leaf, CN=localhost) and the same material as a
  # PKCS#12 bundle carrying the CA, so both loaders have one chain certificate
  # to add.
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

  # A second pair for the reload cases, a third key that parses cleanly but
  # belongs to neither certificate, a per-host pair, and a key file that is not
  # a key at all.
  must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
       "/beta.key -out " & dir & "/beta.pem -days 2 -subj /CN=beta.vortex")
  must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
       "/stray.key -out " & dir & "/stray.pem -days 2 -subj /CN=stray.vortex")
  must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
       "/api.key -out " & dir & "/api.pem -days 2 -subj /CN=api.example.com")
  writeFile(dir / "junk.key", "-----BEGIN PRIVATE KEY-----\nzzzz\n")
  let startCert = readFile(dir / "leaf.pem")      # CN=localhost
  let startKey = readFile(dir / "leaf.key")
  let betaCert = dir / "beta.pem"                 # CN=beta.vortex
  let betaKey = dir / "beta.key"

  proc engineFromPem(cert, key: string, host = "", hostCert = "",
                     hostKey = ""): pointer =
    vqTestEngineNewC("".cstring, "".cstring, cert.cstring, key.cstring,
                     "".cstring, "".cstring, host.cstring, hostCert.cstring,
                     hostKey.cstring)

  proc engineFromFiles(cert, key: string): pointer =
    vqTestEngineNewC(cert.cstring, key.cstring, "".cstring, "".cstring,
                     "".cstring, "".cstring, "".cstring, "".cstring, "".cstring)

  proc engineFromP12(p12File: string): pointer =
    vqTestEngineNewC("".cstring, "".cstring, "".cstring, "".cstring,
                     p12File.cstring, "".cstring, "".cstring, "".cstring,
                     "".cstring)

  proc subject(e: pointer): string =
    var buf = newString(512)
    vqTestEngineSubject(e, buf.cstring, csize_t(buf.len))
    $cast[cstring](addr buf[0])

  proc hostSubject(e: pointer): string =
    var buf = newString(512)
    vqTestEngineHostSubject(e, buf.cstring, csize_t(buf.len))
    $cast[cstring](addr buf[0])

  proc reload(e: pointer, cert = "", key = ""): bool =
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
      let e = engineFromPem(startCert, startKey)
      check e != nil
      defer: vqEngineFree(e)
      check "localhost" in subject(e)
      check not reload(e, betaCert, dir / "stray.key")
      # SSL_CTX_use_PrivateKey rejects the pair itself, so the reason OpenSSL
      # queued reaches the caller; makeCtx's own check_private_key is the
      # backstop for the halves that load but do not go together.
      check "mismatch" in $vqEngineLastError(e)
      check vqTestEngineUsable(e) == 1      # pre-fix: 0, h3 dead for good
      check "localhost" in subject(e)       # pre-fix: the new leaf, keyless

    test "a key file that does not parse is refused":
      let e = engineFromPem(startCert, startKey)
      check e != nil
      defer: vqEngineFree(e)
      check not reload(e, betaCert, dir / "junk.key")
      check "cannot load TLS certificate/key" in $vqEngineLastError(e)
      check vqTestEngineUsable(e) == 1
      check "localhost" in subject(e)

    test "a key file that cannot be read is refused":
      let e = engineFromPem(startCert, startKey)
      check e != nil
      defer: vqEngineFree(e)
      check not reload(e, betaCert, dir / "no-such.key")
      check vqTestEngineUsable(e) == 1
      check "localhost" in subject(e)

    test "a certificate rotated without its key is refused":
      # An empty key means "keep the configured one", which cannot match the
      # new certificate. The pre-fix reload reported this as a success.
      let e = engineFromPem(startCert, startKey)
      check e != nil
      defer: vqEngineFree(e)
      check not reload(e, betaCert, "")
      check vqTestEngineUsable(e) == 1
      check "localhost" in subject(e)

    test "a matching pair is installed and reported as a success":
      let e = engineFromPem(startCert, startKey)
      check e != nil
      defer: vqEngineFree(e)
      check reload(e, betaCert, betaKey)
      check $vqEngineLastError(e) == ""
      check "beta.vortex" in subject(e)
      check vqTestEngineUsable(e) == 1

    test "a per-host context that will not rebuild fails the whole reload":
      # The per-host rebuild is part of the same transaction, so a per-host
      # certificate file that went bad between reloads must not leave the
      # default context half-swapped.
      let e = engineFromPem(startCert, startKey, "api.example.com",
                            dir / "api.pem", dir / "api.key")
      check e != nil
      defer: vqEngineFree(e)
      check "api.example.com" in hostSubject(e)
      writeFile(dir / "api.pem", "-----BEGIN CERTIFICATE-----\nzzzz\n")
      check not reload(e, betaCert, betaKey)
      check "api.example.com" in $vqEngineLastError(e)
      check "localhost" in subject(e)            # default context untouched
      check "api.example.com" in hostSubject(e)  # and so is the per-host one
      check vqTestEngineUsable(e) == 1
      must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
           "/api.key -out " & dir & "/api.pem -days 2 -subj /CN=api.example.com")

  suite "a bare QUIC reload re-reads the configured material (#353)":
    ## The engine keeps the material it was configured from, so a reload with no
    ## paths means the same thing on QUIC as on TCP. It used to mean nothing at
    ## all: the loop called readFile("") and the reload failed, so the certbot
    ## pattern the project documents rotated HTTP/1.1 and HTTP/2 and left h3 on
    ## the certificate loaded at startup.
    test "a file-configured engine picks up the files replaced on disk":
      let cert = dir / "rot.pem"
      let key = dir / "rot.key"
      must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & key &
           " -out " & cert & " -days 2 -subj /CN=before.vortex")
      let e = engineFromFiles(cert, key)
      check e != nil
      defer: vqEngineFree(e)
      check "before.vortex" in subject(e)
      must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & key &
           " -out " & cert & " -days 2 -subj /CN=after.vortex")
      check reload(e)                              # no paths: certbot's form
      check "after.vortex" in subject(e)

    test "explicit paths become what the next bare reload re-reads":
      let e = engineFromPem(startCert, startKey)
      check e != nil
      defer: vqEngineFree(e)
      let cert = dir / "roll.pem"
      let key = dir / "roll.key"
      must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & key &
           " -out " & cert & " -days 2 -subj /CN=roll-one.vortex")
      check reload(e, cert, key)
      check "roll-one.vortex" in subject(e)
      must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & key &
           " -out " & cert & " -days 2 -subj /CN=roll-two.vortex")
      check reload(e)
      check "roll-two.vortex" in subject(e)

    test "a PEM-configured engine keeps serving its bytes":
      # Nothing to re-read, so the rebuild is a no-op for the default
      # certificate. It must still report success: the per-host files are
      # re-read on the same call.
      let e = engineFromPem(startCert, startKey, "api.example.com",
                            dir / "api.pem", dir / "api.key")
      check e != nil
      defer: vqEngineFree(e)
      must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
           "/api.key -out " & dir & "/api.pem -days 2 -subj /CN=api2.example.com")
      check reload(e)
      check "localhost" in subject(e)
      check "api2.example.com" in hostSubject(e)

    test "a bare reload on a PKCS#12 engine is a no-op that succeeds":
      let e = engineFromP12(dir / "bundle.p12")
      check e != nil
      defer: vqEngineFree(e)
      check "localhost" in subject(e)
      check reload(e)
      check "localhost" in subject(e)

    test "a key-only reload against a PKCS#12 certificate is refused":
      # Mirrors reloadTlsConfig: the bundle carries both halves and takes
      # precedence, so a lone key would never be opened.
      let e = engineFromP12(dir / "bundle.p12")
      check e != nil
      defer: vqEngineFree(e)
      check not reload(e, "", betaKey)
      check "PKCS#12" in $vqEngineLastError(e)
      check "localhost" in subject(e)

    test "explicit paths replace a PKCS#12 bundle":
      let e = engineFromP12(dir / "bundle.p12")
      check e != nil
      defer: vqEngineFree(e)
      check reload(e, betaCert, betaKey)
      check "beta.vortex" in subject(e)

  # Certificates with an explicitly stated validity window, for #379. Needs
  # openssl's -not_before/-not_after (3.5+); without them those cases are
  # skipped rather than failing the suite.
  let expCert = dir / "expired.pem"
  let expKey = dir / "expired.key"
  let dated = execCmdEx("openssl req -x509 -newkey rsa:2048 -nodes -keyout " &
    expKey & " -out " & expCert & " -subj /CN=expired.vortex" &
    " -not_before 20200101000000Z -not_after 20200102000000Z")[1] == 0

  suite "QUIC material outside its validity window is refused (#379)":
    ## Nothing checked notBefore/notAfter on either transport, so an expired
    ## certificate loaded cleanly and a reload pointed at an archived copy
    ## reported success while every new client failed with
    ## certificate_expired. Hard failure, no clock-skew allowance.
    test "an engine will not start on an expired certificate":
      if not dated:
        echo "    (skipped: openssl has no -not_before/-not_after)"
      else:
        check engineFromFiles(expCert, expKey) == nil
        # vq_engine_new has no engine to hang the reason on, so it lands in the
        # per-thread slot vq_engine_last_error(NULL) reads.
        check "certificate expired at" in $vqEngineLastError(nil)

    test "a reload to an expired certificate keeps the running one":
      if not dated:
        echo "    (skipped: openssl has no -not_before/-not_after)"
      else:
        let e = engineFromPem(startCert, startKey)
        check e != nil
        defer: vqEngineFree(e)
        check not reload(e, expCert, expKey)
        check "certificate expired at" in $vqEngineLastError(e)
        check "localhost" in subject(e)
        check vqTestEngineUsable(e) == 1

  suite "the QUIC session-ticket key is process-wide and rotates (#382)":
    ## Each loop builds its own SSL_CTX, and OpenSSL mints a random ticket key
    ## per context, so a ticket issued on one loop decrypted only there -- while
    ## the kernel's SO_REUSEPORT hash sends a returning client to an arbitrary
    ## loop. On an N-loop server about (N-1)/N of resumption attempts quietly
    ## fell back to a full handshake. The contexts stay per-loop (the per-loop
    ## reload needs them) and the key is shared instead.
    proc ticketKeyName(): string =
      var buf = newString(64)
      vqTestTicketKeyName(buf.cstring, csize_t(buf.len))
      $cast[cstring](addr buf[0])

    test "building another engine does not mint another key":
      let before = ticketKeyName()
      check before.len == 32              # 16 bytes, hex
      check before != repeat('0', 32)
      let a = engineFromPem(startCert, startKey)
      let b = engineFromPem(startCert, startKey)
      check a != nil and b != nil
      defer:
        vqEngineFree(a)
        vqEngineFree(b)
      check ticketKeyName() == before
      # ... and both contexts still offer tickets at all.
      check vqTestEngineNoTicket(a) == 0
      check vqTestEngineNoTicket(b) == 0

    test "a ticket encrypts and decrypts under the shared key":
      # Bits from the harness: encrypt ok, the stamped name decrypts, an
      # unknown name falls back to a full handshake instead of erroring.
      let rv = vqTestTicketKeyCycle()
      check rv >= 0
      check (rv and 1) != 0
      check (rv and 2) != 0
      check (rv and 4) != 0

    test "the key rotates and the previous one is honoured once more":
      # Run last: it ages the process-wide key by two lifetimes.
      let rv = vqTestTicketKeyCycle()
      check (rv and 8) != 0     # a new name after the lifetime elapsed
      check (rv and 16) != 0    # the retired name decrypts, asking for reissue
      check (rv and 32) != 0    # two lifetimes old: refused

  removeDir(dir)
