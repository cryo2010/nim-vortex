## The ngtcp2 shim builds against OpenSSL 3.5, the documented project minimum
## (#398).
##
## `src/vortex/http3/ngtcp2/vq_ngtcp2.cpp` asks <openssl/ssl.h> for
## `SSL_OP_SERVER_PREFERENCE`. OpenSSL 3.6.0 introduced that name for the option
## bit it had always called `SSL_OP_CIPHER_SERVER_PREFERENCE`; 3.5 defines only
## the old one, both being `SSL_OP_BIT(22)`. README.md, HARDENING.md and
## CONTRIBUTING.md all state OpenSSL >= 3.5, yet the shim would not compile
## there, and nothing in the project noticed: the vortex images are Arch-based
## and carry a newer OpenSSL. The fix is a fallback define in the shim, not a
## raised minimum.
##
## The harness tests/vq_h3_tls_ossl35.cpp rewrites the macros to the single
## spelling 3.5's header has and compiles the shim against that, so the suite
## pins the compile on any OpenSSL >= 3.5, and then checks that the context the
## shim built still carries the bit. Reverting the shim's fallback define turns
## the harness into a compile error naming `SSL_OP_SERVER_PREFERENCE`.
##
## It must stay a separate binary from tests/test_h3_tls_ctx.nim: both include
## the shim's translation unit, so linking them together would duplicate the
## shim's extern "C" ABI.

import std/[unittest, os, osproc]

when not defined(plainHttp):
  {.passC: "-I" & currentSourcePath().parentDir.parentDir /
           "src/vortex/http3/ngtcp2".}
  {.passL: "-lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -lssl -lcrypto -lstdc++".}
  {.compile: "vq_h3_tls_ossl35.cpp".}

  proc vqTestOssl35ServerPref(certPem, keyPem: cstring): cint
    {.importc: "vq_test_ossl35_server_pref", cdecl.}

  if findExe("openssl").len == 0:
    echo "SKIP: need openssl for the certificate fixtures"
    quit 0

  let dir = getTempDir() / "vortex_h3ossl35_" & $getCurrentProcessId()
  removeDir(dir); createDir(dir)

  proc must(cmd: string) =
    let (o, rc) = execCmdEx(cmd)
    doAssert rc == 0, cmd & "\n" & o

  # `finally`, not a trailing removeDir: a fixture that fails its doAssert must
  # not leave the key material behind (`defer` is not allowed at top level).
  try:
    must("openssl req -x509 -newkey rsa:2048 -nodes -keyout " & dir &
         "/leaf.key -out " & dir & "/leaf.pem -days 2 -subj /CN=localhost")
    let certPem = readFile(dir / "leaf.pem")
    let keyPem = readFile(dir / "leaf.key")

    suite "the ngtcp2 shim compiles against OpenSSL 3.5 headers (#398)":
      test "server cipher preference survives 3.5's single macro spelling":
        # Reaching this at all means the shim compiled with
        # SSL_OP_SERVER_PREFERENCE absent from the headers, which is the whole
        # bug. The returned bit then proves the fallback resolved to
        # SSL_OP_BIT(22) and that makeCtx still set it, rather than compiling
        # against some other option and quietly handing QUIC's ciphersuite order
        # back to the client (#375).
        check vqTestOssl35ServerPref(certPem.cstring, keyPem.cstring) == 1
  finally:
    removeDir(dir)
else:
  echo "SKIP: HTTP/3 is not built under -d:plainHttp"
