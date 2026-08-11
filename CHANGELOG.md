# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** the public config/WebSocket enums are now `{.pure.}` and their
  values lost the camelCase prefixes. Qualify them by type:
  `ClientVerify` (`cvNone`/`cvOptional`/`cvRequire` -> `ClientVerify.None`/`.Optional`/`.Require`),
  `ProxyProtocol` (`ppDisabled`/`ppOptional`/`ppRequire` -> `ProxyProtocol.Disabled`/`.Optional`/`.Require`),
  and `WsKind` (`wsText`/`wsBinary` -> `WsKind.Text`/`.Binary`).
- **Breaking:** `TlsMinVersion` and `TlsMaxVersion` are merged into one
  `{.pure.}` `TlsVersion` enum with `None`, `V12`, `V13`. `minTlsVersion` and
  `maxTlsVersion` now take `TlsVersion`; on a minimum, `None` means the secure
  default (TLS 1.2 floor), and on a maximum it means no cap. Migration:
  `tlsV12`/`tlsMax12` -> `TlsVersion.V12`, `tlsV13`/`tlsMax13` -> `TlsVersion.V13`,
  `tlsMaxNone` -> `TlsVersion.None`. Defaults are unchanged
  (`minTlsVersion = TlsVersion.V12`, `maxTlsVersion = TlsVersion.None`).
- **Breaking:** the `router` module is renamed to `routing`. Import it as
  `import vortex/routing`. Only code that imported the submodule directly
  (`import vortex/router`) needs to update; `import vortex` is unaffected. The
  rename lets a local `var router = newRouter()` coexist with the module and
  matches the `streaming` module's naming. The `Router` type and `newRouter`
  are unchanged.
