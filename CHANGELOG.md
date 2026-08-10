# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** the `router` module is renamed to `routing`. Import it as
  `import vortex/routing`. Only code that imported the submodule directly
  (`import vortex/router`) needs to update; `import vortex` is unaffected. The
  rename lets a local `var router = newRouter()` coexist with the module and
  matches the `streaming` module's naming. The `Router` type and `newRouter`
  are unchanged.
