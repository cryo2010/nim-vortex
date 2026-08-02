## Single-import convenience: the core vortex API plus the chronos async adapter
## (`{.async.}` handlers, `req.doAsync`, `await req.read()`, `ws.messages`, etc.).
## Instead of
##
##   import vortex
##   import vortex/adapters/chronos
##
## just `import vortex/chronos`. chronos is not a vortex dependency, so add
## `requires "chronos >= 4.0.0"` to your project. For asyncdispatch use
## `import vortex/asyncdispatch` instead (pick one runtime per program).
import ../vortex
export vortex
import ./adapters/chronos
export chronos
