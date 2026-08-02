## Single-import convenience: the core vortex API plus the asyncdispatch async
## adapter (`{.async.}` handlers, `req.doAsync`, `await req.read()`,
## `ws.messages`, etc.). Instead of
##
##   import vortex
##   import vortex/adapters/asyncdispatch
##
## just `import vortex/asyncdispatch`. For chronos drivers use
## `import vortex/chronos` instead (pick one runtime per program).
import ../vortex
export vortex
import ./adapters/asyncdispatch
export asyncdispatch
