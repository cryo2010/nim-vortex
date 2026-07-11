## Shared libFuzzer glue. Each target imports this and calls
## `fuzzMain(testOne)` where `testOne(data: openArray[char])` exercises the
## code under test. This wires it to libFuzzer's entry point and starts
## the Nim runtime on the first input. See fuzz/run.sh for build flags
## (clang + -fsanitize=fuzzer,address, checks on, -d:useMalloc so ASAN
## sees Nim allocations).

proc NimMain() {.importc.}

template fuzzMain*(testOne: untyped) =
  var started {.global.} = false

  proc LLVMFuzzerTestOneInput(data: ptr UncheckedArray[char],
                              len: csize_t): cint {.exportc, cdecl.} =
    if not started:
      NimMain()
      started = true
    if len > 0:
      testOne(toOpenArray(data, 0, int(len) - 1))
    0
