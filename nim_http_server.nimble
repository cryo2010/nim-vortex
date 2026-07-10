# Package

version       = "0.1.0"
author        = "Craig Younker"
description   = "A fast HTTP/1.1, HTTP/2 and HTTP/3 server"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.2.10"

task bench, "Build benchmark server with release flags":
  exec "nim c --mm:orc --threads:on -d:danger --passC:-flto -o:bench/handlers bench/handlers.nim"
