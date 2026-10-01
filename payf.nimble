# Package

version       = "0.1.0"
author        = "payf"
description   = "FinTS CLI for SEPA instant transfers"
license       = "MIT"
srcDir        = "src"
bin           = @["payf"]

# Dependencies

requires "nim >= 2.0.0"
requires "cligen >= 1.6.0"
requires "finz >= 0.1.0"
task test, "Run tests":
  exec "nim c -r --path:src tests/test_payf.nim"
