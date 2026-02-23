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
requires "dotenv >= 2.0.0"
