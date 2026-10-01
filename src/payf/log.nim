## Logging for payf.
##
## Default: appends to `$XDG_DATA_HOME/payf/payf-YYYY.log`
## (or `~/.local/share/payf/payf-YYYY.log`). Disable with `PAYF_NO_LOG=1`.

import std/[os, times]

type
  Logger* = ref object
    file: File           # nil when disabled
    verbose*: bool       # mirror debug lines to stderr
    path*: string        # path to current log file (for error hints)

proc logFilePath*(): string =
  let base = getEnv("XDG_DATA_HOME", getHomeDir() / ".local" / "share")
  base / "payf" / "payf-" & now().format("yyyy") & ".log"

proc initLogger*(verbose = false): Logger =
  result = Logger(verbose: verbose)
  if getEnv("PAYF_NO_LOG") == "1":
    return
  let path = logFilePath()
  try:
    createDir(path.parentDir)
    result.file = open(path, fmAppend)
    result.path = path
  except CatchableError:
    result.file = nil

proc close*(l: Logger) =
  if l == nil: return
  if l.file != nil:
    try: l.file.close()
    except CatchableError: discard
    l.file = nil

proc write(l: Logger, level, msg: string) =
  if l == nil: return
  if l.file == nil: return
  let ts = now().format("yyyy-MM-dd'T'HH:mm:ss")
  try:
    l.file.writeLine ts & " " & level & " " & msg
    l.file.flushFile()
  except CatchableError:
    discard

proc debug*(l: Logger, msg: string) =
  ## Bank-interaction detail. Always to log file; to stderr only if verbose.
  if l == nil: return
  l.write("DEBUG", msg)
  if l.verbose:
    stderr.writeLine msg

proc info*(l: Logger, msg: string) =
  ## Notable events (VoP result). Log file only; no terminal output.
  if l == nil: return
  l.write("INFO", msg)

proc prompt*(l: Logger, msg: string) =
  ## Critical user-facing prompt (TAN approval on phone, press-enter-to-continue).
  ## Always written to stderr so the user knows they need to act.
  if l != nil:
    l.write("INFO", msg)
  stderr.writeLine msg

