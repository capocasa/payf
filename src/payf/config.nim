## Configuration via payf.conf (flat `key = value` lines) and environment
## variables. Environment variables (FINTS_URL, FINTS_PIN, ...) override
## file values.

import std/[os, osproc, strutils, tables]

type
  Config* = object
    fintsUrl*: string
    blz*: string
    user*: string
    pin*: string
    iban*: string
    bic*: string
    accountHolder*: string
    test*: bool

proc execCmd(cmd: string): string =
  ## Execute a command and return first line of stdout
  let (output, exitCode) = execCmdEx(cmd)
  if exitCode != 0:
    raise newException(OSError, "Command failed: " & cmd)
  result = output.strip().splitLines()[0]

proc readConfFile(path: string): Table[string, string] =
  ## Parse flat `key = value` lines. '#' or ';' starts a comment. The
  ## whole rest of the line is the value, so URLs need no quoting
  ## (unlike std/parsecfg, which truncates values at ':').
  result = initTable[string, string]()
  for line in readFile(path).splitLines():
    let l = line.strip()
    if l.len == 0 or l[0] in {'#', ';'}: continue
    let eq = l.find({'=', ':'})
    if eq <= 0: continue
    result[l[0 ..< eq].strip().toLowerAscii] = l[eq + 1 .. ^1].strip()

proc normalizeIban*(iban: string): string =
  ## Banks print IBANs grouped with spaces; strip whitespace and
  ## uppercase so pasted values work verbatim (config and argv both).
  for c in iban:
    if not c.isSpaceAscii: result.add c
  result = toUpperAscii(result)

proc defaultConfPath*(): string =
  ## Local ./payf.conf wins, else the per-user
  ## ~/.config/payf/payf.conf (XDG_CONFIG_HOME respected).
  if fileExists("payf.conf"): return "payf.conf"
  getEnv("XDG_CONFIG_HOME", getHomeDir() / ".config") / "payf" / "payf.conf"

proc loadConfig*(confFile: string = ""): Config =
  ## Load configuration from a conf file ("" = ./payf.conf, falling
  ## back to ~/.config/payf/payf.conf); environment variables of the
  ## same name (upper-case) override file values.
  let path = if confFile.len > 0: confFile else: defaultConfPath()
  var file: Table[string, string]
  if fileExists(path):
    file = readConfFile(path)

  proc value(key, envVar: string, default = ""): string =
    let v = getEnv(envVar)
    if v.len > 0: return v
    if file.hasKey(key): return file[key]
    default

  var pin = value("fints_pin", "FINTS_PIN")
  if pin.len == 0:
    let pinCmd = value("fints_pin_cmd", "FINTS_PIN_CMD")
    if pinCmd.len > 0:
      pin = execCmd(pinCmd)

  result = Config(
    fintsUrl: value("fints_url", "FINTS_URL"),
    blz: value("fints_blz", "FINTS_BLZ"),
    user: value("fints_user", "FINTS_USER"),
    pin: pin,
    iban: normalizeIban(value("iban", "IBAN")),
    bic: value("bic", "BIC"),
    accountHolder: value("account_holder", "ACCOUNT_HOLDER"),
    test: value("test", "TEST", "1") == "1"
  )

proc validate*(cfg: Config): seq[string] =
  ## Validate configuration, return list of missing fields
  result = @[]
  if cfg.fintsUrl.len == 0: result.add("fints_url")
  if cfg.blz.len == 0: result.add("fints_blz")
  if cfg.user.len == 0: result.add("fints_user")
  if cfg.pin.len == 0: result.add("fints_pin")
  if cfg.iban.len == 0: result.add("iban")
