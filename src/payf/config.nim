## Configuration handling via .env files and environment variables

import std/[os, osproc, strutils]
import dotenv

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

proc loadConfig*(envFile: string = ".env"): Config =
  ## Load configuration from .env file with environment variable override
  # Load .env file (dotenv loads into process environment)
  if fileExists(envFile):
    load(filename = envFile)

  # Get PIN from direct value or command
  var pin = getEnv("FINTS_PIN")
  if pin.len == 0:
    let pinCmd = getEnv("FINTS_PIN_CMD")
    if pinCmd.len > 0:
      pin = execCmd(pinCmd)

  result = Config(
    fintsUrl: getEnv("FINTS_URL"),
    blz: getEnv("FINTS_BLZ"),
    user: getEnv("FINTS_USER"),
    pin: pin,
    iban: getEnv("IBAN"),
    bic: getEnv("BIC"),
    accountHolder: getEnv("ACCOUNT_HOLDER"),
    test: getEnv("TEST", "1") == "1"
  )

proc validate*(cfg: Config): seq[string] =
  ## Validate configuration, return list of missing fields
  result = @[]
  if cfg.fintsUrl.len == 0: result.add("FINTS_URL")
  if cfg.blz.len == 0: result.add("FINTS_BLZ")
  if cfg.user.len == 0: result.add("FINTS_USER")
  if cfg.pin.len == 0: result.add("FINTS_PIN")
  if cfg.iban.len == 0: result.add("IBAN")

proc applyOverrides*(cfg: var Config, url, blz, user, pin, iban, bic: string) =
  ## Apply command line overrides to config
  if url.len > 0: cfg.fintsUrl = url
  if blz.len > 0: cfg.blz = blz
  if user.len > 0: cfg.user = user
  if pin.len > 0: cfg.pin = pin
  if iban.len > 0: cfg.iban = iban
  if bic.len > 0: cfg.bic = bic
