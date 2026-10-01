## payf - SEPA instant transfer CLI via FinTS
##
## Usage:
##   payf transfer "Recipient Name" IBAN AMOUNT [--reference ...] [--no-instant]
##   payf list [FROM] [TO]
##   payf balance
##
## Configuration via payf.conf file or environment variables.
## Logs to $XDG_DATA_HOME/payf/payf-YYYY.log (disable with PAYF_NO_LOG=1).

import std/[os, strutils, strformat, times, tables]
import cligen
from finz import makeTransfer, fetchStatements, UiHooks
import payf/config
import payf/dates
import payf/log as payflog
import payf/update

const NimblePkgVersion {.strdefine.} = "dev"

# payf's registered FinTS product ID (not finz's)
const ProductId = "5D8519C8F4024026D066D6661"

proc finzHooks(l: Logger): UiHooks =
  ## Adapt payf's logger and terminal to finz's interaction hooks.
  UiHooks(
    onDebug: proc (msg: string) = l.debug(msg),
    onInfo: proc (msg: string) = l.info(msg),
    onPrompt: proc (msg: string) = l.prompt("payf: " & msg),
    onWait: proc () =
      try: discard stdin.readLine()
      except EOFError: discard
  )

proc die(code: int, msg: string) =
  stderr.writeLine "payf: " & msg
  quit code

proc loadValidConfig(confArg: string): Config =
  let confFile = if confArg.len > 0: confArg else: defaultConfPath()
  try:
    result = loadConfig(confFile)
  except CatchableError as e:
    die 3, "cannot read " & confFile & ": " & e.msg
  let missing = result.validate()
  if missing.len > 0:
    die 3, "missing configuration in " & confFile & ": " & missing.join(", ")

proc hintLog(l: Logger) =
  ## Append a "see logs at ..." hint to the previous error line.
  if l != nil and l.path.len > 0:
    stderr.writeLine "payf: see log: " & l.path

proc transfer(
    args: seq[string],
    reference: string = "",
    bic: string = "",
    instant: bool = true,
    conf: string = "",
    dryRun: bool = false,
    verbose: bool = false
): int =
  ## Execute a SEPA transfer (instant by default).
  ##
  ## Usage: payf transfer "Recipient Name" IBAN AMOUNT

  if args.len != 3:
    die 2, "usage: payf transfer NAME IBAN AMOUNT"
  let name = args[0]
  let to = args[1]
  var amount: float
  try:
    amount = parseFloat(args[2])
  except ValueError:
    die 2, "invalid amount: " & args[2]
  if amount <= 0:
    die 2, "amount must be greater than 0"

  let cfg = loadValidConfig(conf)
  let l = initLogger(verbose)
  defer: l.close()
  l.info(fmt"transfer {amount:.2f} EUR to {name} ({to}) instant={instant}")

  if dryRun:
    return 0

  let txResult = makeTransfer(
    url = cfg.fintsUrl,
    blz = cfg.blz,
    user = cfg.user,
    pin = cfg.pin,
    productId = ProductId,
    senderIban = cfg.iban,
    senderBic = cfg.bic,
    senderName = cfg.accountHolder,
    recipientIban = to,
    recipientBic = bic,
    recipientName = name,
    amount = amount,
    reference = reference,
    ui = finzHooks(l),
    instant = instant
  )

  if txResult.success:
    return 0

  var msg = "transfer failed"
  if txResult.errorCode.len > 0 and txResult.errorMsg.len > 0:
    msg &= ": " & txResult.errorCode & " " & txResult.errorMsg
  elif txResult.errorMsg.len > 0:
    msg &= ": " & txResult.errorMsg
  elif txResult.errorCode.len > 0:
    msg &= ": " & txResult.errorCode
  stderr.writeLine "payf: " & msg
  hintLog(l)
  return 5

proc balance(
    conf: string = "",
    verbose: bool = false
): int =
  ## Query account balance (not yet implemented).
  let cfg = loadValidConfig(conf)
  discard cfg
  stderr.writeLine "payf: balance not yet implemented"
  return 1

proc list(
    args: seq[string],
    conf: string = "",
    sep: string = "\t",
    quote: string = "",
    header: bool = true,
    verbose: bool = false
): int =
  ## List account transactions (HKKAZ / HICAZ).
  ##
  ## Usage: payf list [FROM] [TO]
  ## Date formats: 2024-01-15, 2024-01, 2024, aug, monday, 30d, week, ytd.
  ## Default range: today.

  if args.len > 2:
    die 2, "usage: payf list [FROM] [TO]"
  let fromArg = if args.len >= 1: args[0] else: ""
  let toArg = if args.len >= 2: args[1] else: ""

  let cfg = loadValidConfig(conf)

  let parsedFrom = parseFlexDate(fromArg, isEndDate = false)
  if parsedFrom.err.len > 0:
    die 2, parsedFrom.err
  let parsedTo = parseFlexDate(toArg, isEndDate = true)
  if parsedTo.err.len > 0:
    die 2, parsedTo.err

  let today = now()
  let actualTo = if parsedTo.date.len > 0: parsedTo.date else: today.format("yyyyMMdd")
  let actualFrom = if parsedFrom.date.len > 0: parsedFrom.date else: today.format("yyyyMMdd")

  let l = initLogger(verbose)
  defer: l.close()
  l.info(fmt"list transactions from {actualFrom} to {actualTo}")

  let stmtResult = fetchStatements(
    url = cfg.fintsUrl,
    blz = cfg.blz,
    user = cfg.user,
    pin = cfg.pin,
    productId = ProductId,
    iban = cfg.iban,
    bic = cfg.bic,
    fromDate = actualFrom,
    toDate = actualTo,
    ui = finzHooks(l)
  )

  if not stmtResult.success:
    var msg = "list failed"
    if stmtResult.errorCode.len > 0 and stmtResult.errorMsg.len > 0:
      msg &= ": " & stmtResult.errorCode & " " & stmtResult.errorMsg
    elif stmtResult.errorMsg.len > 0:
      msg &= ": " & stmtResult.errorMsg
    elif stmtResult.errorCode.len > 0:
      msg &= ": " & stmtResult.errorCode
    stderr.writeLine "payf: " & msg
    hintLog(l)
    return 5

  let sepChar = if sep.len > 0: sep[0] else: '\t'

  if header:
    let cols = @["date", "valuta", "amount", "currency", "name", "iban", "bic", "reference", "booking_text", "end_to_end_id"]
    echo cols.join($sepChar)

  for tx in stmtResult.transactions:
    let fields = @[
      escapeField(tx.date, sepChar, quote),
      escapeField(tx.valutaDate, sepChar, quote),
      escapeField(formatAmount(tx.amount), sepChar, quote),
      escapeField(tx.currency, sepChar, quote),
      escapeField(tx.name, sepChar, quote),
      escapeField(tx.iban, sepChar, quote),
      escapeField(tx.bic, sepChar, quote),
      escapeField(tx.reference, sepChar, quote),
      escapeField(tx.bookingText, sepChar, quote),
      escapeField(tx.endToEndId, sepChar, quote)
    ]
    echo fields.join($sepChar)

  return 0

proc version(): int =
  echo "payf " & NimblePkgVersion
  return 0

when isMainModule:
  cleanupStaleBinaries()
  # Detached auto-update worker; strictly silent, runs before everything.
  let cl = commandLineParams()
  if cl.len == 1 and cl[0] == "--self-update-check":
    selfUpdateCheck()
    quit 0
  showUpdateNoticeMaybe()
  spawnBackgroundUpdateMaybe()

  dispatchMulti(
    [transfer, cmdName = "transfer", help = {
      "args": "NAME IBAN AMOUNT",
      "reference": "payment reference/description",
      "bic": "recipient BIC (optional)",
      "instant": "use instant transfer (default: on)",
      "conf": "path to payf.conf (default: ./payf.conf, else ~/.config/payf/payf.conf)",
      "dryRun": "don't actually send",
      "verbose": "mirror bank protocol to stderr"
    }],
    [list, cmdName = "list", help = {
      "args": "[FROM] [TO]  dates (2024-01-15, aug, 30d, week, ...)",
      "conf": "path to payf.conf (default: ./payf.conf, else ~/.config/payf/payf.conf)",
      "sep": "field separator (default: tab)",
      "quote": "quote character (default: none)",
      "header": "include header row",
      "verbose": "mirror bank protocol to stderr"
    }],
    [balance, cmdName = "balance", help = {
      "conf": "path to payf.conf (default: ./payf.conf, else ~/.config/payf/payf.conf)",
      "verbose": "mirror bank protocol to stderr"
    }],
    [version, cmdName = "version"]
  )
