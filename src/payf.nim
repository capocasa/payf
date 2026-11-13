## payf - SEPA instant transfer CLI via FinTS
##
## Usage:
##   payf transfer "Recipient Name" IBAN AMOUNT [--reference ...] [--no-instant]
##   payf batch FILE
##   payf list [FROM] [TO]
##   payf balance
##
## Configuration via payf.conf file or environment variables.
## Logs to $XDG_DATA_HOME/payf/payf-YYYY.log (disable with PAYF_NO_LOG=1).

import std/[os, strutils, strformat, times, tables]
import cligen
from finz import makeTransfer, makeBatchTransfer, fetchStatements, fetchBalance, UiHooks, TransferRequest
import payf/amounts
import payf/batchfile
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

proc die(code: int, msg: string) {.noreturn.} =
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
  let ibanErr = validateIban(result.iban)
  if ibanErr.len > 0:
    die 3, "invalid iban in " & confFile & ": " & ibanErr
  let bicErr = validateBic(result.bic)
  if bicErr.len > 0:
    die 3, "invalid bic in " & confFile & ": " & bicErr

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
  let to = normalizeIban(args[1])
  let ibanErr = validateIban(to)
  if ibanErr.len > 0:
    die 2, "invalid recipient iban: " & ibanErr
  let rcptBic = normalizeBic(bic)
  let bicErr = validateBic(rcptBic)
  if bicErr.len > 0:
    die 2, "invalid recipient bic: " & bicErr
  let parsed = parseAmount(args[2])
  if parsed.err.len > 0:
    die 2, parsed.err
  let amount = parsed.cents / 100
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
    recipientBic = rcptBic,
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

proc batch(
    args: seq[string],
    conf: string = "",
    dryRun: bool = false,
    verbose: bool = false
): int =
  ## Submit several instant transfers as one batch (SEPA-Sammelüberweisung,
  ## HKIPM): one pain.001, one TAN for the whole batch. Instant only — the
  ## bank must advertise HKIPM, there is no non-instant fallback.
  ##
  ## Usage: payf batch FILE
  ## FILE: TSV lines `NAME<TAB>IBAN<TAB>AMOUNT[<TAB>REFERENCE]`, # comments,
  ## optional `name\tiban\tamount\treference` header line.

  if args.len != 1:
    die 2, "usage: payf batch FILE"
  let text =
    try: readFile(args[0])
    except CatchableError as e:
      die 2, "cannot read " & args[0] & ": " & e.msg
  let parsedFile = parseBatchFile(text)
  if parsedFile.err.len > 0:
    die 2, args[0] & ": " & parsedFile.err
  if parsedFile.rows.len == 0:
    die 2, args[0] & ": no payments found"

  let cfg = loadValidConfig(conf)
  let l = initLogger(verbose)
  defer: l.close()
  l.info(fmt"batch {parsedFile.rows.len} payments, {parsedFile.totalCents / 100:.2f} EUR instant")

  if dryRun:
    return 0

  var payments: seq[TransferRequest] = @[]
  for row in parsedFile.rows:
    payments.add TransferRequest(
      recipientName: row.name,
      recipientIban: row.iban,
      recipientBic: "",
      amount: row.cents / 100,
      currency: "EUR",
      reference: row.reference,
      instant: true
    )

  let txResult = makeBatchTransfer(
    url = cfg.fintsUrl,
    blz = cfg.blz,
    user = cfg.user,
    pin = cfg.pin,
    productId = ProductId,
    senderIban = cfg.iban,
    senderBic = cfg.bic,
    senderName = cfg.accountHolder,
    payments = payments,
    ui = finzHooks(l)
  )

  if txResult.success:
    return 0

  var msg = "batch failed"
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
  ## Query account balance (HKSAL / HISAL).
  let cfg = loadValidConfig(conf)

  let l = initLogger(verbose)
  defer: l.close()
  l.info("balance query")

  let balResult = fetchBalance(
    url = cfg.fintsUrl,
    blz = cfg.blz,
    user = cfg.user,
    pin = cfg.pin,
    productId = ProductId,
    iban = cfg.iban,
    bic = cfg.bic,
    ui = finzHooks(l)
  )

  if not balResult.success:
    var msg = "balance failed"
    if balResult.errorCode.len > 0 and balResult.errorMsg.len > 0:
      msg &= ": " & balResult.errorCode & " " & balResult.errorMsg
    elif balResult.errorMsg.len > 0:
      msg &= ": " & balResult.errorMsg
    elif balResult.errorCode.len > 0:
      msg &= ": " & balResult.errorCode
    stderr.writeLine "payf: " & msg
    hintLog(l)
    return 5

  echo formatAmount(balResult.saldo.balance) & " " & balResult.saldo.currency
  return 0

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
    [batch, cmdName = "batch", help = {
      "args": "FILE  TSV: NAME<TAB>IBAN<TAB>AMOUNT[<TAB>REFERENCE]",
      "conf": "path to payf.conf (default: ./payf.conf, else ~/.config/payf/payf.conf)",
      "dryRun": "validate and log only, don't send",
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
