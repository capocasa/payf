## payf - SEPA instant transfer CLI via FinTS
##
## Usage:
##   payf transfer --to IBAN --name "Recipient" --amount 10.00 --ref "Payment"
##   payf list --from 20240101 --to 20240131
##   payf balance
##
## Configuration via .env file or environment variables

import std/[strutils, strformat, times, tables]
import cligen
import payf/config
from payf/fints import makeTransfer, fetchStatements, Transaction

const MonthNames = {
  "jan": 1, "january": 1,
  "feb": 2, "february": 2,
  "mar": 3, "march": 3,
  "apr": 4, "april": 4,
  "may": 5,
  "jun": 6, "june": 6,
  "jul": 7, "july": 7,
  "aug": 8, "august": 8,
  "sep": 9, "september": 9,
  "oct": 10, "october": 10,
  "nov": 11, "november": 11,
  "dec": 12, "december": 12
}.toTable

const DayNames = {
  "mon": dMon, "monday": dMon,
  "tue": dTue, "tuesday": dTue,
  "wed": dWed, "wednesday": dWed,
  "thu": dThu, "thursday": dThu,
  "fri": dFri, "friday": dFri,
  "sat": dSat, "saturday": dSat,
  "sun": dSun, "sunday": dSun
}.toTable

proc lastDayOfMonth(year, month: int): int =
  ## Return last day of given month
  case month
  of 1, 3, 5, 7, 8, 10, 12: 31
  of 4, 6, 9, 11: 30
  of 2:
    if year mod 4 == 0 and (year mod 100 != 0 or year mod 400 == 0): 29
    else: 28
  else: 31

proc previousWeekday(today: DateTime, target: WeekDay): DateTime =
  ## Find the most recent occurrence of target weekday (not today)
  var d = today - 1.days
  while d.weekday != target:
    d = d - 1.days
  result = d

proc parseFlexDate(s: string, isEndDate: bool): tuple[date: string, err: string] =
  ## Parse flexible date format
  ## isEndDate=false: returns start of period (e.g., 2024 → 2024-01-01)
  ## isEndDate=true: returns end of period (e.g., 2024 → 2024-12-31)
  let today = now()
  let todayDate = today.format("yyyyMMdd")
  let input = s.toLowerAscii.strip

  if input.len == 0:
    return (date: "", err: "")

  # YYYY-MM-DD format
  if input.len == 10 and input[4] == '-' and input[7] == '-':
    let normalized = input.replace("-", "")
    if normalized > todayDate:
      return (date: "", err: "Date " & input & " is in the future")
    return (date: normalized, err: "")

  # Already YYYYMMDD format
  if input.len == 8 and input.allCharsInSet({'0'..'9'}):
    if input > todayDate:
      return (date: "", err: "Date " & input & " is in the future")
    return (date: input, err: "")

  # Relative days: 30d, 7d, etc.
  if input.endsWith("d") and input.len >= 2:
    let numPart = input[0..^2]
    try:
      let days = parseInt(numPart)
      let d = today - days.days
      return (date: d.format("yyyyMMdd"), err: "")
    except: discard

  # Named periods
  case input
  of "today":
    return (date: todayDate, err: "")
  of "yesterday":
    return (date: (today - 1.days).format("yyyyMMdd"), err: "")
  of "week":
    # Last week: Monday to Sunday
    let lastSunday = previousWeekday(today, dSun)
    let lastMonday = lastSunday - 6.days
    if isEndDate:
      return (date: lastSunday.format("yyyyMMdd"), err: "")
    else:
      return (date: lastMonday.format("yyyyMMdd"), err: "")
  of "month":
    # Last month
    var year = today.year
    var month = today.month.int - 1
    if month < 1:
      month = 12
      year -= 1
    if isEndDate:
      let lastDay = lastDayOfMonth(year, month)
      return (date: $year & align($month, 2, '0') & align($lastDay, 2, '0'), err: "")
    else:
      return (date: $year & align($month, 2, '0') & "01", err: "")
  of "year":
    # Last year
    let year = today.year - 1
    if isEndDate:
      return (date: $year & "1231", err: "")
    else:
      return (date: $year & "0101", err: "")
  of "ytd":
    # Year to date
    if isEndDate:
      return (date: todayDate, err: "")
    else:
      return (date: $today.year & "0101", err: "")
  of "mtd":
    # Month to date
    if isEndDate:
      return (date: todayDate, err: "")
    else:
      return (date: today.format("yyyyMM") & "01", err: "")
  else: discard

  # Day names: mon, tuesday, etc. → last occurrence
  if input in DayNames:
    let d = previousWeekday(today, DayNames[input])
    return (date: d.format("yyyyMMdd"), err: "")

  # Month names: aug, november → that month this year (or last year if future)
  if input in MonthNames:
    let month = MonthNames[input]
    var year = today.year
    # If month is in future, use last year
    if month > today.month.int:
      year -= 1
    if isEndDate:
      let lastDay = lastDayOfMonth(year, month)
      return (date: $year & align($month, 2, '0') & align($lastDay, 2, '0'), err: "")
    else:
      return (date: $year & align($month, 2, '0') & "01", err: "")

  # Year only: 2024 → 2024-01-01 or 2024-12-31
  if input.len == 4 and input.allCharsInSet({'0'..'9'}):
    let year = parseInt(input)
    if year > today.year:
      return (date: "", err: "Year " & input & " is in the future")
    if isEndDate:
      if year == today.year:
        return (date: todayDate, err: "")  # Can't go past today
      return (date: input & "1231", err: "")
    else:
      return (date: input & "0101", err: "")

  # YYYY-MM or YYYYMM format
  var yearMonth = input.replace("-", "")
  if yearMonth.len == 6 and yearMonth.allCharsInSet({'0'..'9'}):
    let year = parseInt(yearMonth[0..3])
    let month = parseInt(yearMonth[4..5])
    if month < 1 or month > 12:
      return (date: "", err: "Invalid month: " & $month)
    let targetEnd = $year & align($month, 2, '0') & align($lastDayOfMonth(year, month), 2, '0')
    if targetEnd > todayDate:
      return (date: "", err: "Date " & input & " extends into the future")
    if isEndDate:
      let lastDay = lastDayOfMonth(year, month)
      let endDate = $year & align($month, 2, '0') & align($lastDay, 2, '0')
      if endDate > todayDate:
        return (date: todayDate, err: "")
      return (date: endDate, err: "")
    else:
      return (date: $year & align($month, 2, '0') & "01", err: "")

  # MM-DD or MMDD format (current year)
  var monthDay = input.replace("-", "")
  if monthDay.len == 4 and monthDay.allCharsInSet({'0'..'9'}):
    let month = parseInt(monthDay[0..1])
    let day = parseInt(monthDay[2..3])
    if month < 1 or month > 12:
      return (date: "", err: "Invalid month: " & $month)
    let maxDay = lastDayOfMonth(today.year, month)
    if day < 1 or day > maxDay:
      return (date: "", err: "Invalid day: " & $day & " for month " & $month)
    var year = today.year
    let targetDate = $year & align($month, 2, '0') & align($day, 2, '0')
    if targetDate > todayDate:
      year -= 1  # Use last year
    return (date: $year & align($month, 2, '0') & align($day, 2, '0'), err: "")

  # MM only (01-12)
  if input.len == 2 and input.allCharsInSet({'0'..'9'}):
    let month = parseInt(input)
    if month >= 1 and month <= 12:
      var year = today.year
      if month > today.month.int:
        year -= 1
      if isEndDate:
        let lastDay = lastDayOfMonth(year, month)
        return (date: $year & align($month, 2, '0') & align($lastDay, 2, '0'), err: "")
      else:
        return (date: $year & align($month, 2, '0') & "01", err: "")

  return (date: "", err: "Unknown date format: " & s)

proc transfer(
    to: string = "",
    name: string = "",
    amount: float = 0.0,
    reference: string = "",
    bic: string = "",
    instant: bool = true,
    env: string = ".env",
    url: string = "",
    blz: string = "",
    user: string = "",
    pin: string = "",
    iban: string = "",
    senderBic: string = "",
    dryRun: bool = false,
    debug: bool = false
): int =
  ## Execute a SEPA transfer (instant by default)
  ##
  ## Required: --to (recipient IBAN), --name, --amount
  ## Optional: --bic (recipient BIC), --reference, --instant (default: true)

  # Load and validate config
  var cfg = loadConfig(env)
  cfg.applyOverrides(url, blz, user, pin, iban, senderBic)

  let missing = cfg.validate()
  if missing.len > 0:
    stderr.writeLine "Error: Missing configuration: " & missing.join(", ")
    stderr.writeLine "Set in .env file or as environment variables"
    return 1

  # Validate transfer params
  if to.len == 0:
    stderr.writeLine "Error: --to (recipient IBAN) is required"
    return 1
  if name.len == 0:
    stderr.writeLine "Error: --name (recipient name) is required"
    return 1
  if amount <= 0:
    stderr.writeLine "Error: --amount must be greater than 0"
    return 1

  # Display transfer details
  let transferType = if instant: "INSTANT" else: "STANDARD"
  echo fmt"[{transferType} SEPA Transfer]"
  echo fmt"  From: {cfg.accountHolder} ({cfg.iban})"
  echo fmt"  To:   {name} ({to})"
  echo fmt"  Amount: {amount:.2f} EUR"
  if reference.len > 0:
    echo fmt"  Reference: {reference}"
  echo ""

  if dryRun:
    echo "[DRY RUN] Transfer not executed"
    return 0

  # Execute transfer
  echo "Connecting to bank..."

  let txResult = makeTransfer(
    url = cfg.fintsUrl,
    blz = cfg.blz,
    user = cfg.user,
    pin = cfg.pin,
    senderIban = cfg.iban,
    senderBic = cfg.bic,
    senderName = cfg.accountHolder,
    recipientIban = to,
    recipientBic = bic,
    recipientName = name,
    amount = amount,
    reference = reference,
    instant = instant,
    debug = debug
  )

  if txResult.success:
    echo ""
    echo "Transfer successful!"
    return 0
  else:
    stderr.writeLine ""
    if txResult.errorCode.len > 0 and txResult.errorMsg.len > 0:
      stderr.writeLine fmt"Transfer failed: {txResult.errorCode} - {txResult.errorMsg}"
    elif txResult.errorMsg.len > 0:
      stderr.writeLine fmt"Transfer failed: {txResult.errorMsg}"
    elif txResult.errorCode.len > 0:
      stderr.writeLine fmt"Transfer failed: {txResult.errorCode}"
    else:
      stderr.writeLine "Transfer failed: Unknown error"
    return 1

proc balance(
    env: string = ".env",
    url: string = "",
    blz: string = "",
    user: string = "",
    pin: string = "",
    iban: string = "",
    bic: string = ""
): int =
  ## Query account balance (HKSAL)

  var cfg = loadConfig(env)
  cfg.applyOverrides(url, blz, user, pin, iban, bic)

  let missing = cfg.validate()
  if missing.len > 0:
    stderr.writeLine "Error: Missing configuration: " & missing.join(", ")
    return 1

  echo "Balance query not yet implemented"
  echo fmt"Account: {cfg.iban}"
  return 0

proc escapeField(s: string, sep: char, quote: string): string =
  ## Escape a field for CSV output
  if quote.len > 0:
    # Quote the field, doubling any quotes inside
    result = quote & s.replace(quote, quote & quote) & quote
  else:
    # No quoting - replace separator chars with spaces
    if sep == '\t':
      result = s.replace("\t", "  ")
    else:
      result = s.replace($sep, " ")
    # Also replace newlines
    result = result.replace("\n", " ").replace("\r", "")

proc formatAmount(amount: float): string =
  ## Format amount with 2 decimal places
  fmt"{amount:.2f}"

proc list(
    fromDate: string = "",
    toDate: string = "",
    env: string = ".env",
    url: string = "",
    blz: string = "",
    user: string = "",
    pin: string = "",
    iban: string = "",
    bic: string = "",
    sep: string = "\t",
    quote: string = "",
    header: bool = true,
    debug: bool = false
): int =
  ## List account transactions (HKKAZ)
  ##
  ## Outputs transactions as CSV (tab-separated by default)
  ##
  ## Date formats: 2024-01-15, 2024-01, 2024, aug, monday, 30d, week, month, ytd

  var cfg = loadConfig(env)
  cfg.applyOverrides(url, blz, user, pin, iban, bic)

  let missing = cfg.validate()
  if missing.len > 0:
    stderr.writeLine "Error: Missing configuration: " & missing.join(", ")
    return 1

  # Parse flexible date formats
  let parsedFrom = parseFlexDate(fromDate, isEndDate = false)
  if parsedFrom.err.len > 0:
    stderr.writeLine "Error: " & parsedFrom.err
    return 1

  let parsedTo = parseFlexDate(toDate, isEndDate = true)
  if parsedTo.err.len > 0:
    stderr.writeLine "Error: " & parsedTo.err
    return 1

  # Default date range: last 30 days
  let today = now()
  let actualToDate = if parsedTo.date.len > 0: parsedTo.date else: today.format("yyyyMMdd")
  let actualFromDate = if parsedFrom.date.len > 0: parsedFrom.date else: (today - 30.days).format("yyyyMMdd")

  if debug:
    let fromFmt = actualFromDate[0..3] & "-" & actualFromDate[4..5] & "-" & actualFromDate[6..7]
    let toFmt = actualToDate[0..3] & "-" & actualToDate[4..5] & "-" & actualToDate[6..7]
    stderr.writeLine fmt"Fetching transactions from {fromFmt} to {toFmt}"

  let stmtResult = fetchStatements(
    url = cfg.fintsUrl,
    blz = cfg.blz,
    user = cfg.user,
    pin = cfg.pin,
    iban = cfg.iban,
    bic = cfg.bic,
    fromDate = actualFromDate,
    toDate = actualToDate,
    debug = debug
  )

  if not stmtResult.success:
    if stmtResult.errorCode.len > 0:
      stderr.writeLine fmt"Error: {stmtResult.errorCode} - {stmtResult.errorMsg}"
    else:
      stderr.writeLine fmt"Error: {stmtResult.errorMsg}"
    return 1

  let sepChar = if sep.len > 0: sep[0] else: '\t'

  # Output header
  if header:
    let cols = @["date", "valuta", "amount", "currency", "name", "iban", "bic", "reference", "booking_text", "end_to_end_id"]
    echo cols.join($sepChar)

  # Output transactions
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
  ## Show version information
  echo "payf v0.1.0"
  echo "SEPA instant transfer CLI via FinTS"
  return 0

when isMainModule:
  dispatchMulti(
    [transfer, help = {
      "to": "Recipient IBAN",
      "name": "Recipient name",
      "amount": "Transfer amount in EUR",
      "reference": "Payment reference/description",
      "bic": "Recipient BIC (optional)",
      "instant": "Use instant transfer (default: true)",
      "env": "Path to .env config file",
      "url": "Override FinTS server URL",
      "blz": "Override bank code (BLZ)",
      "user": "Override FinTS username",
      "pin": "Override FinTS PIN",
      "iban": "Override sender IBAN",
      "senderBic": "Override sender BIC",
      "dryRun": "Show what would be done without executing",
      "debug": "Show debug output (requests/responses)"
    }],
    [list, help = {
      "fromDate": "Start date (2024-01-15, 2024, aug, 30d, week, ytd)",
      "toDate": "End date (2024-01-15, 2024, nov, yesterday, today)",
      "env": "Path to .env config file",
      "url": "Override FinTS server URL",
      "blz": "Override bank code (BLZ)",
      "user": "Override FinTS username",
      "pin": "Override FinTS PIN",
      "iban": "Override account IBAN",
      "bic": "Override account BIC",
      "sep": "Field separator (default: tab)",
      "quote": "Quote character for fields (default: none)",
      "header": "Include header row (default: true)",
      "debug": "Show debug output"
    }],
    [balance, help = {
      "env": "Path to .env config file",
      "url": "Override FinTS server URL",
      "blz": "Override bank code (BLZ)",
      "user": "Override FinTS username",
      "pin": "Override FinTS PIN",
      "iban": "Override account IBAN",
      "bic": "Override account BIC"
    }],
    [version]
  )
