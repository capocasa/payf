## Input parsing for `payf batch`: TSV rows of
## `NAME<TAB>IBAN<TAB>AMOUNT[<TAB>REFERENCE]`, one payment per line.
## `#` comments and blank lines are skipped; an optional literal
## `name<TAB>iban<TAB>amount<TAB>reference` header line is ignored.
## Amounts stay integer cents until the finz call.

import std/strutils
import payf/amounts
import payf/config

const ReferenceMaxChars = 140  # SEPA Verwendungszweck limit

type
  BatchRow* = object
    name*: string
    iban*: string
    cents*: int
    reference*: string

  BatchFile* = object
    rows*: seq[BatchRow]
    totalCents*: int
    err*: string  ## first error with line number; "" = ok

proc headerLine(line: string): bool =
  ## The canonical header, optionally with trailing fields; a payee
  ## actually named "name" is a risk we accept.
  let fields = line.split('\t')
  fields.len >= 3 and
    fields[0].toLowerAscii == "name" and
    fields[1].toLowerAscii == "iban" and
    fields[2].toLowerAscii == "amount"

proc parseBatchFile*(text: string): BatchFile =
  ## Parse batch input. Fails on the first bad row with its line number
  ## so the user can fix it and rerun.
  result = BatchFile(rows: @[], totalCents: 0)
  var headerChecked = false
  var n = 0
  for raw in text.splitLines():
    inc n
    let line = raw.strip()
    if line.len == 0 or line.startsWith('#'):
      continue
    if not headerChecked:
      headerChecked = true
      if headerLine(line):
        continue
    let fields = line.split('\t', maxsplit = 3)
    if fields.len < 3:
      result.err = "line " & $n & ": expected NAME, IBAN, AMOUNT[, REFERENCE]"
      return
    let name = fields[0].strip()
    if name.len == 0:
      result.err = "line " & $n & ": empty name"
      return
    let iban = normalizeIban(fields[1])
    let ibanErr = validateIban(iban)
    if ibanErr.len > 0:
      result.err = "line " & $n & ": invalid iban: " & ibanErr
      return
    let parsed = parseAmount(fields[2])
    if parsed.err.len > 0:
      result.err = "line " & $n & ": " & parsed.err
      return
    if parsed.cents <= 0:
      result.err = "line " & $n & ": amount must be greater than 0"
      return
    let reference = if fields.len == 4: fields[3].strip() else: ""
    if reference.len > ReferenceMaxChars:
      result.err = "line " & $n & ": reference longer than " & $ReferenceMaxChars & " chars"
      return
    result.rows.add BatchRow(name: name, iban: iban, cents: parsed.cents, reference: reference)
    result.totalCents += parsed.cents

when isMainModule:
  discard
