## Amount parsing for the `payf transfer` command. Accepts both decimal
## conventions (`10.50`, `10,50`) and rejects anything a German and an
## English reader could read differently, so a pasted amount can never
## silently move the decimal point.

import std/strutils

proc stripGrouping(s: string): string =
  ## Drop spaces bank UIs use as digit grouping (ASCII, NBSP, thin
  ## space, narrow NBSP).
  for c in s:
    if c in Whitespace: continue
    result.add c
  result = result.replace("\u00A0", "").replace("\u2009", "").replace("\u202F", "")

proc parseAmount*(s: string): tuple[cents: int, err: string] =
  ## `10`, `10.5`, `10,5`, `10.50`, `10,50` parse; `1.000`, `10,000`,
  ## `1.000,50`, `1,000.50` are rejected as locale-ambiguous. No locale
  ## groups digits in twos or mints three-decimal cents, so a single
  ## separator with up to two digits is always a decimal separator.
  let t = stripGrouping(s)
  if t.len == 0 or not t.allCharsInSet({'0'..'9', '.', ','}):
    return (cents: 0, err: "invalid amount: " & s)

  let seps = t.count('.') + t.count(',')
  if seps > 1:
    let lastSep = max(t.rfind('.'), t.rfind(','))
    let plain = t[0 ..< lastSep].replace(".", "").replace(",", "")
    return (cents: 0,
            err: "ambiguous amount '" & s & "': write " & plain & "," & t[lastSep + 1 .. ^1])

  var intPart = t
  var fracPart = ""
  if seps == 1:
    let sep = t.find({'.', ','})
    intPart = t[0 ..< sep]
    fracPart = t[sep + 1 .. ^1]
    if fracPart.len > 2:
      return (cents: 0, err: "ambiguous amount '" & s & "': could be " &
              intPart & "," & fracPart[0 .. 1] & " or " & intPart & fracPart)

  if intPart.len == 0 or (seps == 1 and fracPart.len == 0):
    return (cents: 0, err: "invalid amount: " & s)

  try:
    var cents = parseInt(intPart) * 100
    if fracPart.len == 1: cents += parseInt(fracPart) * 10
    elif fracPart.len == 2: cents += parseInt(fracPart)
    result = (cents: cents, err: "")
  except CatchableError:
    return (cents: 0, err: "amount too large: " & s)
