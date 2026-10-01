## Tests for payf CLI logic (the FinTS protocol suite lives in ~/p/fint).

import std/[unittest, strutils, times]
import ../src/payf/dates

suite "flexible date parsing":
  test "ISO date":
    let r = parseFlexDate("2024-01-15", isEndDate = false)
    check r.date == "20240115"
    check r.err == ""

  test "bare YYYYMMDD":
    let r = parseFlexDate("20240115", isEndDate = true)
    check r.date == "20240115"

  test "N days back":
    let r = parseFlexDate("10d", isEndDate = false)
    check r.date.len == 8
    check r.date != now().format("yyyyMMdd")

  test "named month":
    let r = parseFlexDate("jan", isEndDate = false)
    check r.date.endsWith("01")

  test "year":
    let r = parseFlexDate("2024", isEndDate = false)
    check r.date == "20240101"

  test "garbage is rejected":
    let r = parseFlexDate("notadate", isEndDate = false)
    check r.err.len > 0

suite "output field escaping":
  test "tab-separated replaces separator":
    check escapeField("a\tb", '\t', "") == "a  b"

  test "quoted keeps separator":
    check escapeField("a\tb", '\t', "\"") == "\"a\tb\""

  test "newlines flattened":
    check escapeField("a\nb", '|', "") == "a b"
