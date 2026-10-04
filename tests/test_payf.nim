## Tests for payf CLI logic (the FinTS protocol suite lives in ~/p/fint).

import std/[os, unittest, strutils, times]
import ../src/payf/amounts
import ../src/payf/dates
import ../src/payf/update
import ../src/payf/config

suite "amount parsing":
  test "plain and both decimal conventions":
    check parseAmount("10").cents == 1000
    check parseAmount("10.5").cents == 1050
    check parseAmount("10,5").cents == 1050
    check parseAmount("10.50").cents == 1050
    check parseAmount("10,50").cents == 1050
    check parseAmount("10000,10").cents == 1000010
    check parseAmount("10000.10").cents == 1000010
    check parseAmount("0,01").cents == 1

  test "space grouping is stripped":
    check parseAmount("1 234,56").cents == 123456
    check parseAmount("\u00A01\u00A0234,56").cents == 123456
    check parseAmount(" 10,50 ").cents == 1050

  test "ambiguous forms are rejected":
    check parseAmount("1.000").err.contains("could be 1,00 or 1000")
    check parseAmount("10.500").err.contains("could be 10,50 or 10500")
    check parseAmount("10,000").err.len > 0
    check parseAmount("1.234").err.len > 0
    check parseAmount("1.000,50").err.contains("write 1000,50")
    check parseAmount("1,000.50").err.contains("write 1000,50")

  test "invalid amounts":
    check parseAmount("abc").err.len > 0
    check parseAmount("10.").err.len > 0
    check parseAmount("-5").err.len > 0
    check parseAmount("").err.len > 0
    check parseAmount("10.5.3").err.len > 0

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

suite "auto-update semver":
  test "parse plain and v-prefixed":
    check parseSemver("1.2.3") == @[1, 2, 3]
    check parseSemver("v0.10.0") == @[0, 10, 0]

  test "compare":
    check semverGt("0.2.0", "0.1.0")
    check semverGt("0.10.0", "0.9.9")
    check not semverGt("0.1.0", "0.1.0")
    check not semverGt("0.1.0", "0.2.0")

  test "unequal length":
    check semverGt("0.1.1", "0.1")
    check not semverGt("0.1", "0.1.0")

  test "env override wins over build default":
    putEnv("PAYF_AUTO_UPDATE", "false")
    check not autoUpdateEnabled()
    putEnv("PAYF_AUTO_UPDATE", "true")
    check autoUpdateEnabled()
    delEnv("PAYF_AUTO_UPDATE")

suite "config loading":
  test "reads payf.conf, env overrides":
    let dir = getTempDir() / "payf-test-conf"
    removeDir(dir)
    createDir(dir)
    let conf = dir / "payf.conf"
    writeFile(conf, """fints_url=https://bank/fints30
fints_blz=12345678
fints_user=carl
iban=DE89370400440532013000
bic=GENODEF1XXX
account_holder=Max Mustermann
""")

    let cfg = loadConfig(conf)
    check cfg.fintsUrl == "https://bank/fints30"
    check cfg.blz == "12345678"
    check cfg.iban == "DE89370400440532013000"
    check cfg.accountHolder == "Max Mustermann"

    putEnv("FINTS_USER", "someone-else")
    let cfg2 = loadConfig(conf)
    check cfg2.user == "someone-else"
    delEnv("FINTS_USER")
    removeDir(dir)

  test "normalizes iban whitespace":
    let dir = getTempDir() / "payf-test-iban"
    removeDir(dir)
    createDir(dir)
    let conf = dir / "payf.conf"
    writeFile(conf, "iban = DE89 3704 0044 0532 0130 00\n")
    check loadConfig(conf).iban == "DE89370400440532013000"
    putEnv("IBAN", " de12 3456 ")
    check loadConfig(conf).iban == "DE123456"
    delEnv("IBAN")
    removeDir(dir)

    check normalizeIban("de89 3704\t0044 0532 0130 00") == "DE89370400440532013000"
    check normalizeIban("") == ""

  test "missing file means empty config":
    let cfg = loadConfig("/nonexistent/payf.conf")
    check cfg.fintsUrl == ""
    check cfg.validate().len == 5

suite "conf file cascade":
  test "local payf.conf wins, else XDG user conf":
    let dir = getTempDir() / "payf-test-cascade"
    removeDir(dir)
    createDir(dir / "payf")
    let oldDir = getCurrentDir()
    setCurrentDir(dir)
    putEnv("XDG_CONFIG_HOME", dir)

    # no local file -> user conf
    check defaultConfPath() == dir / "payf" / "payf.conf"
    writeFile(dir / "payf" / "payf.conf", "fints_url=https://user/fints30\n")
    check loadConfig("").fintsUrl == "https://user/fints30"

    # local file appears -> it wins, no merging
    writeFile("payf.conf", "fints_url=https://local/fints30\n")
    check defaultConfPath() == "payf.conf"
    let cfg = loadConfig("")
    check cfg.fintsUrl == "https://local/fints30"
    check cfg.blz == ""  # user conf value does NOT leak in

    setCurrentDir(oldDir)
    delEnv("XDG_CONFIG_HOME")
    removeDir(dir)

suite "output field escaping":
  test "tab-separated replaces separator":
    check escapeField("a\tb", '\t', "") == "a  b"

  test "quoted keeps separator":
    check escapeField("a\tb", '\t', "\"") == "\"a\tb\""

  test "newlines flattened":
    check escapeField("a\nb", '|', "") == "a b"
