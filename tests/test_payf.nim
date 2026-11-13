## Tests for payf CLI logic (the FinTS protocol suite lives in ~/p/fint).

import std/[os, unittest, strutils, times]
import ../src/payf/amounts
import ../src/payf/batchfile
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

suite "iban validation":
  test "valid ibans pass":
    check validateIban("DE75700000000071101002") == ""
    check validateIban("DE89370400440532013000") == ""
    check validateIban("LU897510000110287619") == ""
    check validateIban("") == ""

  test "truncated iban fails checksum":
    # two digits short of DE75700000000071101002; this exact value sent
    # the bank into an endless 3040 VoP loop ending in 9000
    let err = validateIban(normalizeIban("DE75 7000 0000 0071 1010"))
    check err.contains("checksum failed")
    check err.contains("DE757000000000711010")

  test "structural rejects":
    check validateIban("DE7570000000007110100Y").len > 0
    check validateIban("1275700000000071101002").len > 0
    check validateIban("DE7570000000071101002").len > 0
    check validateIban("DE75 7000 0000 0071 1010 02").len > 0

suite "bic validation":
  test "valid bics pass":
    check validateBic("MARKDEF1750") == ""
    check validateBic("GENODEF1XXX") == ""
    check validateBic("BYLADEM1001") == ""
    check validateBic("MARKDEF1") == ""
    check validateBic("") == ""

  test "truncated bic rejected":
    # MARKDEF1750 without its final digit; the 10-character BIC
    # misrouted the VoP payee lookup into a 3040 loop ending in 9000
    let err = validateBic(normalizeBic("MARKDEF175"))
    check err.contains("expected 8 or 11 characters")
    check err.contains("MARKDEF175")

  test "structural rejects":
    check validateBic("MARKDEF17500").len > 0  # 12 chars
    check validateBic("1ARKDEF1750").len > 0    # digit in bank code
    check validateBic("MARKDEF17#0").len > 0    # non-alphanumeric character
    check validateBic("markdef1 750").len > 0   # must be normalized first

  test "normalize strips grouping and case":
    check normalizeBic("markdef1 750") == "MARKDEF1750"
    check normalizeBic(" GENODEF1XXX ") == "GENODEF1XXX"

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

  test "config with broken sender bic":
    let dir = getTempDir() / "payf-test-bad-bic"
    removeDir(dir)
    createDir(dir)
    let conf = dir / "payf.conf"
    writeFile(conf, "bic = MARKDEF175\n")
    let cfg = loadConfig(conf)
    check validateBic(cfg.bic).contains("expected 8 or 11 characters")
    removeDir(dir)

  test "config with broken sender iban":
    let dir = getTempDir() / "payf-test-bad-iban"
    removeDir(dir)
    createDir(dir)
    let conf = dir / "payf.conf"
    writeFile(conf, "iban = DE757000000000711010\n")
    let cfg = loadConfig(conf)
    check cfg.iban == "DE757000000000711010"
    check validateIban(cfg.iban).contains("checksum failed")
    removeDir(dir)

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

suite "batch file parsing":
  test "valid rows with header, comments, blank lines":
    let text = ["# monthly run",
                "name\tiban\tamount\treference",
                "",
                "Erika Musterfrau\tde75 5121 0800 1245 1261 99\t100,50\tInvoice 1",
                "Bob\tDE02120300000000202051\t10\t"].join("\n")
    let f = parseBatchFile(text)
    check f.err == ""
    check f.rows.len == 2
    check f.rows[0].name == "Erika Musterfrau"
    check f.rows[0].iban == "DE75512108001245126199"  # normalized
    check f.rows[0].cents == 10050
    check f.rows[0].reference == "Invoice 1"
    check f.rows[1].reference == ""
    check f.totalCents == 11050

  test "reference may contain tabs (last field takes the rest)":
    let f = parseBatchFile("Bob\tDE02120300000000202051\t10\ta\tb")
    check f.err == ""
    check f.rows[0].reference == "a\tb"

  test "bad iban fails with line number":
    let f = parseBatchFile("A\tDE02120300000000202051\t1\t\nB\tDE99\t2\t")
    check f.err.startsWith("line 2: invalid iban")

  test "bad amount fails with line number":
    let f = parseBatchFile("A\tDE02120300000000202051\t1.000\t")
    check f.err.startsWith("line 1: ")
    check "ambiguous" in f.err

  test "too few fields fails":
    let f = parseBatchFile("Just A Name\tDE02120300000000202051")
    check f.err == "line 1: expected NAME, IBAN, AMOUNT[, REFERENCE]"

  test "non-positive amount fails":
    let f = parseBatchFile("A\tDE02120300000000202051\t0\t")
    check f.err == "line 1: amount must be greater than 0"

  test "oversized reference fails":
    let f = parseBatchFile("A\tDE02120300000000202051\t1\t" & repeat('x', 141))
    check "reference longer than 140" in f.err

  test "empty file has no payments":
    let f = parseBatchFile("# nothing\n")
    check f.err == ""
    check f.rows.len == 0

suite "output field escaping":
  test "tab-separated replaces separator":
    check escapeField("a\tb", '\t', "") == "a  b"

  test "quoted keeps separator":
    check escapeField("a\tb", '\t', "\"") == "\"a\tb\""

  test "newlines flattened":
    check escapeField("a\nb", '|', "") == "a b"
