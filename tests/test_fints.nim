## Tests for FinTS library

import std/[unittest, strutils]
import ../src/payf/fints

suite "FinTS message building":
  test "SEPA pain.001 generation":
    let account = Account(
      iban: "DE89370400440532013000",
      bic: "COBADEFFXXX",
      holder: "Max Mustermann",
      blz: "37040044"
    )

    let transfer = TransferRequest(
      recipientName: "Erika Musterfrau",
      recipientIban: "DE75512108001245126199",
      recipientBic: "SOLADEST600",
      amount: 100.50,
      currency: "EUR",
      reference: "Invoice 12345",
      instant: true
    )

    let messageId = "TEST123456"
    let xml = generatePain001(transfer, account, messageId)

    check xml.contains("pain.001.001.09")
    check xml.contains("DE89370400440532013000")
    check xml.contains("DE75512108001245126199")
    check xml.contains("100.50")  # XML uses dot format
    check xml.contains("INST")  # Instant payment marker
    check xml.contains("Invoice 12345")

  test "non-instant transfer omits INST":
    let account = Account(
      iban: "DE89370400440532013000",
      bic: "COBADEFFXXX",
      holder: "Test",
      blz: "37040044"
    )

    let transfer = TransferRequest(
      recipientName: "Test",
      recipientIban: "DE75512108001245126199",
      recipientBic: "SOLADEST600",
      amount: 10.00,
      currency: "EUR",
      reference: "Test",
      instant: false  # Not instant
    )

    let xml = generatePain001(transfer, account, "TEST")
    check not xml.contains("<Cd>INST</Cd>")

suite "FinTS data escaping":
  test "escape special characters":
    check escapeFintsData("Hello+World") == "Hello?+World"
    check escapeFintsData("A:B:C") == "A?:B?:C"
    check escapeFintsData("Test'End") == "Test?'End"
    check escapeFintsData("100@200") == "100?@200"
    check escapeFintsData("??") == "????"

  test "unescape data":
    check unescapeFintsData("Hello?+World") == "Hello+World"
    check unescapeFintsData("A?:B?:C") == "A:B:C"
    check unescapeFintsData("????") == "??"

suite "Amount formatting":
  test "German decimal format":
    check formatAmount(100.50) == "100,50"
    check formatAmount(1000.00) == "1000,00"
    check formatAmount(0.01) == "0,01"
    check formatAmount(99999.99) == "99999,99"

suite "MT940 parsing":
  test "parse simple MT940 statement":
    let mt940 = """
:20:STARTUM
:25:37040044/0532013000
:28C:00001
:60F:C240101EUR1000,00
:61:2401020102D50,00NTRFNONREF//AUXREF
:86:?00ÜBERWEISUNG?20Test Reference?30COBADEFFXXX?31DE75512108001245126199?32Erika Musterfrau
:62F:C240102EUR950,00
"""
    let txs = parseMT940(mt940)
    check txs.len == 1
    check txs[0].amount == -50.0  # Debit
    check txs[0].currency == "EUR"
    check txs[0].valutaDate == "20240102"
    check txs[0].date == "20240102"
    check txs[0].name == "Erika Musterfrau"
    check txs[0].iban == "DE75512108001245126199"
    check txs[0].bic == "COBADEFFXXX"
    check txs[0].bookingText == "ÜBERWEISUNG"
    check "Test Reference" in txs[0].reference

  test "parse credit transaction":
    let mt940 = """
:60F:C240101EUR1000,00
:61:240103C200,00NTRFNONREF
:86:?00GUTSCHRIFT?20Payment received?32Max Mustermann
:62F:C240103EUR1200,00
"""
    let txs = parseMT940(mt940)
    check txs.len == 1
    check txs[0].amount == 200.0  # Credit (positive)

  test "parse multiple transactions":
    let mt940 = """
:60F:C240101EUR1000,00
:61:240102D100,00NTRFNONREF
:86:?00LASTSCHRIFT?32Company A
:61:240103C50,00NTRFNONREF
:86:?00GUTSCHRIFT?32Company B
:61:240104D25,50NTRFNONREF
:86:?00ÜBERWEISUNG?32Company C
:62F:C240104EUR924,50
"""
    let txs = parseMT940(mt940)
    check txs.len == 3
    check txs[0].amount == -100.0
    check txs[1].amount == 50.0
    check txs[2].amount == -25.5

  test "parse end-to-end reference":
    let mt940 = """
:60F:C240101EUR1000,00
:61:240102D50,00NTRFNONREF
:86:?00SEPA?20EREF+E2E123456789?21KREF+CUST123?32Someone
:62F:C240102EUR950,00
"""
    let txs = parseMT940(mt940)
    check txs.len == 1
    check txs[0].endToEndId == "E2E123456789"

when isMainModule:
  discard
