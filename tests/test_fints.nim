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
    check xml.contains("100,50")
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

when isMainModule:
  discard
