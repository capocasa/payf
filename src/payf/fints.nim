## FinTS 3.0 library for SEPA instant transfers
##
## Implements the minimal subset needed for HKIPZ (Einzelne SEPA-Instant-Überweisung)
## Reference: FinTS 3.0 specification and python-fints

import std/[httpclient, base64, strutils, strformat, times, random, os]
import std/net

const
  FintsVersion* = "300"
  HbciVersion* = 300
  ProductId* = "5D8519C8F4024026D066D6661"  # Registered FinTS product ID

type
  FintsError* = object of CatchableError

  TanMethod* = object
    id*: string
    name*: string
    version*: int
    processType*: int  # 1=one-step, 2=two-step, 4=decoupled

  BankParams* = object
    bpdVersion*: int
    updVersion*: int
    supportedTanMethods*: seq[TanMethod]
    supportsInstantPayment*: bool

  Account* = object
    iban*: string
    bic*: string
    number*: string
    subaccount*: string
    blz*: string
    holder*: string

  FintsClient* = object
    url*: string
    blz*: string
    user*: string
    pin*: string
    productId*: string
    productVersion*: string
    account*: Account
    dialogId*: string
    msgNum*: int
    systemId*: string
    bankParams*: BankParams
    selectedTanMethod*: string
    hktanVersion*: int  # HKTAN segment version (6 or 7)
    hkkazVersion*: int  # HKKAZ segment version (5, 6, or 7)
    hicazVersion*: int  # HICAZ segment version (1 or 2)
    hicazCamtUrn*: string  # camt URN for HICAZ (e.g., urn:iso:std:iso:20022:tech:xsd:camt.052.001.08)
    vopReportFormat*: string  # VoP report format from HIVPPS
    vopRequired*: bool  # Whether VoP is required for transfers
    debug*: bool
    http: HttpClient

  TransferRequest* = object
    recipientName*: string
    recipientIban*: string
    recipientBic*: string
    amount*: float
    currency*: string
    reference*: string
    instant*: bool

  TransferResult* = object
    success*: bool
    tanRequired*: bool
    tanChallenge*: string
    tanMediaName*: string
    orderRef*: string
    errorCode*: string
    errorMsg*: string

  Transaction* = object
    date*: string           # Booking date (YYYYMMDD)
    valutaDate*: string     # Value date (YYYYMMDD)
    amount*: float          # Positive = credit, negative = debit
    currency*: string
    name*: string           # Counterparty name
    iban*: string           # Counterparty IBAN
    bic*: string            # Counterparty BIC
    reference*: string      # Payment reference
    bookingText*: string    # Booking type (e.g. "ÜBERWEISUNG")
    endToEndId*: string     # End-to-end ID

  StatementResult* = object
    success*: bool
    transactions*: seq[Transaction]
    errorCode*: string
    errorMsg*: string
    tanRequired*: bool
    orderRef*: string
    tanChallenge*: string

# Forward declarations
proc buildSegment(name: string, version, num: int, data: seq[string]): string
proc escapeFintsData*(s: string): string
proc parseSegments(msg: string): seq[tuple[name: string, version, num: int, data: seq[string]]]

# --- Utility functions ---

proc generateReference(): string =
  ## Generate a message reference
  let now = now()
  result = now.format("yyyyMMddHHmmss")

proc escapeFintsData*(s: string): string =
  ## Escape special characters in FinTS segment data: ? + : ' @
  result = s
  result = result.replace("?", "??")
  result = result.replace("+", "?+")
  result = result.replace(":", "?:")
  result = result.replace("'", "?'")
  result = result.replace("@", "?@")

proc escapeXml*(s: string): string =
  ## Escape special characters for XML content: & < > " '
  result = s
  result = result.replace("&", "&amp;")
  result = result.replace("<", "&lt;")
  result = result.replace(">", "&gt;")
  result = result.replace("\"", "&quot;")
  result = result.replace("'", "&apos;")

proc unescapeFintsData*(s: string): string =
  ## Unescape FinTS data
  result = ""
  var i = 0
  while i < s.len:
    if i + 1 < s.len and s[i] == '?':
      result.add(s[i + 1])
      i += 2
    else:
      result.add(s[i])
      i += 1

proc extractBinary*(s: string): string =
  ## Extract binary content from @len@data format
  if s.len > 2 and s[0] == '@':
    var lenEnd = 1
    while lenEnd < s.len and s[lenEnd] in '0'..'9':
      lenEnd += 1
    if lenEnd < s.len and s[lenEnd] == '@':
      return s[lenEnd + 1 .. ^1]
  return s

proc formatAmount*(amount: float): string =
  ## Format amount with comma decimal separator (German format)
  let parts = ($amount).split('.')
  if parts.len == 2:
    result = parts[0] & "," & parts[1].alignLeft(2, '0')[0..1]
  else:
    result = parts[0] & ",00"

# --- Segment building ---

proc buildSegment(name: string, version, num: int, data: seq[string]): string =
  ## Build a FinTS segment, omitting trailing empty fields
  let header = fmt"{name}:{num}:{version}"
  if data.len > 0:
    # Find last non-empty element
    var lastNonEmpty = -1
    for i in countdown(data.len - 1, 0):
      if data[i].len > 0:
        lastNonEmpty = i
        break
    if lastNonEmpty >= 0:
      result = header & "+" & data[0..lastNonEmpty].join("+") & "'"
    else:
      result = header & "'"
  else:
    result = header & "'"

proc buildHNHBK(msgLen: int, dialogId: string, msgNum: int): string =
  ## Message header segment (Nachrichtenkopf)
  ## Format: HNHBK:1:3+msgLen(12)+hbciVersion+dialogId+msgNum'
  let lenStr = align($msgLen, 12, '0')  # 12 digits, zero-padded
  let data = @[
    lenStr,
    $HbciVersion,
    dialogId,
    $msgNum
  ]
  result = buildSegment("HNHBK", 3, 1, data)

proc buildHNHBS(msgNum, segNum: int): string =
  ## Message end segment (Nachrichtenabschluss)
  let data = @[$msgNum]
  result = buildSegment("HNHBS", 1, segNum, data)

proc buildHNVSK(blz, user, systemId: string): string =
  ## Encryption header segment (Verschluesselungskopf) for PIN/TAN
  ## Uses "dummy" encryption - no actual encryption
  let now = now()
  let dateStr = now.format("yyyyMMdd")
  let timeStr = now.format("HHmmss")
  let data = @[
    "PIN:1",                       # Security profile
    "998",                         # Security function (998=PIN/TAN encryption)
    "1",                           # Security role (1=ISS)
    "2::" & systemId,              # Security identification
    "1:" & dateStr & ":" & timeStr, # Security date/time
    "2:2:13:@8@00000000:5:1",      # Encryption algorithm (2-key 3DES, CBC)
    "280:" & blz & ":" & escapeFintsData(user) & ":V:0:0",  # Key name
    "0"                            # Compression (0=none)
  ]
  result = buildSegment("HNVSK", 3, 998, data)

proc buildHNVSD(encryptedData: string): string =
  ## Encrypted data segment (Verschluesselte Daten)
  ## Contains the signed segments as "encrypted" binary data
  result = "HNVSD:999:1+@" & $encryptedData.len & "@" & encryptedData & "'"

proc buildHNSHK(segNum: int, secFunc, secRef: string, blz, user, systemId: string): string =
  ## Security header (Sicherheitskopf) for PIN/TAN
  ## Format based on FinTS 3.0 spec and working implementations
  let escapedUser = escapeFintsData(user)
  let now = now()
  let dateStr = now.format("yyyyMMdd")
  let timeStr = now.format("HHmmss")
  let secData = @[
    "PIN:1",                       # Security profile (PIN version 1)
    secFunc,                       # Security function (999=single step)
    secRef,                        # Security reference
    "1",                           # Security area (1=SHM)
    "1",                           # Security role (1=ISS)
    "2::" & systemId,              # Security identification (2=system ID based)
    "1",                           # Security reference number
    "1:" & dateStr & ":" & timeStr, # Security datetime (1=STS, date, time)
    "1:999:1",                     # Hash algorithm
    "6:10:16",                     # Signature algorithm
    "280:" & blz & ":" & escapedUser & ":S:0:0"  # Key name (280=Germany)
  ]
  result = buildSegment("HNSHK", 4, segNum, secData)

proc buildHNSHA(segNum, hnshkRef: int, pin: string, tanValue: string = ""): string =
  ## Security footer (Sicherheitsabschluss)
  ## PIN must be escaped for FinTS special chars
  var authData = escapeFintsData(pin)
  if tanValue.len > 0:
    authData = authData & ":" & escapeFintsData(tanValue)

  let data = @[
    $hnshkRef,
    "",
    authData
  ]
  result = buildSegment("HNSHA", 2, segNum, data)

proc buildHKIDN(segNum: int, blz, customerId, systemId: string): string =
  ## Identification segment (Identifikation)
  let data = @[
    "280:" & blz,           # Bank identifier (280=Germany, then BLZ)
    escapeFintsData(customerId),  # Customer ID (user login)
    systemId,               # System ID ("0" for new)
    "1"                     # System ID status (1=ID required)
  ]
  result = buildSegment("HKIDN", 2, segNum, data)

proc buildHKVVB(segNum: int, bpdVersion, updVersion: int, lang: int = 0, productVersion: string = "0.1.0"): string =
  ## Processing preparation segment (Verarbeitungsvorbereitung)
  let data = @[
    bpdVersion.intToStr,
    updVersion.intToStr,
    lang.intToStr,
    ProductId,       # Registered product ID
    productVersion   # Product version
  ]
  result = buildSegment("HKVVB", 3, segNum, data)

proc buildHKTAN(segNum: int, tanProcess: string, segmentType: string = "", orderRef: string = "", tanMediaName: string = "", version: int = 7): string =
  ## TAN process segment
  ## tanProcess: "4" = start, "2" = submit TAN, "S" = check decoupled status
  ## segmentType: for process 4, the segment type needing TAN (e.g., "HKIDN")
  var data: seq[string]
  case tanProcess
  of "4":  # Start TAN process
    data = @[tanProcess, segmentType, "", "", "", "", "", "", "", "", tanMediaName]
  of "2":  # Submit TAN
    data = @[tanProcess, "", "", "", escapeFintsData(orderRef)]
  of "S":  # Check decoupled status
    data = @[tanProcess, "", "", "", escapeFintsData(orderRef), "N"]
  else:
    data = @[tanProcess]
  result = buildSegment("HKTAN", version, segNum, data)

proc buildHKVPP(segNum: int, reportFormat: string, pollingId: string = "", offset: string = ""): string =
  ## VoP name check request (Namensabgleich Prüfauftrag)
  ## HKVPP1 fields: supported_reports, polling_id, max_queries, offset
  if pollingId.len > 0 or offset.len > 0:
    let pidField = if pollingId.len > 0: "@" & $pollingId.len & "@" & pollingId else: ""
    let offField = if offset.len > 0: escapeFintsData(offset) else: ""
    let data = @[escapeFintsData(reportFormat), pidField, "", offField]
    result = buildSegment("HKVPP", 1, segNum, data)
  else:
    let data = @[escapeFintsData(reportFormat)]
    result = buildSegment("HKVPP", 1, segNum, data)

proc buildHKVPA(segNum: int, vopId: string): string =
  ## VoP approval (Namensabgleich Ausführungsauftrag)
  let data = @["@" & $vopId.len & "@" & vopId]
  result = buildSegment("HKVPA", 1, segNum, data)

proc buildHKEND(segNum: int, dialogId: string): string =
  ## Dialog end segment
  let data = @[dialogId]
  result = buildSegment("HKEND", 1, segNum, data)

proc deriveAccountNumber(iban: string): string =
  ## Derive account number from German IBAN
  ## German IBAN: DE + 2 check digits + 8 digit BLZ + 10 digit account number
  if iban.len >= 22 and iban.startsWith("DE"):
    result = iban[12..21]  # Last 10 digits
    # Strip leading zeros
    while result.len > 1 and result[0] == '0':
      result = result[1..^1]
  else:
    result = ""

proc buildHKKAZ(segNum: int, account: Account, fromDate, toDate: string, offset: string = "", version: int = 7): string =
  ## Build HKKAZ segment (Kontoumsätze) for fetching account statements
  ## fromDate/toDate format: YYYYMMDD
  var data: seq[string]

  # Derive account number from IBAN if not provided
  let accountNum = if account.number.len > 0: account.number else: deriveAccountNumber(account.iban)
  let subaccount = account.subaccount  # Usually empty

  if version >= 7:
    # HKKAZ version 7: KTI format (just IBAN:BIC)
    var kti = account.iban
    if account.bic.len > 0:
      kti.add(":" & account.bic)
    data = @[kti, "N", fromDate, toDate]
  elif version == 6:
    # HKKAZ version 6: KTV format (IBAN:BIC:account:subaccount:280:blz)
    var ktv = account.iban
    if account.bic.len > 0:
      ktv.add(":" & account.bic)
    ktv.add(":" & accountNum & ":" & subaccount & ":280:" & account.blz)
    data = @[ktv, "N", fromDate, toDate]
  else:
    # HKKAZ version 5 and below: KTO format (account:subaccount:country:blz)
    let kto = accountNum & ":" & subaccount & ":280:" & account.blz
    data = @[kto, "N", fromDate, toDate]
  if offset.len > 0:
    data.add(offset)
  result = buildSegment("HKKAZ", version, segNum, data)

proc buildHKCAZ(segNum: int, account: Account, fromDate, toDate: string, camtUrn: string, offset: string = "", version: int = 1): string =
  ## Build HKCAZ segment (CAMT-Kontoumsätze) for fetching account statements in camt format
  ## fromDate/toDate format: YYYYMMDD
  var kti = account.iban
  if account.bic.len > 0:
    kti.add(":" & account.bic)
  var data = @[kti, camtUrn, "N", fromDate, toDate]
  if offset.len > 0:
    data.add(offset)
  result = buildSegment("HKCAZ", version, segNum, data)

# --- SEPA XML generation ---

proc formatAmountXml*(amount: float): string =
  ## Format amount with dot decimal separator for pain.001 XML
  let parts = ($amount).split('.')
  if parts.len == 2:
    result = parts[0] & "." & parts[1].alignLeft(2, '0')[0..1]
  else:
    result = parts[0] & ".00"

proc generatePain001*(transfer: TransferRequest, debtor: Account, messageId: string): string =
  ## Generate pain.001.001.09 XML for SEPA instant transfer
  let amountStr = formatAmountXml(transfer.amount)
  let now = now()
  let creationDate = now.format("yyyy-MM-dd'T'HH:mm:ss")
  let requestedDate = if transfer.instant: "1999-01-01" else: now.format("yyyy-MM-dd")

  result = """<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.09" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <CstmrCdtTrfInitn>
    <GrpHdr>
      <MsgId>""" & messageId & """</MsgId>
      <CreDtTm>""" & creationDate & """</CreDtTm>
      <NbOfTxs>1</NbOfTxs>
      <CtrlSum>""" & amountStr & """</CtrlSum>
      <InitgPty>
        <Nm>""" & escapeXml(debtor.holder) & """</Nm>
      </InitgPty>
    </GrpHdr>
    <PmtInf>
      <PmtInfId>""" & messageId & """-1</PmtInfId>
      <PmtMtd>TRF</PmtMtd>
      <BtchBookg>true</BtchBookg>
      <NbOfTxs>1</NbOfTxs>
      <CtrlSum>""" & amountStr & """</CtrlSum>
      <PmtTpInf>
        <SvcLvl>
          <Cd>SEPA</Cd>
        </SvcLvl>"""

  # Add instant payment local instrument if requested
  if transfer.instant:
    result.add """
        <LclInstrm>
          <Cd>INST</Cd>
        </LclInstrm>"""

  result.add """
      </PmtTpInf>
      <ReqdExctnDt>
        <Dt>""" & requestedDate & """</Dt>
      </ReqdExctnDt>
      <Dbtr>
        <Nm>""" & escapeXml(debtor.holder) & """</Nm>
      </Dbtr>
      <DbtrAcct>
        <Id>
          <IBAN>""" & debtor.iban & """</IBAN>
        </Id>
      </DbtrAcct>
      <DbtrAgt>
        <FinInstnId>
          <BICFI>""" & debtor.bic & """</BICFI>
        </FinInstnId>
      </DbtrAgt>
      <ChrgBr>SLEV</ChrgBr>
      <CdtTrfTxInf>
        <PmtId>
          <EndToEndId>""" & messageId & """</EndToEndId>
        </PmtId>
        <Amt>
          <InstdAmt Ccy='""" & transfer.currency & """'>""" & amountStr & """</InstdAmt>
        </Amt>"""

  if transfer.recipientBic.len > 0:
    result.add """
        <CdtrAgt>
          <FinInstnId>
            <BICFI>""" & transfer.recipientBic & """</BICFI>
          </FinInstnId>
        </CdtrAgt>"""

  result.add """
        <Cdtr>
          <Nm>""" & escapeXml(transfer.recipientName) & """</Nm>
        </Cdtr>
        <CdtrAcct>
          <Id>
            <IBAN>""" & transfer.recipientIban & """</IBAN>
          </Id>
        </CdtrAcct>
        <RmtInf>
          <Ustrd>""" & escapeXml(transfer.reference) & """</Ustrd>
        </RmtInf>
      </CdtTrfTxInf>
    </PmtInf>
  </CstmrCdtTrfInitn>
</Document>"""

proc buildHKIPZFromPain(segNum: int, account: Account, pain: string): string =
  ## Build HKIPZ segment from pre-generated pain.001 XML
  let kti = account.iban & ":" & account.bic
  let data = @[
    kti,
    "urn?:iso?:std?:iso?:20022?:tech?:xsd?:pain.001.001.09",
    "@" & $pain.len & "@" & pain
  ]
  result = buildSegment("HKIPZ", 1, segNum, data)

proc buildHKIPZ(segNum: int, account: Account, transfer: TransferRequest, debug: bool = false): string =
  ## Build HKIPZ segment (Einzelne SEPA-Instant-Überweisung)
  let messageId = generateReference()
  let pain = generatePain001(transfer, account, messageId)
  if debug:
    stderr.writeLine "[DEBUG] pain.001 XML:\n" & pain
  result = buildHKIPZFromPain(segNum, account, pain)

proc buildHKCCS(segNum: int, account: Account, transfer: TransferRequest): string =
  ## Build HKCCS segment (Einzelne SEPA-Überweisung) - standard non-instant
  let messageId = generateReference()
  let pain = generatePain001(transfer, account, messageId)

  let kti = account.iban & ":" & account.bic

  let data = @[
    kti,
    "urn?:iso?:std?:iso?:20022?:tech?:xsd?:pain.001.001.09",
    "@" & $pain.len & "@" & pain
  ]
  result = buildSegment("HKCCS", 1, segNum, data)

# --- Segment parsing ---

proc parseSegments(msg: string): seq[tuple[name: string, version, num: int, data: seq[string]]] =
  ## Parse FinTS message into segments
  result = @[]
  var pos = 0
  var segmentStart = 0
  var inBinary = false
  var binaryLen = 0
  var binaryCount = 0

  while pos < msg.len:
    if inBinary:
      binaryCount += 1
      if binaryCount >= binaryLen:
        inBinary = false
      pos += 1
      continue

    # Check for binary data marker @123@
    if msg[pos] == '@' and not inBinary:
      var numEnd = pos + 1
      while numEnd < msg.len and msg[numEnd] in '0'..'9':
        numEnd += 1
      if numEnd > pos + 1 and numEnd < msg.len and msg[numEnd] == '@':
        binaryLen = parseInt(msg[pos+1 ..< numEnd])
        pos = numEnd + 1
        inBinary = true
        binaryCount = 0
        continue

    # Check for segment end (unescaped ')
    if msg[pos] == '\'' and (pos == 0 or msg[pos-1] != '?'):
      let segment = msg[segmentStart .. pos - 1]
      if segment.len > 0:
        # Parse segment header: NAME:num:version+data or NAME:num:version:ref+data
        let colonPos = segment.find(':')
        if colonPos > 0:
          let name = segment[0 ..< colonPos]
          # Find segment number, version, and optional ref
          var rest = segment[colonPos + 1 .. ^1]
          let colonPos2 = rest.find(':')
          if colonPos2 > 0:
            let num = try: parseInt(rest[0 ..< colonPos2]) except: 0
            rest = rest[colonPos2 + 1 .. ^1]
            # Version might be followed by :ref or +data
            let plusPos = rest.find('+')
            let colonPos3 = rest.find(':')
            var version: int
            var dataStr: string
            if colonPos3 > 0 and (plusPos < 0 or colonPos3 < plusPos):
              # Format: version:ref+data or version:ref
              version = try: parseInt(rest[0 ..< colonPos3]) except: 0
              let afterRef = rest[colonPos3 + 1 .. ^1]
              let plusPos2 = afterRef.find('+')
              if plusPos2 > 0:
                dataStr = afterRef[plusPos2 + 1 .. ^1]
              else:
                dataStr = ""
            elif plusPos > 0:
              version = try: parseInt(rest[0 ..< plusPos]) except: 0
              dataStr = rest[plusPos + 1 .. ^1]
            else:
              version = try: parseInt(rest) except: 0
              dataStr = ""

            # Split data by + (respecting escapes and binary blocks)
            var data: seq[string] = @[]
            if dataStr.len > 0:
              var current = ""
              var i = 0
              while i < dataStr.len:
                # Check for binary data marker @len@
                if dataStr[i] == '@':
                  var numEnd = i + 1
                  while numEnd < dataStr.len and dataStr[numEnd] in '0'..'9':
                    numEnd += 1
                  if numEnd > i + 1 and numEnd < dataStr.len and dataStr[numEnd] == '@':
                    let binLen = parseInt(dataStr[i+1 ..< numEnd])
                    let binEnd = min(numEnd + 1 + binLen, dataStr.len)
                    current.add(dataStr[i ..< binEnd])
                    i = binEnd
                    continue
                if dataStr[i] == '?' and i + 1 < dataStr.len:
                  current.add(dataStr[i + 1])
                  i += 2
                elif dataStr[i] == '+':
                  data.add(current)
                  current = ""
                  i += 1
                else:
                  current.add(dataStr[i])
                  i += 1
              data.add(current)

            result.add((name: name, version: version, num: num, data: data))

      segmentStart = pos + 1

    pos += 1

proc findSegment(segments: seq[tuple[name: string, version, num: int, data: seq[string]]], name: string): int =
  ## Find segment index by name, returns -1 if not found
  for i, seg in segments:
    if seg.name == name:
      return i
  return -1

proc extractHNVSDContent(msg: string): string =
  ## Extract the inner content from HNVSD segment directly from raw message
  ## HNVSD format: HNVSD:999:1+@length@<content>'
  let hnvsdPos = msg.find("HNVSD:999:1+@")
  if hnvsdPos < 0:
    return ""

  # Find the length prefix
  var lenStart = hnvsdPos + 13  # after "HNVSD:999:1+@"
  var lenEnd = lenStart
  while lenEnd < msg.len and msg[lenEnd] in '0'..'9':
    lenEnd += 1

  if lenEnd >= msg.len or msg[lenEnd] != '@':
    return ""

  let contentLen = try: parseInt(msg[lenStart ..< lenEnd]) except: return ""
  let contentStart = lenEnd + 1

  if contentStart + contentLen > msg.len:
    return ""

  return msg[contentStart ..< contentStart + contentLen]

proc parseAllSegments(msg: string): seq[tuple[name: string, version, num: int, data: seq[string]]] =
  ## Parse FinTS message including inner HNVSD content
  let outerSegments = parseSegments(msg)
  let innerContent = extractHNVSDContent(msg)
  if innerContent.len > 0:
    # Parse inner segments and combine with outer
    let innerSegments = parseSegments(innerContent)
    result = outerSegments & innerSegments
  else:
    result = outerSegments

# --- MT940 parsing ---

proc parseMT940Date(s: string): string =
  ## Parse MT940 date (YYMMDD) to YYYYMMDD
  if s.len >= 6:
    let yy = s[0..1]
    let year = if yy.parseInt >= 80: "19" & yy else: "20" & yy
    result = year & s[2..5]
  else:
    result = s

proc parseMT940Amount(s: string): float =
  ## Parse MT940 amount (with comma decimal separator)
  result = parseFloat(s.replace(",", "."))

proc parseMT940*(data: string): seq[Transaction] =
  ## Parse MT940 SWIFT message format into transactions
  result = @[]
  var currentTx: Transaction
  var inTx = false
  var multiLineRef = ""

  let lines = data.replace("\r\n", "\n").split('\n')
  var i = 0
  while i < lines.len:
    let line = lines[i]

    # :60F: or :60M: Opening balance - contains currency
    # Format: C/D + YYMMDD + CCY + amount (e.g., C240101EUR1000,00)
    if line.startsWith(":60F:") or line.startsWith(":60M:"):
      let content = line[5..^1]
      if content.len >= 10:
        currentTx.currency = content[7..9]

    # :61: Transaction line
    if line.startsWith(":61:"):
      if inTx:
        result.add(currentTx)
      currentTx = Transaction(currency: currentTx.currency)
      inTx = true
      multiLineRef = ""

      let content = line[4..^1]
      # Format: YYMMDD[YYMMDD]CD[R]amount[N...]//[ref]
      # Valuta date: first 6 chars
      if content.len >= 6:
        currentTx.valutaDate = parseMT940Date(content[0..5])
      # Booking date: next 4 chars (MMDD) if present
      var pos = 6
      if content.len > pos + 4 and content[pos] in '0'..'9':
        let mmdd = content[pos..pos+3]
        currentTx.date = currentTx.valutaDate[0..3] & mmdd
        pos += 4
      else:
        currentTx.date = currentTx.valutaDate

      # Credit/Debit indicator + optional R (reversal)
      if pos < content.len:
        let cd = content[pos]
        pos += 1
        if pos < content.len and content[pos] == 'R':
          pos += 1
        # Amount until N or /
        var amountStr = ""
        while pos < content.len and content[pos] notin {'N', '/'}:
          amountStr.add(content[pos])
          pos += 1
        if amountStr.len > 0:
          currentTx.amount = parseMT940Amount(amountStr)
          if cd == 'D':
            currentTx.amount = -currentTx.amount

    # :86: Details (multiple fields with separators)
    if line.startsWith(":86:"):
      let content = line[4..^1]
      # Collect continuation lines
      var fullContent = content
      while i + 1 < lines.len and not lines[i+1].startsWith(":"):
        i += 1
        fullContent.add(lines[i])

      # Parse structured format with ?XX fields
      if "?" in fullContent:
        var fields: array[100, string]
        var currentField = -1
        var j = 0
        while j < fullContent.len:
          if j + 2 < fullContent.len and fullContent[j] == '?':
            let fieldNum = try: parseInt(fullContent[j+1..j+2]) except: -1
            if fieldNum >= 0:
              currentField = fieldNum
              j += 3
              continue
          if currentField >= 0 and currentField < 100:
            fields[currentField].add(fullContent[j])
          j += 1

        # ?00 = booking text
        currentTx.bookingText = fields[0]
        # ?20-?29 = reference (Verwendungszweck)
        for k in 20..29:
          if fields[k].len > 0:
            if currentTx.reference.len > 0:
              currentTx.reference.add(" ")
            currentTx.reference.add(fields[k])
        # ?30 = BIC
        currentTx.bic = fields[30]
        # ?31 = IBAN (or account number)
        currentTx.iban = fields[31]
        # ?32-?33 = counterparty name
        currentTx.name = fields[32]
        if fields[33].len > 0:
          currentTx.name.add(" " & fields[33])
        # EREF+ in reference contains end-to-end ID
        let erefPos = currentTx.reference.find("EREF+")
        if erefPos >= 0:
          let afterEref = currentTx.reference[erefPos+5 .. ^1]
          # End-to-end ID ends at next + or space or end of string
          var endPos = afterEref.len
          for terminator in ["+", " "]:
            let pos = afterEref.find(terminator)
            if pos >= 0 and pos < endPos:
              endPos = pos
          currentTx.endToEndId = afterEref[0 ..< endPos]
      else:
        # Unstructured format - use as reference
        currentTx.reference = fullContent

    i += 1

  if inTx:
    result.add(currentTx)

# --- camt.052/053 parsing ---

proc extractXmlTag(xml: string, tag: string): string =
  ## Extract content between <tag> and </tag>
  let startTag = "<" & tag & ">"
  let endTag = "</" & tag & ">"
  let startPos = xml.find(startTag)
  if startPos < 0:
    return ""
  let contentStart = startPos + startTag.len
  let endPos = xml.find(endTag, contentStart)
  if endPos < 0:
    return ""
  return xml[contentStart ..< endPos]

proc extractXmlTagWithNs(xml: string, tag: string): string =
  ## Extract content, handling namespace prefixes like <ns:tag>
  # Try without namespace first
  result = extractXmlTag(xml, tag)
  if result.len > 0:
    return
  # Try to find tag with any namespace prefix
  let tagStart = "<"
  var pos = 0
  while pos < xml.len:
    let nextTag = xml.find(tagStart, pos)
    if nextTag < 0:
      break
    let tagEnd = xml.find(">", nextTag)
    if tagEnd < 0:
      break
    let fullTag = xml[nextTag+1 ..< tagEnd]
    # Check if this tag ends with :tagname or is just tagname
    if fullTag == tag or fullTag.endsWith(":" & tag):
      let closeTag = "</" & fullTag & ">"
      let contentStart = tagEnd + 1
      let closePos = xml.find(closeTag, contentStart)
      if closePos > 0:
        return xml[contentStart ..< closePos]
    pos = tagEnd + 1
  return ""

proc parseCamtAmount(s: string): float =
  ## Parse camt amount (uses dot decimal separator)
  try:
    result = parseFloat(s)
  except:
    result = 0.0

proc parseCamtDate(s: string): string =
  ## Parse camt date (YYYY-MM-DD) to YYYYMMDD
  result = s.replace("-", "")

proc parseCamt*(xml: string): seq[Transaction] =
  ## Parse camt.052/053 XML into transactions
  ## Handles both camt.052 (intraday) and camt.053 (end of day)
  result = @[]

  # Find all Ntry (entry) elements
  var pos = 0
  while pos < xml.len:
    let ntryStart = xml.find("<Ntry>", pos)
    if ntryStart < 0:
      # Try with namespace
      let nsNtryStart = xml.find(":Ntry>", pos)
      if nsNtryStart < 0:
        break
      pos = nsNtryStart
      continue

    # Find end of this Ntry
    let ntryEnd = xml.find("</Ntry>", ntryStart)
    if ntryEnd < 0:
      break

    let ntry = xml[ntryStart ..< ntryEnd + 7]
    var tx = Transaction()

    # Amount: <Amt Ccy="EUR">123.45</Amt>
    let amtStart = ntry.find("<Amt")
    if amtStart >= 0:
      let ccyStart = ntry.find("Ccy=\"", amtStart)
      if ccyStart >= 0:
        let ccyEnd = ntry.find("\"", ccyStart + 5)
        if ccyEnd > ccyStart:
          tx.currency = ntry[ccyStart + 5 ..< ccyEnd]
      let amtContentStart = ntry.find(">", amtStart) + 1
      let amtEnd = ntry.find("</Amt>", amtContentStart)
      if amtEnd > amtContentStart:
        tx.amount = parseCamtAmount(ntry[amtContentStart ..< amtEnd])

    # Credit/Debit: <CdtDbtInd>CRDT</CdtDbtInd> or DBIT
    let cdtDbt = extractXmlTag(ntry, "CdtDbtInd")
    if cdtDbt == "DBIT":
      tx.amount = -tx.amount

    # Booking date: <BookgDt><Dt>2024-01-15</Dt></BookgDt>
    let bookgDt = extractXmlTag(ntry, "BookgDt")
    if bookgDt.len > 0:
      tx.date = parseCamtDate(extractXmlTag(bookgDt, "Dt"))

    # Value date: <ValDt><Dt>2024-01-15</Dt></ValDt>
    let valDt = extractXmlTag(ntry, "ValDt")
    if valDt.len > 0:
      tx.valutaDate = parseCamtDate(extractXmlTag(valDt, "Dt"))
    if tx.valutaDate.len == 0:
      tx.valutaDate = tx.date

    # Bank transaction code / booking text
    let domn = extractXmlTag(ntry, "Domn")
    if domn.len > 0:
      tx.bookingText = extractXmlTag(domn, "Cd")

    # Entry details
    let ntryDtls = extractXmlTag(ntry, "NtryDtls")
    if ntryDtls.len > 0:
      let txDtls = extractXmlTag(ntryDtls, "TxDtls")
      if txDtls.len > 0:
        # Related parties
        let rltdPties = extractXmlTag(txDtls, "RltdPties")
        if rltdPties.len > 0:
          # Creditor or Debtor name
          let cdtr = extractXmlTag(rltdPties, "Cdtr")
          let dbtr = extractXmlTag(rltdPties, "Dbtr")
          let party = if cdtr.len > 0: cdtr else: dbtr
          if party.len > 0:
            tx.name = extractXmlTag(party, "Nm")
          # Creditor or Debtor account
          let cdtrAcct = extractXmlTag(rltdPties, "CdtrAcct")
          let dbtrAcct = extractXmlTag(rltdPties, "DbtrAcct")
          let acct = if cdtrAcct.len > 0: cdtrAcct else: dbtrAcct
          if acct.len > 0:
            let id = extractXmlTag(acct, "Id")
            tx.iban = extractXmlTag(id, "IBAN")

        # Related agents (BIC)
        let rltdAgts = extractXmlTag(txDtls, "RltdAgts")
        if rltdAgts.len > 0:
          let cdtrAgt = extractXmlTag(rltdAgts, "CdtrAgt")
          let dbtrAgt = extractXmlTag(rltdAgts, "DbtrAgt")
          let agt = if cdtrAgt.len > 0: cdtrAgt else: dbtrAgt
          if agt.len > 0:
            let finInstnId = extractXmlTag(agt, "FinInstnId")
            tx.bic = extractXmlTag(finInstnId, "BICFI")
            if tx.bic.len == 0:
              tx.bic = extractXmlTag(finInstnId, "BIC")

        # Remittance info (reference)
        let rmtInf = extractXmlTag(txDtls, "RmtInf")
        if rmtInf.len > 0:
          tx.reference = extractXmlTag(rmtInf, "Ustrd")

        # End-to-end ID
        let refs = extractXmlTag(txDtls, "Refs")
        if refs.len > 0:
          tx.endToEndId = extractXmlTag(refs, "EndToEndId")

    if tx.date.len > 0 or tx.amount != 0:
      result.add(tx)

    pos = ntryEnd + 7

# --- Client implementation ---

proc newFintsClient*(url, blz, user, pin: string, productVersion: string = "0.1.0"): FintsClient =
  ## Create a new FinTS client
  result = FintsClient(
    url: url,
    blz: blz,
    user: user,
    pin: pin,
    productId: ProductId,
    productVersion: productVersion,
    dialogId: "0",
    msgNum: 0,
    systemId: "0",
    http: newHttpClient(sslContext = newContext(verifyMode = CVerifyPeer))
  )
  result.http.headers = newHttpHeaders({"Content-Type": "text/plain"})

proc close*(client: var FintsClient) =
  ## Close the HTTP client
  client.http.close()

proc reconnect*(client: var FintsClient) =
  ## Recreate HTTP client (needed after bank closes connection)
  client.http.close()
  client.http = newHttpClient(sslContext = newContext(verifyMode = CVerifyPeer))
  client.http.headers = newHttpHeaders({"Content-Type": "text/plain"})

proc sendMessage(client: var FintsClient, segments: string, lastSegNum: int): string =
  ## Send FinTS message and return response
  ## segments should contain HNSHK...HNSHA (signed content)
  ## lastSegNum is the segment number of the last inner segment
  client.msgNum += 1

  # Build encryption wrapper
  let hnvsk = buildHNVSK(client.blz, client.user, client.systemId)
  let hnvsd = buildHNVSD(segments)

  # Calculate message length
  # Structure: HNHBK + HNVSK + HNVSD + HNHBS
  let innerContent = hnvsk & hnvsd
  var msg = buildHNHBK(0, client.dialogId, client.msgNum)
  let headerLen = msg.len
  let hnhbs = buildHNHBS(client.msgNum, lastSegNum + 1)

  # Calculate total length and rebuild
  let totalLen = headerLen + innerContent.len + hnhbs.len
  msg = buildHNHBK(totalLen, client.dialogId, client.msgNum) & innerContent & hnhbs

  # Encode and send
  let encoded = encode(msg)

  if client.debug:
    stderr.writeLine "[DEBUG] Sending to: " & client.url
    stderr.writeLine "[DEBUG] Request: " & msg[0 .. min(500, msg.len - 1)] & "..."

  try:
    let response = client.http.postContent(client.url, body = encoded)
    try:
      # Strip whitespace/newlines — some banks return MIME-style base64
      let cleaned = response.replace("\r", "").replace("\n", "").strip()
      result = decode(cleaned)
    except:
      if client.debug:
        stderr.writeLine "[DEBUG] Raw response (not base64): " & response[0 .. min(500, response.len - 1)]
      raise newException(FintsError, "Invalid base64 response from bank")
    if client.debug:
      stderr.writeLine "[DEBUG] Response: " & result[0 .. min(1000, result.len - 1)] & "..."
  except FintsError:
    raise
  except:
    raise newException(FintsError, "HTTP request failed: " & getCurrentExceptionMsg())

proc parseResponse(de: string): tuple[code: string, refSeg: string, msg: string] =
  ## Parse HIRMG/HIRMS data element: "code:refSeg:message" or "code::message"
  let parts = de.split(':', maxsplit = 2)
  if parts.len >= 1:
    result.code = parts[0]
  if parts.len >= 2:
    result.refSeg = parts[1]
  if parts.len >= 3:
    result.msg = parts[2]

proc initDialog*(client: var FintsClient): bool =
  ## Initialize FinTS dialog (anonymous dialog for BPD/UPD)
  ## Raises FintsError on failure with detailed error message
  client.dialogId = "0"
  client.msgNum = 0

  if client.debug:
    stderr.writeLine "[DEBUG] PIN length: " & $client.pin.len & ", escaped: " & $escapeFintsData(client.pin).len

  # Build init segments
  var segments = ""
  var segNum = 2
  let secRef = $rand(1000000..9999999)
  let secFunc = if client.selectedTanMethod.len > 0: client.selectedTanMethod else: "999"

  # Security header
  segments.add buildHNSHK(segNum, secFunc, secRef, client.blz, client.user, client.systemId)
  segNum += 1

  # Identification
  segments.add buildHKIDN(segNum, client.blz, client.user, client.systemId)
  segNum += 1

  # Processing preparation
  segments.add buildHKVVB(segNum, 0, 0)
  segNum += 1

  # TAN process (only for two-step auth when TAN method is known)
  if client.selectedTanMethod.len > 0:
    segments.add buildHKTAN(segNum, "4", "HKIDN", version = client.hktanVersion)
    segNum += 1

  # Security footer
  segments.add buildHNSHA(segNum, secRef.parseInt, client.pin)

  let response = client.sendMessage(segments, segNum)
  let respSegments = parseAllSegments(response)

  if client.debug:
    stderr.writeLine "[DEBUG] Parsed " & $respSegments.len & " segments"
    for seg in respSegments:
      stderr.writeLine "[DEBUG]   - " & seg.name & ":" & $seg.num & ":" & $seg.version & " (" & $seg.data.len & " data elements)"

  # Check for HIRMG/HIRMS for errors FIRST (before extracting dialog ID)
  var errors: seq[string] = @[]
  for seg in respSegments:
    if seg.name == "HIRMG" or seg.name == "HIRMS":
      for de in seg.data:
        let parsed = parseResponse(de)
        if client.debug:
          stderr.writeLine "[DEBUG] " & seg.name & " response: code=" & parsed.code & " msg=" & parsed.msg
        if parsed.code.len >= 4 and parsed.code[0] == '9':  # Error codes start with 9
          errors.add(parsed.code & ": " & parsed.msg)

  if errors.len > 0:
    raise newException(FintsError, "Dialog initialization failed: " & errors.join("; "))

  # Parse TAN method from HIRMS 3920 response
  for seg in respSegments:
    if seg.name == "HIRMS":
      for de in seg.data:
        let parsed = parseResponse(de)
        if parsed.code == "3920":
          # Format: "Zugelassene TAN-Verfahren für den Benutzer:methodId"
          let parts = parsed.msg.split(':')
          if parts.len >= 2:
            client.selectedTanMethod = parts[^1].strip()
            if client.debug:
              stderr.writeLine "[DEBUG] Selected TAN method: " & client.selectedTanMethod

  # Check for HNHBK to get dialog ID
  let hnhbkIdx = findSegment(respSegments, "HNHBK")
  if hnhbkIdx >= 0 and respSegments[hnhbkIdx].data.len >= 3:
    client.dialogId = respSegments[hnhbkIdx].data[2]
    if client.debug:
      stderr.writeLine "[DEBUG] Dialog ID: " & client.dialogId

  # Parse BPD for supported segments
  for seg in respSegments:
    if seg.name == "HIPINS":  # PIN/TAN info
      discard
    elif seg.name == "HIIPZS":  # SEPA instant payment info
      client.bankParams.supportsInstantPayment = true
      if client.debug:
        stderr.writeLine "[DEBUG] HIIPZS data: " & $seg.data
    elif seg.name == "HISPAS":
      if client.debug:
        stderr.writeLine "[DEBUG] HISPAS data: " & $seg.data
    elif seg.name == "HICCSS":
      if client.debug:
        stderr.writeLine "[DEBUG] HICCSS data: " & $seg.data
    elif seg.name == "HIVPPS":
      if client.debug:
        stderr.writeLine "[DEBUG] HIVPPS data: " & $seg.data
      # Parse VoP parameters - check if HKIPZ/HKCCS requires VoP
      if seg.data.len > 3:
        let paramData = seg.data[3]
        if "HKIPZ" in paramData or "HKCCS" in paramData:
          client.vopRequired = true
          # Extract the full URN for pain.002 report format
          # Format in DEG: "999:J:V:J:J:urn:iso:std:iso:20022:tech:xsd:pain.002.001.10:HKCCS:..."
          # The URN starts with "urn" and ends before the first HK segment code
          let urnStart = paramData.find("urn")
          if urnStart >= 0:
            let afterUrn = paramData[urnStart .. ^1]
            # Find end of URN - it ends before :HK or at end of string
            let hkPos = afterUrn.find(":HK")
            if hkPos > 0:
              client.vopReportFormat = afterUrn[0 ..< hkPos]
            else:
              client.vopReportFormat = afterUrn
          if client.debug:
            stderr.writeLine "[DEBUG] VoP required, report format: " & client.vopReportFormat
    elif seg.name == "HIEKAS":
      # HIEKAS is the BPD parameter segment for HKKAZ (account statements)
      # Store the highest supported version
      if seg.version > client.hkkazVersion:
        client.hkkazVersion = seg.version
        if client.debug:
          stderr.writeLine "[DEBUG] HKKAZ version " & $seg.version & " supported"
    elif seg.name == "HICAZS":
      # HICAZS is the BPD parameter segment for HICAZ (camt statements)
      if seg.version > client.hicazVersion:
        client.hicazVersion = seg.version
        # Extract camt URN from segment data (usually in field 4)
        if seg.data.len > 3:
          let paramData = seg.data[3]
          # URN looks like: urn:iso:std:iso:20022:tech:xsd:camt.052.001.08
          # Note: colons are part of the URN, only terminate on FinTS separators
          let urnStart = paramData.find("urn:")
          if urnStart >= 0:
            var urnEnd = paramData.len
            for ch in ['+', '\'', ' ']:
              let pos = paramData.find(ch, urnStart)
              if pos > 0 and pos < urnEnd:
                urnEnd = pos
            client.hicazCamtUrn = paramData[urnStart ..< urnEnd]
        if client.debug:
          stderr.writeLine "[DEBUG] HICAZ version " & $seg.version & " supported, URN: " & client.hicazCamtUrn
    elif seg.name == "HITANS":
      if client.debug:
        stderr.writeLine "[DEBUG] HITANS version " & $seg.version & " data: " & $seg.data
      # Check if this HITANS version contains the selected TAN method
      if client.selectedTanMethod.len > 0 and seg.data.len > 3:
        if client.selectedTanMethod in seg.data[3]:
          client.hktanVersion = seg.version
          if client.debug:
            stderr.writeLine "[DEBUG] Using HKTAN version " & $seg.version & " for TAN method " & client.selectedTanMethod

  return true

proc endDialog*(client: var FintsClient) =
  ## End FinTS dialog
  if client.dialogId != "0":
    var segments = ""
    var segNum = 2
    let secRef = $rand(1000000..9999999)

    segments.add buildHNSHK(segNum, "999", secRef, client.blz, client.user, client.systemId)
    segNum += 1

    segments.add buildHKEND(segNum, client.dialogId)
    segNum += 1

    segments.add buildHNSHA(segNum, secRef.parseInt, client.pin)

    try:
      discard client.sendMessage(segments, segNum)
    except FintsError:
      discard  # Dialog may already be closed by bank
    client.dialogId = "0"

proc parseHIVPP(seg: tuple[name: string, version, num: int, data: seq[string]], debug: bool): tuple[vopId, pollingId, resultCode, differentName: string, waitSec: int] =
  ## Parse HIVPP response fields
  ## Fields: vopid(0), vopidvalidto(1), pollingid(2), reportdesc(3), report(4), result_DEG(5), infotext(6), wait(7)
  result.waitSec = 2
  if debug:
    stderr.writeLine "[DEBUG] HIVPP: " & $seg.data
  # Field 0: vopId (binary @len@data)
  if seg.data.len > 0 and seg.data[0].len > 0:
    let raw = seg.data[0]
    if raw.startsWith("@"):
      result.vopId = extractBinary(raw)
    else:
      result.vopId = raw
  # Field 2: pollingId (binary @len@data)
  if seg.data.len > 2 and seg.data[2].len > 0:
    let raw = seg.data[2]
    if raw.startsWith("@"):
      result.pollingId = extractBinary(raw)
    else:
      result.pollingId = raw
  # Field 5: result DEG (iban:ibanaddon:differentname:otheridentifier:result_code:reason)
  if seg.data.len > 5 and seg.data[5].len > 0:
    let parts = seg.data[5].split(':')
    if parts.len >= 5:
      result.resultCode = parts[4]
    if parts.len >= 3 and parts[2].len > 0:
      result.differentName = parts[2]
  # Field 7: wait seconds
  if seg.data.len > 7 and seg.data[7].len > 0:
    try:
      result.waitSec = parseInt(seg.data[7])
    except: discard

proc transfer*(client: var FintsClient, request: TransferRequest): TransferResult =
  ## Execute SEPA transfer (instant or standard)
  ## Implements the correct VoP flow: Check → Poll → Auth
  result = TransferResult(success: false)

  # Ensure dialog is initialized with proper TAN method
  if client.dialogId == "0":
    try:
      # First dialog: discover TAN methods and BPD (one-step auth)
      discard client.initDialog()
      # If we discovered a TAN method, re-init with proper two-step auth
      if client.selectedTanMethod.len > 0 and client.selectedTanMethod != "999":
        client.endDialog()
        discard client.initDialog()
    except FintsError as e:
      result.errorMsg = e.msg
      return

  let secFunc = if client.selectedTanMethod.len > 0: client.selectedTanMethod else: "999"
  let hktanVer = if client.hktanVersion > 0: client.hktanVersion else: 7

  # Step 1: Send HKVPP (VoP Check) + HKIPZ (transfer) + HKTAN (process 4)
  var vopId = ""
  var vopPollingId = ""
  var vopWaitSec = 2
  var vopResultCode = ""
  var vopDifferentName = ""
  var vopOffset = ""
  var vopPending = false
  var skipVopAuth = false

  # Generate pain.001 XML once — must be identical in Step 1 and Step 3
  let transferMessageId = generateReference()
  let painXml = generatePain001(request, client.account, transferMessageId)
  if client.debug:
    stderr.writeLine "[DEBUG] pain.001 XML:\n" & painXml

  block:
    var segments = ""
    var segNum = 2
    let secRef = $rand(1000000..9999999)

    segments.add buildHNSHK(segNum, secFunc, secRef, client.blz, client.user, client.systemId)
    segNum += 1

    if client.vopRequired and client.vopReportFormat.len > 0:
      segments.add buildHKVPP(segNum, client.vopReportFormat)
      segNum += 1

    segments.add buildHKIPZFromPain(segNum, client.account, painXml)
    segNum += 1

    segments.add buildHKTAN(segNum, "4", "HKIPZ", version = hktanVer)
    segNum += 1

    segments.add buildHNSHA(segNum, secRef.parseInt, client.pin)

    let response = client.sendMessage(segments, segNum)
    let respSegments = parseAllSegments(response)

    for seg in respSegments:
      if seg.name == "HIRMG" or seg.name == "HIRMS":
        for de in seg.data:
          let parsed = parseResponse(de)
          if client.debug:
            stderr.writeLine "[DEBUG] " & seg.name & ": " & parsed.code & " " & parsed.msg
          if parsed.code == "0010" or parsed.code == "0020" or parsed.code == "0030":
            result.success = true
          elif parsed.code == "3091":
            # Bank skips VoP auth entirely — proceed directly with TAN
            skipVopAuth = true
          elif parsed.code == "3945":
            # VoP pending — bank hasn't completed name check yet
            vopPending = true
          elif parsed.code == "3040":
            # More data available — extract aufsetzpunkt for polling
            let msgParts = parsed.msg.split(':')
            if msgParts.len >= 2 and msgParts[^1].len > 0:
              vopOffset = msgParts[^1]
          elif parsed.code == "9050":
            discard  # Generic "message has errors" — check HIRMS for details
          elif parsed.code.startsWith("9"):
            # Prefer HIRMS-specific errors over earlier generic ones
            result.errorCode = parsed.code
            result.errorMsg = parsed.msg
      elif seg.name == "HITAN":
        if client.debug:
          stderr.writeLine "[DEBUG] HITAN data: " & $seg.data
        # HITAN v7: process(0) + orderHash(1) + orderRef(2) + challenge(3) + ...
        if seg.data.len > 2:
          result.orderRef = seg.data[2]
        if seg.data.len > 3:
          result.tanChallenge = seg.data[3]
        if seg.data.len > 6:
          result.tanMediaName = seg.data[6]
        result.tanRequired = true
      elif seg.name == "HIVPP":
        let hivpp = parseHIVPP(seg, client.debug)
        vopId = hivpp.vopId
        vopPollingId = hivpp.pollingId
        vopWaitSec = hivpp.waitSec
        vopResultCode = hivpp.resultCode
        vopDifferentName = hivpp.differentName

    if result.errorCode.len > 0:
      result.success = false
      return result

    # If bank skips VoP auth (3091) or no VoP required, we're done
    if skipVopAuth or not client.vopRequired:
      return result

    # If we got a vopId, skip polling — go straight to Step 3 (VoP Auth)
    if vopId.len > 0:
      discard  # Fall through to Step 3 below
    elif vopPollingId.len > 0:
      # VoP is pending — try polling, fall back to async if polling fails
      discard  # Fall through to Step 2 below
    else:
      # No vopId and no pollingId — bank may handle VoP asynchronously
      # (Atruvia banks send SecureGo notification even without HITAN)
      if result.tanRequired or vopPending:
        result.tanRequired = true
        return result
      result.errorMsg = "VoP: no vopId or pollingId in HIVPP response"
      return result

  # Step 2: Poll if PENDING (no vopId yet) — use pollingId + offset
  if vopId.len == 0 and vopPollingId.len > 0:
    stderr.writeLine "Verifying payee name..."
    if client.debug:
      stderr.writeLine "[DEBUG] VoP polling with pollingId=" & vopPollingId & " offset=" & vopOffset & " waitSec=" & $vopWaitSec

    for attempt in 0 ..< 5:
      sleep(vopWaitSec * 1000)
      if client.debug:
        stderr.writeLine "[DEBUG] VoP poll attempt " & $(attempt + 1)

      var segments = ""
      var segNum = 2
      let secRef = $rand(1000000..9999999)

      segments.add buildHNSHK(segNum, secFunc, secRef, client.blz, client.user, client.systemId)
      segNum += 1

      segments.add buildHKVPP(segNum, client.vopReportFormat, vopPollingId, vopOffset)
      segNum += 1

      segments.add buildHNSHA(segNum, secRef.parseInt, client.pin)

      let response = client.sendMessage(segments, segNum)
      let respSegments = parseAllSegments(response)

      var gotVopId = false
      var pollError = false
      var otherError = ""
      var otherErrorCode = ""
      for seg in respSegments:
        if seg.name == "HIRMG" or seg.name == "HIRMS":
          for de in seg.data:
            let parsed = parseResponse(de)
            if client.debug:
              stderr.writeLine "[DEBUG] VoP " & seg.name & ": " & parsed.code & " " & parsed.msg
            if parsed.code == "9210" or parsed.code == "9050":
              # 9210 = VOP order invalid, 9050 = message contains errors
              # Both indicate polling not supported — fall back to async
              pollError = true
            elif parsed.code == "3040":
              # Update offset for next poll
              let msgParts = parsed.msg.split(':')
              if msgParts.len >= 2 and msgParts[^1].len > 0:
                vopOffset = msgParts[^1]
            elif parsed.code.startsWith("9"):
              otherErrorCode = parsed.code
              otherError = parsed.msg
        elif seg.name == "HIVPP":
          let hivpp = parseHIVPP(seg, client.debug)
          if hivpp.vopId.len > 0:
            vopId = hivpp.vopId
            vopResultCode = hivpp.resultCode
            vopDifferentName = hivpp.differentName
            gotVopId = true
          if hivpp.pollingId.len > 0:
            vopPollingId = hivpp.pollingId
          if hivpp.waitSec > 0:
            vopWaitSec = hivpp.waitSec

      # Non-polling errors take priority
      if otherError.len > 0 and not pollError:
        result.errorCode = otherErrorCode
        result.errorMsg = otherError
        return

      if pollError:
        # Polling not supported (e.g. Atruvia banks).
        # Bank processes VoP asynchronously and sends SecureGo notification
        # even without HITAN. Return tanRequired to trigger manual approval.
        if client.debug:
          stderr.writeLine "[DEBUG] VoP polling not supported, falling back to async approval"
        result.tanRequired = true
        return result

      if gotVopId:
        stderr.writeLine "Payee verified."
        break

    if vopId.len == 0:
      # Polling timed out — fall back to async approval
      stderr.writeLine "VoP still pending, proceeding with async approval..."
      result.tanRequired = true
      return result

  # Handle VoP result codes
  case vopResultCode
  of "RVNM":
    stderr.writeLine "Warning: Payee name does NOT match. Proceed with caution."
  of "RVMC":
    if vopDifferentName.len > 0:
      stderr.writeLine "Note: Payee name is a close match. Bank suggests: " & vopDifferentName
  of "RVNA":
    stderr.writeLine "Note: Receiving bank does not support payee verification."
  of "RCVC", "":
    discard  # Match or not provided — proceed normally
  else:
    if client.debug:
      stderr.writeLine "[DEBUG] VoP result code: " & vopResultCode

  # Step 3: Send HKVPA (VoP Auth with vopId) + HKIPZ (transfer again) + HKTAN
  block:
    var segments = ""
    var segNum = 2
    let secRef = $rand(1000000..9999999)

    segments.add buildHNSHK(segNum, secFunc, secRef, client.blz, client.user, client.systemId)
    segNum += 1

    segments.add buildHKVPA(segNum, vopId)
    segNum += 1

    segments.add buildHKIPZFromPain(segNum, client.account, painXml)
    segNum += 1

    segments.add buildHKTAN(segNum, "4", "HKIPZ", version = hktanVer)
    segNum += 1

    segments.add buildHNSHA(segNum, secRef.parseInt, client.pin)

    let response = client.sendMessage(segments, segNum)
    let respSegments = parseAllSegments(response)

    result = TransferResult(success: false)
    var scaNotRequired = false
    for seg in respSegments:
      if seg.name == "HIRMG" or seg.name == "HIRMS":
        for de in seg.data:
          let parsed = parseResponse(de)
          if client.debug:
            stderr.writeLine "[DEBUG] " & seg.name & ": " & parsed.code & " " & parsed.msg
          if parsed.code == "0010" or parsed.code == "0020" or parsed.code == "0030":
            result.success = true
          elif parsed.code == "3076":
            scaNotRequired = true
          elif parsed.code == "9050":
            discard  # Generic "message has errors" — check HIRMS for details
          elif parsed.code.startsWith("9"):
            result.errorCode = parsed.code
            result.errorMsg = parsed.msg
      elif seg.name == "HITAN":
        if client.debug:
          stderr.writeLine "[DEBUG] HITAN data: " & $seg.data
        if seg.data.len > 2:
          result.orderRef = seg.data[2]
        if seg.data.len > 3:
          result.tanChallenge = seg.data[3]
        if seg.data.len > 6:
          result.tanMediaName = seg.data[6]
        result.tanRequired = true

    # 3076 = SCA not required — transfer already complete
    if scaNotRequired:
      result.tanRequired = false

    if result.errorCode.len > 0:
      result.success = false
      return result

  return result

proc submitTan*(client: var FintsClient, orderRef: string, tan: string): TransferResult =
  ## Submit TAN for pending transfer
  result = TransferResult(success: false)

  var segments = ""
  var segNum = 2
  let secRef = $rand(1000000..9999999)
  let secFunc = if client.selectedTanMethod.len > 0: client.selectedTanMethod else: "999"

  segments.add buildHNSHK(segNum, secFunc, secRef, client.blz, client.user, client.systemId)
  segNum += 1

  let hktanVer = if client.hktanVersion > 0: client.hktanVersion else: 7
  segments.add buildHKTAN(segNum, "2", "", orderRef, version = hktanVer)
  segNum += 1

  segments.add buildHNSHA(segNum, secRef.parseInt, client.pin, tan)

  let response = client.sendMessage(segments, segNum)
  let respSegments = parseAllSegments(response)

  for seg in respSegments:
    if seg.name == "HIRMG" or seg.name == "HIRMS":
      for de in respSegments[findSegment(respSegments, seg.name)].data:
        if de.startsWith("0010") or de.startsWith("0020"):
          result.success = true
        elif de.startsWith("9"):
          result.errorCode = de[0..3]
          if de.len > 5:
            result.errorMsg = de[5..^1]

  return result

# --- Convenience functions ---

proc pollDecoupledTan*(client: var FintsClient, orderRef: string): TransferResult =
  ## Poll for decoupled TAN confirmation (SecureGo plus etc.)
  ## Returns success=true if bank confirms, errorCode="POLL_UNSUPPORTED" if
  ## bank doesn't support HKTAN process "S" polling.
  result = TransferResult(success: false)

  let secFunc = if client.selectedTanMethod.len > 0: client.selectedTanMethod else: "999"
  let hktanVer = if client.hktanVersion > 0: client.hktanVersion else: 7

  for attempt in 0 ..< 30:  # Max 60 seconds
    sleep(2000)
    if client.debug:
      stderr.writeLine "[DEBUG] Polling decoupled TAN, attempt " & $(attempt + 1)

    var segments = ""
    var segNum = 2
    let secRef = $rand(1000000..9999999)

    segments.add buildHNSHK(segNum, secFunc, secRef, client.blz, client.user, client.systemId)
    segNum += 1

    segments.add buildHKTAN(segNum, "S", "", orderRef, version = hktanVer)
    segNum += 1

    segments.add buildHNSHA(segNum, secRef.parseInt, client.pin)

    let response = client.sendMessage(segments, segNum)
    let respSegments = parseAllSegments(response)

    var stillPending = false
    for seg in respSegments:
      if seg.name == "HIRMG" or seg.name == "HIRMS":
        for de in seg.data:
          let parsed = parseResponse(de)
          if client.debug:
            stderr.writeLine "[DEBUG] Poll " & seg.name & ": " & parsed.code & " " & parsed.msg
          if parsed.code == "0010" or parsed.code == "0020" or parsed.code == "0030":
            result.success = true
          elif parsed.code == "3955" or parsed.code == "3956":
            stillPending = true  # Decoupled auth still pending
          elif parsed.code == "9050":
            discard  # Generic "message has errors" — check HIRMS for details
          elif parsed.code == "9110" or parsed.code == "9100":
            # Bank doesn't support HKTAN process "S" polling
            if client.debug:
              stderr.writeLine "[DEBUG] Bank does not support decoupled TAN polling"
            result.errorCode = "POLL_UNSUPPORTED"
            result.errorMsg = "Bank does not support status polling"
            return
          elif parsed.code.startsWith("9"):
            result.errorCode = parsed.code
            result.errorMsg = parsed.msg
            return

    if result.success:
      return

    if not stillPending and not result.success:
      # No success and no pending status — unexpected state
      result.errorMsg = "Unexpected response during TAN polling"
      return

  result.errorMsg = "Decoupled TAN confirmation timed out"

proc pollDecoupledStatements*(client: var FintsClient, orderRef: string): StatementResult =
  ## Poll for decoupled TAN confirmation for statement retrieval
  ## Returns statements when confirmed, or error codes
  result = StatementResult(success: false, transactions: @[])

  let secFunc = if client.selectedTanMethod.len > 0: client.selectedTanMethod else: "999"
  let hktanVer = if client.hktanVersion > 0: client.hktanVersion else: 7

  for attempt in 0 ..< 30:  # Max 60 seconds
    sleep(2000)
    if client.debug:
      stderr.writeLine "[DEBUG] Polling decoupled TAN for statements, attempt " & $(attempt + 1)

    var segments = ""
    var segNum = 2
    let secRef = $rand(1000000..9999999)

    segments.add buildHNSHK(segNum, secFunc, secRef, client.blz, client.user, client.systemId)
    segNum += 1

    segments.add buildHKTAN(segNum, "S", "", orderRef, version = hktanVer)
    segNum += 1

    segments.add buildHNSHA(segNum, secRef.parseInt, client.pin)

    let response = client.sendMessage(segments, segNum)
    let respSegments = parseAllSegments(response)

    var stillPending = false
    for seg in respSegments:
      if seg.name == "HIRMG" or seg.name == "HIRMS":
        for de in seg.data:
          let parsed = parseResponse(de)
          if client.debug:
            stderr.writeLine "[DEBUG] Poll " & seg.name & ": " & parsed.code & " " & parsed.msg
          if parsed.code == "0010" or parsed.code == "0020" or parsed.code == "0030":
            result.success = true
          elif parsed.code == "3955" or parsed.code == "3956":
            stillPending = true  # Decoupled auth still pending
          elif parsed.code == "9050":
            discard  # Generic "message has errors" — check HIRMS for details
          elif parsed.code == "9110" or parsed.code == "9100":
            # Bank doesn't support HKTAN process "S" polling
            if client.debug:
              stderr.writeLine "[DEBUG] Bank does not support decoupled TAN polling"
            result.errorCode = "POLL_UNSUPPORTED"
            result.errorMsg = "Bank does not support status polling"
            return
          elif parsed.code.startsWith("9"):
            result.errorCode = parsed.code
            result.errorMsg = parsed.msg
            return

      elif seg.name == "HICAZ":
        # Statements might come back with polling response
        for dataElem in seg.data:
          if dataElem.len > 0 and dataElem.startsWith("@"):
            let camtData = extractBinary(dataElem)
            if camtData.len > 0 and camtData.startsWith("<?xml"):
              if client.debug:
                stderr.writeLine "[DEBUG] Got camt data in poll response"
              let txs = parseCamt(camtData)
              result.transactions.add(txs)
              break

    if result.success:
      return

    if not stillPending and not result.success:
      # No success and no pending status — unexpected state
      result.errorMsg = "Unexpected response during TAN polling"
      return

  result.errorMsg = "Decoupled TAN confirmation timed out"

proc getStatementsHICAZ(client: var FintsClient, fromDate, toDate: string, withTan: bool = true): StatementResult =
  ## Fetch account statements via HICAZ (camt format)
  ## withTan: if true, include HKTAN for decoupled TAN flow
  result = StatementResult(success: false, transactions: @[])

  let secFunc = if client.selectedTanMethod.len > 0: client.selectedTanMethod else: "999"
  let hicazVer = client.hicazVersion
  let camtUrn = client.hicazCamtUrn
  let hktanVer = if client.hktanVersion > 0: client.hktanVersion else: 7
  var offset = ""

  if client.debug:
    stderr.writeLine "[DEBUG] Using HICAZ version " & $hicazVer & " with URN: " & camtUrn

  while true:
    var segments = ""
    var segNum = 2
    let secRef = $rand(1000000..9999999)

    segments.add buildHNSHK(segNum, secFunc, secRef, client.blz, client.user, client.systemId)
    segNum += 1

    segments.add buildHKCAZ(segNum, client.account, fromDate, toDate, camtUrn, offset, hicazVer)
    segNum += 1

    if withTan:
      segments.add buildHKTAN(segNum, "4", "HKCAZ", version = hktanVer)
      segNum += 1

    segments.add buildHNSHA(segNum, secRef.parseInt, client.pin)

    let response = client.sendMessage(segments, segNum)
    let respSegments = parseAllSegments(response)

    var gotMore = false
    var newOffset = ""

    var hirmgError = ("", "")  # Store HIRMG error temporarily

    for seg in respSegments:
      if seg.name == "HIRMG" or seg.name == "HIRMS":
        for de in seg.data:
          let parsed = parseResponse(de)
          if client.debug:
            stderr.writeLine "[DEBUG] " & seg.name & ": " & parsed.code & " " & parsed.msg
          if parsed.code == "0010" or parsed.code == "0020":
            result.success = true
          elif parsed.code == "3040":
            gotMore = true
            let msgParts = parsed.msg.split(':')
            if msgParts.len >= 2 and msgParts[^1].len > 0:
              newOffset = msgParts[^1]
          elif parsed.code == "9370":
            # TAN required - not an error if we're doing TAN flow
            result.tanRequired = true
          elif parsed.code.startsWith("9"):
            if seg.name == "HIRMS":
              # HIRMS errors are more specific, use them directly
              result.errorCode = parsed.code
              result.errorMsg = parsed.msg
              return
            else:
              # Store HIRMG error as fallback
              hirmgError = (parsed.code, parsed.msg)

      elif seg.name == "HITAN":
        # HITAN contains TAN challenge/order reference for decoupled TAN
        if client.debug:
          stderr.writeLine "[DEBUG] HITAN data: " & $seg.data
        if seg.data.len > 2:
          result.orderRef = seg.data[2]
        if seg.data.len > 3:
          result.tanChallenge = seg.data[3]
        result.tanRequired = true

      elif seg.name == "HICAZ":
        # HICAZ contains camt XML data in binary format
        # Format: account:bic + urn + @len@xmldata
        if client.debug:
          stderr.writeLine "[DEBUG] HICAZ segment has " & $seg.data.len & " data elements"
        for i, dataElem in seg.data:
          if client.debug and dataElem.len > 0:
            stderr.writeLine "[DEBUG] HICAZ data[" & $i & "]: " & dataElem[0 .. min(80, dataElem.len - 1)] & (if dataElem.len > 80: "..." else: "")
          if dataElem.len > 0 and dataElem.startsWith("@"):
            let camtData = extractBinary(dataElem)
            if camtData.len > 0 and camtData.startsWith("<?xml"):
              if client.debug:
                stderr.writeLine "[DEBUG] Extracted camt XML: " & camtData[0 .. min(200, camtData.len - 1)] & "..."
              let txs = parseCamt(camtData)
              if client.debug:
                stderr.writeLine "[DEBUG] Parsed " & $txs.len & " transactions from camt"
              result.transactions.add(txs)
              break

    # If TAN required and we have orderRef, return for polling
    if result.tanRequired and result.orderRef.len > 0:
      return

    # If HIRMG error but no HIRMS error, use HIRMG
    if hirmgError[0].len > 0:
      result.errorCode = hirmgError[0]
      result.errorMsg = hirmgError[1]
      return

    if not gotMore or newOffset.len == 0:
      break
    offset = newOffset

  result.success = true

proc getStatementsHKKAZ(client: var FintsClient, fromDate, toDate: string): StatementResult =
  ## Fetch account statements via HKKAZ (MT940 format)
  result = StatementResult(success: false, transactions: @[])

  let secFunc = if client.selectedTanMethod.len > 0: client.selectedTanMethod else: "999"
  let hkkazVer = if client.hkkazVersion > 0: client.hkkazVersion else: 7
  var offset = ""

  if client.debug:
    stderr.writeLine "[DEBUG] Using HKKAZ version " & $hkkazVer

  while true:
    var segments = ""
    var segNum = 2
    let secRef = $rand(1000000..9999999)

    segments.add buildHNSHK(segNum, secFunc, secRef, client.blz, client.user, client.systemId)
    segNum += 1

    segments.add buildHKKAZ(segNum, client.account, fromDate, toDate, offset, hkkazVer)
    segNum += 1

    segments.add buildHNSHA(segNum, secRef.parseInt, client.pin)

    let response = client.sendMessage(segments, segNum)
    let respSegments = parseAllSegments(response)

    var gotMore = false
    var newOffset = ""

    var hirmgError = ("", "")  # Store HIRMG error temporarily

    for seg in respSegments:
      if seg.name == "HIRMG" or seg.name == "HIRMS":
        for de in seg.data:
          let parsed = parseResponse(de)
          if client.debug:
            stderr.writeLine "[DEBUG] " & seg.name & ": " & parsed.code & " " & parsed.msg
          if parsed.code == "0010" or parsed.code == "0020":
            result.success = true
          elif parsed.code == "3040":
            gotMore = true
            let msgParts = parsed.msg.split(':')
            if msgParts.len >= 2 and msgParts[^1].len > 0:
              newOffset = msgParts[^1]
          elif parsed.code.startsWith("9"):
            if seg.name == "HIRMS":
              # HIRMS errors are more specific, use them directly
              result.errorCode = parsed.code
              result.errorMsg = parsed.msg
              return
            else:
              # Store HIRMG error as fallback
              hirmgError = (parsed.code, parsed.msg)

      elif seg.name == "HIKAZ":
        # HIKAZ contains MT940 data in binary format
        if seg.data.len > 0:
          let mt940Data = extractBinary(seg.data[0])
          if mt940Data.len > 0:
            let txs = parseMT940(mt940Data)
            result.transactions.add(txs)

    # If HIRMG error but no HIRMS error, use HIRMG
    if hirmgError[0].len > 0:
      result.errorCode = hirmgError[0]
      result.errorMsg = hirmgError[1]
      return

    if not gotMore or newOffset.len == 0:
      break
    offset = newOffset

  result.success = true

proc getStatements*(client: var FintsClient, fromDate, toDate: string): StatementResult =
  ## Fetch account statements (tries HICAZ first, falls back to HKKAZ)
  ## fromDate/toDate format: YYYYMMDD
  result = StatementResult(success: false, transactions: @[])

  # Ensure dialog is initialized
  if client.dialogId == "0":
    try:
      discard client.initDialog()
      if client.selectedTanMethod.len > 0 and client.selectedTanMethod != "999":
        client.endDialog()
        discard client.initDialog()
    except FintsError as e:
      result.errorMsg = e.msg
      return

  var hicazResult: StatementResult

  # Prefer HICAZ (camt) if available - newer, cleaner format
  if client.hicazVersion > 0 and client.hicazCamtUrn.len > 0:
    if client.debug:
      stderr.writeLine "[DEBUG] Trying HICAZ (camt format)..."
    hicazResult = client.getStatementsHICAZ(fromDate, toDate)

    if hicazResult.success:
      return hicazResult

    # Handle decoupled TAN (SecureGo plus)
    if hicazResult.tanRequired and hicazResult.orderRef.len > 0:
      if client.debug:
        stderr.writeLine "[DEBUG] TAN required for statement retrieval"

      # Show challenge message if present
      if hicazResult.tanChallenge.len > 0 and hicazResult.tanChallenge != "nochallenge":
        stderr.writeLine hicazResult.tanChallenge
      else:
        stderr.writeLine "Please confirm statement retrieval in your banking app..."

      # Poll for decoupled TAN confirmation
      let pollResult = client.pollDecoupledStatements(hicazResult.orderRef)
      if pollResult.success:
        # If we got statements during polling, return them
        if pollResult.transactions.len > 0:
          return pollResult
        # Otherwise try to fetch statements again (TAN should be confirmed now)
        let retryResult = client.getStatementsHICAZ(fromDate, toDate, withTan = false)
        if retryResult.success:
          return retryResult
        result = retryResult
        return
      elif pollResult.errorCode == "POLL_UNSUPPORTED":
        # Bank doesn't support polling - need manual confirmation
        stderr.writeLine "Bank doesn't support automatic confirmation. Press Enter after confirming in app..."
        discard stdin.readLine()
        let retryResult = client.getStatementsHICAZ(fromDate, toDate, withTan = false)
        if retryResult.success:
          return retryResult
        result = retryResult
        return
      else:
        result = pollResult
        return

    # Try HKKAZ fallback if HICAZ fails
    if client.debug:
      stderr.writeLine "[DEBUG] HICAZ failed, falling back to HKKAZ..."

  # Fall back to HKKAZ (MT940)
  if client.hkkazVersion > 0:
    if client.debug:
      stderr.writeLine "[DEBUG] Trying HKKAZ (MT940 format)..."
    result = client.getStatementsHKKAZ(fromDate, toDate)
    if result.success:
      return
    # If HKKAZ also failed and HICAZ needed TAN but no orderRef, report that
    if hicazResult.tanRequired and hicazResult.orderRef.len == 0:
      result.errorCode = "9370"
      result.errorMsg = "Bank requires TAN but didn't provide order reference"
    return

  # HICAZ was tried but failed, use its error
  if hicazResult.errorCode.len > 0:
    return hicazResult

  # Neither supported
  result.errorMsg = "Bank does not advertise HICAZ or HKKAZ support"

proc fetchStatements*(url, blz, user, pin: string,
                      iban, bic: string,
                      fromDate, toDate: string,
                      debug: bool = false): StatementResult =
  ## Convenience function to fetch account statements
  var client = newFintsClient(url, blz, user, pin)
  client.debug = debug
  defer: client.close()

  client.account = Account(
    iban: iban,
    bic: bic,
    blz: blz
  )

  result = client.getStatements(fromDate, toDate)
  client.endDialog()

proc makeTransfer*(url, blz, user, pin: string,
                   senderIban, senderBic, senderName: string,
                   recipientIban, recipientBic, recipientName: string,
                   amount: float, reference: string,
                   instant: bool = true,
                   debug: bool = false): TransferResult =
  ## Execute a complete transfer including TAN handling
  var client = newFintsClient(url, blz, user, pin)
  client.debug = debug
  defer: client.close()

  client.account = Account(
    iban: senderIban,
    bic: senderBic,
    holder: senderName,
    blz: blz
  )

  let request = TransferRequest(
    recipientName: recipientName,
    recipientIban: recipientIban,
    recipientBic: recipientBic,
    amount: amount,
    currency: "EUR",
    reference: reference,
    instant: instant
  )

  result = client.transfer(request)

  # Handle decoupled TAN (SecureGo plus)
  if result.tanRequired:
    if result.tanChallenge.len > 0 and result.tanChallenge != "nochallenge":
      stderr.writeLine result.tanChallenge
    else:
      stderr.writeLine "Approve the transfer on your banking app (SecureGo plus)"

    if result.orderRef.len > 0:
      # Poll bank for decoupled TAN confirmation
      stderr.writeLine "Waiting for approval..."
      let pollResult = client.pollDecoupledTan(result.orderRef)
      if pollResult.success:
        result = pollResult
      elif pollResult.errorCode == "POLL_UNSUPPORTED":
        # Bank doesn't support HKTAN process "S" polling — ask user
        stderr.writeLine "Press Enter after approving..."
        try: discard stdin.readLine()
        except EOFError: discard
        # Bank already confirmed acceptance (0020) in Step 3
        result.success = true
      else:
        result = pollResult
    else:
      # No order reference — ask user to confirm manually
      stderr.writeLine "Press Enter after approving..."
      try: discard stdin.readLine()
      except EOFError: discard
      result.success = true

  client.endDialog()
