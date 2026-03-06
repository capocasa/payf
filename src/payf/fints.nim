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
    data = @[tanProcess, "", "", "", escapeFintsData(orderRef)]
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

            # Split data by + (respecting escapes)
            var data: seq[string] = @[]
            if dataStr.len > 0:
              var current = ""
              var i = 0
              while i < dataStr.len:
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
          elif parsed.code.startsWith("9"):
            result.errorCode = parsed.code
            result.errorMsg = parsed.msg
            return
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
    for seg in respSegments:
      if seg.name == "HIRMG" or seg.name == "HIRMS":
        for de in seg.data:
          let parsed = parseResponse(de)
          if client.debug:
            stderr.writeLine "[DEBUG] " & seg.name & ": " & parsed.code & " " & parsed.msg
          if parsed.code == "0010" or parsed.code == "0020" or parsed.code == "0030":
            result.success = true
          elif parsed.code.startsWith("9"):
            result.errorCode = parsed.code
            result.errorMsg = parsed.msg
            return
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

    for seg in respSegments:
      if seg.name == "HIRMG" or seg.name == "HIRMS":
        for de in seg.data:
          let parsed = parseResponse(de)
          if client.debug:
            stderr.writeLine "[DEBUG] Poll " & seg.name & ": " & parsed.code & " " & parsed.msg
          if parsed.code == "0010" or parsed.code == "0020" or parsed.code == "0030":
            result.success = true
          elif parsed.code == "3955":
            discard  # Still pending - continue polling
          elif parsed.code.startsWith("9"):
            result.errorCode = parsed.code
            result.errorMsg = parsed.msg
            return

    if result.success:
      return

  result.errorMsg = "Decoupled TAN confirmation timed out"

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
    if result.orderRef.len > 0:
      # We have an order reference - poll for completion
      stderr.writeLine "Waiting for TAN confirmation (approve on your device)..."
      if result.tanChallenge.len > 0:
        stderr.writeLine result.tanChallenge
      result = client.pollDecoupledTan(result.orderRef)
    else:
      # No order reference (VoP pending case) - bank sends auth to device
      # but doesn't return HITAN. User must approve on their app.
      stderr.writeLine ""
      if result.tanChallenge.len > 0:
        stderr.writeLine result.tanChallenge
      else:
        stderr.writeLine "Approve the transfer on your banking app (SecureGo plus)"
      stderr.writeLine "Press Enter after approving..."
      try:
        discard stdin.readLine()
      except EOFError:
        discard
      result.success = true

  client.endDialog()
