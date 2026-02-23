## payf - SEPA instant transfer CLI via FinTS
##
## Usage:
##   payf transfer --to IBAN --name "Recipient" --amount 10.00 --ref "Payment"
##   payf balance
##
## Configuration via .env file or environment variables

import std/[strutils, strformat]
import cligen
import payf/config
from payf/fints import makeTransfer

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

  if txResult.tanRequired:
    echo ""
    echo "TAN required:"
    if txResult.tanChallenge.len > 0:
      echo txResult.tanChallenge
    stdout.write "Enter TAN: "
    stdout.flushFile()
    let tan = stdin.readLine().strip()
    if tan.len == 0:
      echo "Aborted"
      return 1

    # TODO: Submit TAN - requires maintaining client session
    echo "TAN submission not yet implemented for multi-step auth"
    return 1

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
