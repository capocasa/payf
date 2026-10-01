# payf

SEPA instant transfer from the command line. Connects to your German bank via FinTS 3.0, verifies the payee name, submits the transfer, and waits for you to approve it on your phone.

```bash
payf transfer "Max Mustermann" DE89370400440532013000 25.00 --reference "Invoice 123"
```

Bank transfers should be easy to script. payf removes the web interface but keeps the security — every transfer still goes through your bank's TAN confirmation (SecureGo plus or similar). For small or repeat transfers, the bank may skip the TAN step entirely.

## Status

payf works. Transfers have been tested with real money on Atruvia/VR bank servers. Other FinTS 3.0 servers should work but may need adjustments. Bank onboarding (FinTS server URL, product ID registration) still takes some manual effort.

## Install

Latest main build (macOS / Linux):

```bash
curl -fsSL https://payf.capocasa.dev/main/install | sh
```

Windows (PowerShell):

```powershell
irm https://payf.capocasa.dev/main/install.ps1 | iex
```

Those track `main`. For tagged releases see
[releases](https://github.com/capocasa/payf/releases). Release binaries
self-update quietly; opt out with `PAYF_AUTO_UPDATE=false`.

## Building

Requires [Nim](https://nim-lang.org/) >= 2.0.

```bash
nimble build
```

## Configuration

Copy `.env.example` to `.env` and fill in your bank details:

```bash
cp .env.example .env
```

You need:
- **FINTS_URL** — your bank's FinTS server URL (ask your bank or check their website)
- **FINTS_BLZ** — your bank's routing number (Bankleitzahl)
- **FINTS_USER** — your online banking username
- **FINTS_PIN** or **FINTS_PIN_CMD** — your PIN, or a command to retrieve it (e.g. `pass bankname`)
- **IBAN** — your account IBAN
- **BIC** — your account BIC
- **ACCOUNT_HOLDER** — your name as registered with the bank

## Usage

```bash
# Instant transfer (default)
payf transfer "Recipient" IBAN 10.00 --reference "Payment"

# Standard (non-instant) transfer
payf transfer "Recipient" IBAN 10.00 --instant=false

# Dry run
payf transfer "Recipient" IBAN 10.00 --dry-run

# Verbose (FinTS protocol to stderr)
payf transfer "Recipient" IBAN 10.00 -v

# Recent transactions (CSV on stdout)
payf list 30d
```

Silent on success. Errors go to stderr. All bank interaction is appended to
`$XDG_DATA_HOME/payf/payf-YYYY.log` (disable with `PAYF_NO_LOG=1`).

## FinTS Product ID

This software uses registered FinTS product ID `5D8519C8F4024026D066D6661`.

If you fork this project, you should [register your own product ID](https://www.hbci-zka.de/register/prod_register.htm) with Deutsche Kreditwirtschaft.

## License

MIT
