# payf

SEPA instant transfer from the command line.

payf connects to your German bank via FinTS 3.0 and sends SEPA instant payments. No web browser, no app — just a command.

```bash
payf transfer --to DE89370400440532013000 --name "Max Mustermann" --amount 25.00 --ref "Invoice 123"
```

## Why

Bank transfers should be easy to make and easy to automate. payf removes the friction of logging into a web interface while keeping the security of your bank's TAN confirmation — every transfer is approved on your phone via SecureGo plus or similar.

## Status

payf works. Transfers have been tested with real money on Atruvia/VR bank servers. That said, this is new software and has only been tested against one bank server so far. Other FinTS 3.0 servers should work but may need adjustments. Bank onboarding (getting your FinTS server URL, registering a product ID) still requires some manual effort.

## How it works

1. payf connects to your bank's FinTS server
2. Verifies the payee name (Verification of Payee / Namensabgleich)
3. Submits the transfer
4. Your bank sends an approval request to your phone (SecureGo plus / decoupled TAN)
5. You approve, payf confirms success

For small or repeat transfers, the bank may skip the TAN step entirely.

## Building

Requires [Nim](https://nim-lang.org/) >= 2.0 and nimble.

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
payf transfer --to IBAN --name "Recipient" --amount 10.00 --ref "Payment"

# Standard (non-instant) transfer
payf transfer --to IBAN --name "Recipient" --amount 10.00 --instant=false

# Dry run
payf transfer --to IBAN --name "Recipient" --amount 10.00 --dry-run

# Debug mode (show FinTS protocol messages)
payf transfer --to IBAN --name "Recipient" --amount 10.00 --debug
```

## FinTS Product ID

This software uses registered FinTS product ID `5D8519C8F4024026D066D6661`.

If you fork this project, you should [register your own product ID](https://www.hbci-zka.de/register/prod_register.htm) with Deutsche Kreditwirtschaft.

## License

MIT
