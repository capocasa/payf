# payf

SEPA instant transfer CLI via FinTS 3.0.

Send SEPA instant payments from the command line using your German bank account. Built in Nim with a pure FinTS 3.0 implementation (no external banking libraries).

```bash
payf transfer --to DE89370400440532013000 --name "Max Mustermann" --amount 25.00 --ref "Invoice 123"
```

## Features

- FinTS 3.0 protocol with PIN/TAN authentication
- SEPA instant transfer (HKIPZ) with Verification of Payee (VoP/Namensabgleich)
- Decoupled TAN (SecureGo plus) — approve on your phone
- Tested with Atruvia/VR banks

## Building

Requires Nim and nimble.

```bash
nimble build
```

## Configuration

Create a `.env` file (see `.env.example`):

```
FINTS_URL=https://fints2.atruvia.de/cgi-bin/hbciservlet
FINTS_BLZ=50592200
FINTS_USER=your_username
FINTS_PIN_CMD=pass bankname
IBAN=DE89370400440532013000
BIC=GENODE51OBH
ACCOUNT_HOLDER=Your Name
```

Or set environment variables directly. PIN can be set via `FINTS_PIN` or retrieved from a command via `FINTS_PIN_CMD`.

## Usage

```bash
# Transfer (instant by default)
payf transfer --to IBAN --name "Recipient" --amount 10.00 --ref "Payment"

# Standard (non-instant) transfer
payf transfer --to IBAN --name "Recipient" --amount 10.00 --instant=false

# Dry run (show what would happen)
payf transfer --to IBAN --name "Recipient" --amount 10.00 --dry-run

# Debug mode (show FinTS messages)
payf transfer --to IBAN --name "Recipient" --amount 10.00 --debug
```

## FinTS Product ID

This software uses registered FinTS product ID `5D8519C8F4024026D066D6661` (product name: payklaus).

If you fork this project for your own application, you should [register your own product ID](https://www.hbci-zka.de/register/prod_register.htm) with Deutsche Kreditwirtschaft.

## License

MIT
