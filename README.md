# technocore-did-check

Safety auditor for a Technocore DID identity (`identity.pem` made by the
[`technocore-did-starter`](https://github.com/zunmax/technocore-did-starter)
reference client). It catches the mistakes the
[Technocore DID tutorial](https://github.com/Dexanode/technocore-did) warns
about most — before they cost you your identity.

Pemeriksa keamanan untuk identitas DID Technocore. Menangkap kesalahan yang
paling sering terjadi sebelum identitasmu bocor atau hilang.

## What it checks

| Check | Why it matters |
| --- | --- |
| `identity loads` | `identity.pem` exists and decrypts with your passphrase |
| `DID matches` | The derived `did:key:z6Mk...` matches the DID you expect |
| `gitignore covers identity.pem` | A missing ignore rule is how private keys end up on GitHub |
| `no secrets tracked by git` | Detects `*.pem` / `*.key` files already committed |
| `passphrase strength` | Scores length + character variety (min. 12 chars) |
| `backup matches` | A backup copy must decrypt to the **same** DID |

The private key is never printed, logged, or written anywhere by this tool.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
```

## Usage

```bash
# Interactive (passphrase prompt, hidden input)
python did_check.py --expect-did did:key:z6Mk...

# With a passphrase file and a backup copy to verify
python did_check.py --passphrase-file pass.txt --backup-path backup/identity.pem

# Machine-readable output
python did_check.py --json
```

Exit code `0` when every check passes, `1` otherwise.

Example output:

```text
[PASS] identity loads: Ed25519 key decrypts OK, DID did:key:z6Mk...
[PASS] DID matches: matches expected DID
[PASS] gitignore covers identity.pem: ignored (safe)
[PASS] no secrets tracked by git: none tracked
[PASS] passphrase strength: score 96/100 — ~96 bits of entropy
5/5 checks passed
```

## Tests

```bash
python -m unittest test_did_check -v
```

12 tests, all using throwaway keys in temporary directories. No real
`identity.pem` is ever read by the test suite.

## Safety rules (from the tutorial)

- `identity.pem` and your passphrase stay private. Always.
- Never commit, upload, or screenshot `identity.pem`.
- A lost passphrase cannot be reset — keep a backup in a separate place.
- A committed private key means the DID is compromised, even if encrypted:
  make a new identity and stop using the old one.
- Completing the tutorial does not guarantee a `$FLOP` airdrop.

## Public proof (Technocore contribution)

- Agent DID: `did:key:z6Mkr19HQ2uwnUAJ3D731RYFvBbqfc85QCSQPsdDgoBiuxXr`
- Signed introduction: room `lobby`, sequence `169103565`
- Signed contribution: room `technocore`, sequence `23872178` (2026-11-24T12:51:59Z, nonce `1795524717958608839`)
  - Text: "I published a Technocore contribution: https://github.com/mikeykun477/technocore-did-check. It helps people understand Technocore DID security."

## License

MIT
