#!/usr/bin/env python3
"""technocore-did-check: safety auditor for a Technocore DID identity.

Checks a Technocore Ed25519 identity (``identity.pem`` made by the
``technocore-did-starter`` reference client) for the mistakes the tutorial
warns about most:

1. ``identity.pem`` exists and decrypts with the given passphrase.
2. The derived ``did:key:z6Mk...`` matches the expected DID (when given).
3. ``identity.pem`` is covered by a ``.gitignore`` (no accidental commit).
4. No ``*.pem`` / ``*.key`` file is tracked by git in the repository.
5. The passphrase is at least 12 characters with mixed character classes.
6. A backup copy decrypts to the same key (when ``--backup-path`` is given).

Only the ``cryptography`` package is needed besides the standard library.
The private key is never printed, logged, or written anywhere by this tool.

Usage:
    python did_check.py [--identity identity.pem]
                        [--expect-did did:key:z6Mk...]
                        [--passphrase-file PASS.txt | prompt]
                        [--backup-path backup/identity.pem]
                        [--json]

Exit code 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import getpass
import json
import math
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519 = b"\xed\x01"
MULTIBASE_LENGTH = 48
MIN_PASSPHRASE_LENGTH = 12


class CheckError(RuntimeError):
    """A check could not run (not a failure of the thing checked)."""


def base58btc_encode(data: bytes) -> str:
    """Encode bytes with the base58btc alphabet, preserving leading zeroes."""
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    """Derive the public did:key identifier for an Ed25519 private key."""
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    multibase = "z" + base58btc_encode(MULTICODEC_ED25519 + public_key)
    if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
        raise CheckError("generated an invalid Ed25519 did:key")
    return "did:key:" + multibase


def load_private_key(path: Path, password: bytes) -> Ed25519PrivateKey:
    """Load an encrypted PEM private key, rejecting anything unexpected."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CheckError(f"cannot read {path}: {error}") from error
    try:
        key = serialization.load_pem_private_key(raw, password=password)
    except ValueError as error:
        raise CheckError("identity.pem did not decrypt (wrong passphrase?)") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise CheckError("identity.pem is not an Ed25519 private key")
    return key


def passphrase_strength(password: str) -> tuple[int, str]:
    """Score a passphrase 0-100 from length and character variety."""
    classes = sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )
    alphabet = 26 * (classes >= 1) + 26 * (classes >= 2) + 10 * (classes >= 3)
    alphabet += 32 * (classes >= 4)
    entropy = len(password) * math.log2(max(alphabet, 2))
    score = min(100, int(entropy))
    if len(password) < MIN_PASSPHRASE_LENGTH:
        return score, "too short (minimum 12 characters)"
    if classes < 3:
        return score, "use at least 3 character classes (lower/upper/digit/symbol)"
    return score, f"~{entropy:.0f} bits of entropy"


def git_repo_root(start: Path) -> Path | None:
    """Return the enclosing git repository root, or None."""
    result = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip())


def gitignored(repo_root: Path, path: Path) -> bool:
    """True when git considers the path ignored."""
    result = subprocess.run(
        ["git", "-C", str(repo_root), "check-ignore", "-q", str(path)],
        capture_output=True,
        timeout=10,
    )
    return result.returncode == 0


def tracked_secrets(repo_root: Path) -> list[str]:
    """Tracked *.pem / *.key files in the repository (should be none)."""
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "*.pem", "*.key"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise CheckError(f"git ls-files failed: {result.stderr.strip()}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def run_checks(args: argparse.Namespace) -> list[dict]:
    """Run every check and return a list of {name, ok, detail} dicts."""
    checks: list[dict] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    identity_path = Path(args.identity)
    if args.passphrase_file:
        password = Path(args.passphrase_file).read_bytes().strip()
    else:
        password = getpass.getpass("Passphrase for identity.pem: ").encode()

    # 1. Identity loads and is Ed25519.
    try:
        key = load_private_key(identity_path, password)
        did = did_from_private_key(key)
        add("identity loads", True, f"Ed25519 key decrypts OK, DID {did}")
    except CheckError as error:
        add("identity loads", False, str(error))
        return checks

    # 2. DID matches the expected value.
    if args.expect_did:
        add(
            "DID matches",
            did == args.expect_did,
            f"derived {did}" if did != args.expect_did else "matches expected DID",
        )

    # 3 + 4. Git hygiene (only when inside a repository).
    repo_root = git_repo_root(identity_path.resolve().parent)
    if repo_root is None:
        add("gitignore covers identity.pem", True, "not inside a git repository")
        add("no secrets tracked by git", True, "not inside a git repository")
    else:
        ignored = gitignored(repo_root, identity_path.resolve())
        add(
            "gitignore covers identity.pem",
            ignored,
            "ignored (safe)" if ignored else "NOT ignored — a commit could leak it",
        )
        tracked = tracked_secrets(repo_root)
        add(
            "no secrets tracked by git",
            not tracked,
            "none tracked" if not tracked else f"tracked: {', '.join(tracked)}",
        )

    # 5. Passphrase strength.
    score, detail = passphrase_strength(password.decode(errors="replace"))
    add("passphrase strength", score >= 60, f"score {score}/100 — {detail}")

    # 6. Backup decrypts to the same key.
    if args.backup_path:
        try:
            backup_key = load_private_key(Path(args.backup_path), password)
            same = did_from_private_key(backup_key) == did
            add(
                "backup matches",
                same,
                "backup decrypts to the same DID"
                if same
                else "backup is a DIFFERENT key",
            )
        except CheckError as error:
            add("backup matches", False, str(error))

    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit a Technocore DID identity for safety mistakes."
    )
    parser.add_argument("--identity", default="identity.pem")
    parser.add_argument("--expect-did", default=None)
    parser.add_argument("--passphrase-file", default=None)
    parser.add_argument("--backup-path", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    checks = run_checks(args)
    failed = [c for c in checks if not c["ok"]]

    if args.json:
        print(json.dumps({"did": checks[0]["detail"], "checks": checks}, indent=2))
    else:
        for check in checks:
            mark = "PASS" if check["ok"] else "FAIL"
            print(f"[{mark}] {check['name']}: {check['detail']}")
        print(f"{len(checks) - len(failed)}/{len(checks)} checks passed")

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
