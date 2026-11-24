#!/usr/bin/env python3
"""Tests for did_check.py.

Every test uses throwaway keys created in a temporary directory.
No real identity.pem is ever read here.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

import did_check

# Fixed test vector: seed 0x2a * 32, DID computed with the reference client.
SEED_HEX = "2a" * 32
EXPECTED_DID = "did:key:z6MkgAnvkP45uNxwCKeNdt6wrYkEjpYX4f7Nrd8MQqFL8Fbn"
STRONG_PASS = "Correct-Horse-Battery-99!"
WEAK_PASS = "short"


def write_pem(directory: Path, password: bytes, seed_hex: str = SEED_HEX) -> Path:
    """Write an encrypted Ed25519 identity.pem with a fixed seed key."""
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    path = directory / "identity.pem"
    path.write_bytes(pem)
    return path


def write_pass_file(directory: Path, password: str) -> Path:
    path = directory / "pass.txt"
    path.write_text(password)
    return path


def run_cli(*argv: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "did_check.py"), *argv],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        timeout=30,
    )


class TestDerivation(unittest.TestCase):
    def test_fixed_seed_matches_reference_did(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))
        self.assertEqual(did_check.did_from_private_key(key), EXPECTED_DID)

    def test_did_format(self):
        # The multibase for an Ed25519 key must start with z6Mk.
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))
        did = did_check.did_from_private_key(key)
        self.assertTrue(did.startswith("did:key:z6Mk"))
        self.assertEqual(len(did), len("did:key:") + 48)


class TestLoad(unittest.TestCase):
    def test_loads_with_correct_passphrase(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pem(Path(tmp), STRONG_PASS.encode())
            key = did_check.load_private_key(path, STRONG_PASS.encode())
            self.assertEqual(did_check.did_from_private_key(key), EXPECTED_DID)

    def test_wrong_passphrase_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pem(Path(tmp), STRONG_PASS.encode())
            with self.assertRaises(did_check.CheckError):
                did_check.load_private_key(path, b"wrong-passphrase-123")

    def test_non_ed25519_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            rsa = generate_private_key(public_exponent=65537, key_size=2048)
            pem = rsa.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(STRONG_PASS.encode()),
            )
            path = Path(tmp) / "identity.pem"
            path.write_bytes(pem)
            with self.assertRaises(did_check.CheckError):
                did_check.load_private_key(path, STRONG_PASS.encode())


class TestPassphrase(unittest.TestCase):
    def test_short_passphrase_fails(self):
        score, _ = did_check.passphrase_strength(WEAK_PASS)
        self.assertLess(score, 60)

    def test_strong_passphrase_passes(self):
        score, _ = did_check.passphrase_strength(STRONG_PASS)
        self.assertGreaterEqual(score, 60)


class TestCli(unittest.TestCase):
    def test_all_pass_in_clean_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / ".gitignore").write_text("*.pem\n*.key\n")
            write_pem(root, STRONG_PASS.encode())
            pass_file = write_pass_file(root, STRONG_PASS)
            result = run_cli(
                "--expect-did", EXPECTED_DID,
                "--passphrase-file", str(pass_file),
                cwd=root,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("[PASS] identity loads", result.stdout)
            self.assertIn("[PASS] DID matches", result.stdout)
            self.assertIn("[PASS] gitignore covers identity.pem", result.stdout)
            self.assertIn("[PASS] no secrets tracked by git", result.stdout)
            self.assertIn("5/5 checks passed", result.stdout)

    def test_missing_gitignore_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            write_pem(root, STRONG_PASS.encode())
            pass_file = write_pass_file(root, STRONG_PASS)
            result = run_cli("--passphrase-file", str(pass_file), cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("[FAIL] gitignore covers identity.pem", result.stdout)

    def test_tracked_pem_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "t@t.t"], check=True
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "t"], check=True
            )
            (root / ".gitignore").write_text("*.pem\n")
            pem = write_pem(root, STRONG_PASS.encode())
            subprocess.run(
                ["git", "-C", str(root), "add", "-f", "identity.pem"], check=True
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "bad"], check=True
            )
            pass_file = write_pass_file(root, STRONG_PASS)
            result = run_cli("--passphrase-file", str(pass_file), cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("[FAIL] no secrets tracked by git", result.stdout)
            self.assertIn("identity.pem", result.stdout)

    def test_wrong_did_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pem(root, STRONG_PASS.encode())
            pass_file = write_pass_file(root, STRONG_PASS)
            result = run_cli(
                "--expect-did", "did:key:z6Mk1111111111111111111111111111111111111111",
                "--passphrase-file", str(pass_file),
                cwd=root,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("[FAIL] DID matches", result.stdout)

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_pem(root, STRONG_PASS.encode())
            pass_file = write_pass_file(root, STRONG_PASS)
            result = run_cli("--json", "--passphrase-file", str(pass_file), cwd=root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            import json

            data = json.loads(result.stdout)
            self.assertTrue(all(c["ok"] for c in data["checks"]))


if __name__ == "__main__":
    unittest.main()
