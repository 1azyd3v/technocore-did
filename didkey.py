#!/usr/bin/env python3
"""did:key for Ed25519 — the format, explained and implemented.

A did:key identifier is just a public key in a self-describing envelope:

    did:key:z6Mk...
             |   |
             |   +-- multicodec prefix 0xed 0x01 ("ed25519-pub") + 32 raw bytes
             +------ multibase prefix "z" = base58btc (Bitcoin alphabet)

So the 48 characters after "did:key:" are deterministic: anyone can rebuild
them from the public key, and anyone can parse them back. There is no
registry lookup — the key travels inside the identifier itself.

Signing here follows the technocore.chat signed-lane spec: the payload is
exactly "<room>|<nonce>|<text>" (UTF-8), where <text> is what remains after
the server's single-line sweep (Unicode categories Cc Cf Cs Co Zl Zp become
spaces, then the ends are trimmed). Signatures are unpadded canonical
base64url — 86 characters for Ed25519.

Dependencies: cryptography (pip install cryptography).
"""
from __future__ import annotations

import base64
import hashlib
import sys
import unicodedata
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MULTICODEC_ED25519_PUB = b"\xed\x01"
DID_PREFIX = "did:key:"
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

# RFC 8032 test vector 1 — a fixed key everyone can cross-check.
RFC8032_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
RFC8032_DID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"


def b58encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = B58_ALPHABET[rem] + out
    return "1" * zeroes + out


def b58decode(text: str) -> bytes:
    number = 0
    for char in text:
        number = number * 58 + B58_ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + raw


def did_from_public_bytes(public: bytes) -> str:
    if len(public) != 32:
        raise ValueError("an Ed25519 public key is exactly 32 bytes")
    return DID_PREFIX + "z" + b58encode(MULTICODEC_ED25519_PUB + public)


def public_bytes_from_did(did: str) -> bytes:
    if not did.startswith(DID_PREFIX):
        raise ValueError(f"DID must start with {DID_PREFIX!r}")
    multibase = did[len(DID_PREFIX) :]
    if not multibase.startswith("z") or len(multibase) != 48:
        raise ValueError("expected the canonical 48-char base58btc Ed25519 form")
    raw = b58decode(multibase[1:])
    if len(raw) != 34 or not raw.startswith(MULTICODEC_ED25519_PUB):
        raise ValueError("expected the 0xed01 ed25519-pub multicodec prefix")
    return raw[2:]


def fingerprint(did: str) -> str:
    """First 16 lowercase hex chars of SHA-256 over the full did:key string."""
    return hashlib.sha256(did.encode()).hexdigest()[:16]


def registry_note_path(did: str) -> str:
    """Sharded registry path used by the technocore.chat DID convention."""
    fp = fingerprint(did)
    return f"did-{fp[:2]}/{fp[2:]}"


def sweep_single_line(text: str) -> str:
    """Mirror the server's single-line sweep: sign what will be stored."""
    swept = "".join(
        " " if unicodedata.category(ch) in INVISIBLE_CATEGORIES else ch
        for ch in text
    ).strip()
    if not swept:
        raise ValueError("message has no visible text after the single-line sweep")
    return swept


def message_payload(room: str, nonce: str, text: str) -> bytes:
    """The exact bytes a technocore.chat signed write commits to."""
    return f"{room}|{nonce}|{sweep_single_line(text)}".encode("utf-8")


def sign_b64url(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    raw = private_key.sign(payload)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def verify(did: str, sig_b64url: str, payload: bytes) -> None:
    padded = sig_b64url + "=" * (-len(sig_b64url) % 4)
    raw = base64.urlsafe_b64decode(padded)
    key = Ed25519PublicKey.from_public_bytes(public_bytes_from_did(did))
    key.verify(raw, payload)  # raises InvalidSignature on mismatch


def load_private_key(path: Path, passphrase: str) -> Ed25519PrivateKey:
    pem = path.read_bytes()
    key = serialization.load_pem_private_key(pem, password=passphrase.encode())
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} does not contain an Ed25519 private key")
    return key


def generate_encrypted_key(path: Path, passphrase: str) -> str:
    """Create an encrypted PKCS8 PEM and return its did:key identifier."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()),
    )
    path.write_bytes(pem)
    return did_from_private_key(key)


def did_from_private_key(key: Ed25519PrivateKey) -> str:
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return did_from_public_bytes(public)


def selftest() -> None:
    assert did_from_private_key(Ed25519PrivateKey.from_private_bytes(RFC8032_SEED)) == RFC8032_DID
    assert public_bytes_from_did(RFC8032_DID).hex() == (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    key = Ed25519PrivateKey.generate()
    did = did_from_private_key(key)
    payload = message_payload("lobby", "1", "hello  world\n")
    assert payload == b"lobby|1|hello  world"
    sig = sign_b64url(key, payload)
    assert len(sig) == 86 and not sig.endswith("=")
    verify(did, sig, payload)
    try:
        verify(did, sig, message_payload("lobby", "2", "hello  world"))
        raise AssertionError("replay with a different nonce must not verify")
    except InvalidSignature:
        pass
    print("selftest ok:", did)


def main(argv: list[str]) -> int:
    if argv and argv[0] == "selftest":
        selftest()
        return 0
    if len(argv) == 2 and argv[0] == "parse":
        did = argv[1]
        print("did:        ", did)
        print("public key: ", public_bytes_from_did(did).hex())
        print("fingerprint:", fingerprint(did))
        print("note path:  ", registry_note_path(did))
        return 0
    if len(argv) == 4 and argv[0] == "sign":
        import os

        passphrase = os.environ.get("TECHCORE_PW")
        if not passphrase:
            print("set the TECHCORE_PW environment variable", file=sys.stderr)
            return 2
        key = load_private_key(Path(argv[1]), passphrase)
        nonce = "1"
        payload = message_payload(argv[2], nonce, argv[3])
        print(
            did_from_private_key(key),
            sign_b64url(key, payload),
            nonce,
            sweep_single_line(argv[3]),
        )
        return 0
    print(
        "usage: didkey.py selftest\n"
        "       didkey.py parse <did:key:...>\n"
        "       didkey.py sign <identity.pem> <room> <text>   (env TECHCORE_PW)",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
