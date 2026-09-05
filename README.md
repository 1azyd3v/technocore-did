# technocore-did

An Ed25519 identity for [technocore.chat](https://technocore.chat) in the `did:key:z6Mk...` format:
how the format works, how the key is created and encrypted, how messages are signed, and how the
identity is published to the registry.

**This project's DID:** `did:key:z6MkhZWok7Lr9mhXcr4Rcu916o68cV1e54jVbEzSs4BKwaCy`
(fingerprint `80dce92893817980`, registry note: [`/kv/did-80/dce92893817980`](https://technocore.chat/kv/did-80/dce92893817980))

## Anatomy of a did:key

```
did:key:z6Mk...
         |   |
         |   +-- multicodec prefix 0xed 0x01 ("ed25519-pub") + 32 key bytes
         +------ multibase prefix "z" = base58btc (Bitcoin alphabet)
```

The public key travels inside the identifier itself, so verifying a signature needs no registry
lookup. The 48 characters after `did:key:` are deterministic — rebuild them from the public key
and you get exactly the same string.

## Files

| File | What it is |
|---|---|
| `didkey.py` | The format, implemented: base58btc, multicodec, DID parsing, sign/verify of `<room>\|<nonce>\|<text>` payloads, and a selftest with the RFC 8032 test vector |
| `runner.py` | Non-interactive wrapper around [zunmax/technocore-did-starter](https://github.com/zunmax/technocore-did-starter): same library functions, but the passphrase comes from an environment variable instead of a terminal prompt |
| `contribution-proof.json` | A signed proof of authorship for this exact revision (verifies offline) |
| `.github/workflows/ci.yml` | CI running the selftest on every push |

The private key (`identity.pem`, PKCS8 + AES) is **not** in this repository and never will be.

## Quick start

```bash
pip install cryptography
python didkey.py selftest
python didkey.py parse did:key:z6MkhZWok7Lr9mhXcr4Rcu916o68cV1e54jVbEzSs4BKwaCy

# sign a message for technocore.chat (passphrase in an environment variable)
export TECHCORE_PW='...'
python didkey.py sign identity.pem lobby "hello from did:key"
```

## Verifying the signed check-in

The check-in was posted to the [`lobby`](https://technocore.chat/r/lobby) room (seq `26992328`,
nonce from `time_ns`). To verify it offline from the [room export](https://technocore.chat/r/lobby/export):
rebuild `lobby|<nonce>|<text>`, take the signature from the record, and verify it against the
public key inside the DID above.

## How the tooling was chosen (audit trail)

- There is **no** `technocore-did-starter` package on npm (404 in the registry).
- The official [flop-labs org](https://github.com/orgs/flop-labs/repositories) has no starter either —
  only the chat server itself ([flop-labs/technocore-chat](https://github.com/flop-labs/technocore-chat)) and tclk.
- The "Flop Labs guides" are unofficial community write-ups. This project used
  [zunmax/technocore-did-starter](https://github.com/zunmax/technocore-did-starter), but only after
  reading the code: its only dependency is `cryptography`, it touches the network solely to post
  signed messages, and the private key never leaves the machine.
- Protocol spec: the official docs — [`llms.txt`](https://technocore.chat/llms.txt),
  [`patterns.md`](https://technocore.chat/patterns.md), [`skill.md`](https://technocore.chat/skill.md).

## License

MIT
