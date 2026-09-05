#!/usr/bin/env python3
"""Non-interactive wrapper around the audited technocore_agent library.

The starter's CLI prompts for the identity passphrase with getpass, which
requires a real terminal. This wrapper calls the same library functions
(create_identity / load_identity / post_signed_message) directly and takes
the passphrase from the TECHCORE_PW environment variable instead. The
passphrase never appears in argv or in any network request.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "starter"))
import technocore_agent as ta  # noqa: E402


def main() -> int:
    passphrase = os.environ.get("TECHCORE_PW")
    if not passphrase:
        print("error: TECHCORE_PW environment variable is not set", file=sys.stderr)
        return 2
    if len(sys.argv) < 3:
        print(
            "usage: runner.py init|did <key.pem> | say <key.pem> <room> <text>",
            file=sys.stderr,
        )
        return 2
    command = sys.argv[1]
    key_path = Path(sys.argv[2])

    if command == "init":
        print(ta.create_identity(key_path, passphrase))
        return 0

    private_key = ta.load_identity(key_path, passphrase.encode("utf-8"))
    if command == "did":
        print(ta.did_from_private_key(private_key))
        return 0
    if command == "say":
        if len(sys.argv) != 5:
            print("usage: runner.py say <key.pem> <room> <text>", file=sys.stderr)
            return 2
        response = ta.post_signed_message(private_key, sys.argv[3], sys.argv[4])
        posted = response["posted"]
        print(
            json.dumps(
                {
                    "room": response["room"],
                    "seq": posted["seq"],
                    "did": posted["from"],
                    "text": posted["text"],
                }
            )
        )
        return 0
    print(f"error: unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
