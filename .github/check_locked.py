#!/usr/bin/env python3
"""Fail if any artifact in this public repo is readable without its code.

The pages here are published to be SENT TO PEOPLE, which means the URL travels
— forwarded, pasted into a thread, screenshotted. A page that is merely behind
a JavaScript prompt is not protected at all: the file is world-readable, so
anyone can `curl` the raw URL and read straight past the prompt.

So the rule is that an artifact must BE ciphertext. This checks for the marks of
the unlock shell RIA publishes: a WebCrypto decrypt, PBKDF2 key derivation, and
the encrypted payload itself. A page missing any of them either isn't encrypted
or isn't something this repo should be serving.

`index.html` is the one deliberate exception — it is the landing page and says
nothing.
"""
import pathlib
import sys

ALLOWED_PLAINTEXT = {"index.html"}
REQUIRED = [
    ("crypto.subtle.decrypt", "no WebCrypto decrypt — the page isn't encrypted"),
    ("PBKDF2", "no key derivation from the access code"),
    ("AES-GCM", "no AES-GCM payload"),
    ('const S="', "no encrypted payload embedded"),
]

root = pathlib.Path(__file__).resolve().parent.parent
failures = []
checked = 0

for path in sorted(root.rglob("*.html")):
    rel = path.relative_to(root)
    if ".github" in rel.parts or str(rel) in ALLOWED_PLAINTEXT:
        continue
    checked += 1
    text = path.read_text(encoding="utf-8", errors="replace")
    missing = [why for marker, why in REQUIRED if marker not in text]
    if missing:
        failures.append((rel, missing))

if failures:
    print("::error::Unlocked artifacts found in a PUBLIC repository.\n")
    for rel, missing in failures:
        print(f"  {rel}")
        for why in missing:
            print(f"      - {why}")
    print("\nEvery page here is readable by anyone who sees the URL. Publish it")
    print("through RIA (`share=true`), which encrypts under a per-artifact code,")
    print("or delete it. Do not add an exception unless the page is genuinely")
    print("meant for the whole internet.")
    sys.exit(1)

print(f"OK — {checked} artifact(s) checked, all encrypted behind an access code.")
