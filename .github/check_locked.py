#!/usr/bin/env python3
"""Fail if anything in this public repo is readable without its code.

The pages here are published to be SENT TO PEOPLE, which means the URL travels
— forwarded, pasted into a thread, screenshotted. A page that is merely behind
a JavaScript prompt is not protected at all: the file is world-readable, so
anyone can `curl` the raw URL and read straight past the prompt.

So the rule is that an artifact must BE ciphertext. This checks for the marks of
the unlock shell RIA publishes: a WebCrypto decrypt, PBKDF2 key derivation, and
the encrypted payload itself.

DEFAULT-DENY, AND THAT IS THE WHOLE DESIGN.
-------------------------------------------
This used to scan `rglob("*.html")` and check those files for encryption
markers. Every HTML page in the repo was therefore verified, and every file
that was not HTML was invisible — a `.md`, a `.pdf`, a `.csv`, a `.txt` would
have been served in plaintext with this guard passing green. Six retros in a
row recorded it as a known hole, because the day artifacts grew a second format
was the day the guard silently stopped covering the repo.

A guard that enumerates what to check can only ever be as current as the last
person who remembered to update it. So the question is inverted: every file
here must be either an ALLOWED piece of infrastructure or a verified encrypted
artifact, and anything else fails by default. A new artifact format now fails
CI on the day it lands — loudly, before it is published — instead of quietly
becoming the exception nobody noticed.

That failure is not a nuisance to route around. The unlock shell is HTML and
WebCrypto; there is no mechanism that encrypts a PDF. A non-HTML artifact in
this repo is not "a format the guard doesn't know about", it is an unprotected
file. Adding it here means building the lock first.
"""
import pathlib
import sys

# Infrastructure: files that are meant to be public and say nothing private.
# Exact paths, never patterns — a pattern is how an artifact sneaks in wearing
# an infrastructure name.
ALLOWED_PLAINTEXT = {
    "index.html",              # the landing page; deliberately says nothing
    "README.md",
    "ARTIFACTS.md",            # the index — filenames and titles, never codes
    "CNAME",                   # the custom domain
    "icon.svg",
    "icon-32.png",
    "apple-touch-icon.png",
    "og.png",                  # link-preview image, same for every artifact
    ".nojekyll",
}

# Comment metadata. Holds an issue number and a verifier hash and nothing else
# — the comment TEXT lives in GitHub issues, not in this repo. The shape is
# checked below rather than trusted, because "it only holds a hash today" is
# the kind of thing that stops being true without anyone deciding it should.
COMMENT_DIR = "comments"
COMMENT_KEYS = {"issue", "verifier"}

REQUIRED = [
    ("crypto.subtle.decrypt", "no WebCrypto decrypt — the page isn't encrypted"),
    ("PBKDF2", "no key derivation from the access code"),
    ("AES-GCM", "no AES-GCM payload"),
    ('const S="', "no encrypted payload embedded"),
]

root = pathlib.Path(__file__).resolve().parent.parent
failures = []
checked = 0

for path in sorted(root.rglob("*")):
    if not path.is_file():
        continue
    rel = path.relative_to(root)
    if ".git" in rel.parts or ".github" in rel.parts:
        continue
    if str(rel) in ALLOWED_PLAINTEXT:
        continue

    if rel.parts[0] == COMMENT_DIR:
        # Allowed, but only while it stays metadata.
        import json
        try:
            keys = set(json.loads(path.read_text(encoding="utf-8")))
        except Exception as exc:                                # noqa: BLE001
            failures.append((rel, [f"unreadable comment metadata: {exc}"]))
            continue
        extra = keys - COMMENT_KEYS
        if extra:
            failures.append((rel, [
                f"carries {sorted(extra)} beyond {sorted(COMMENT_KEYS)} — if "
                "comment text is being stored here it is public plaintext"]))
        continue

    if path.suffix.lower() != ".html":
        failures.append((rel, [
            "not an HTML artifact, so nothing encrypts it. The unlock shell is "
            "HTML + WebCrypto; there is no lock for this format yet"]))
        continue

    checked += 1
    text = path.read_text(encoding="utf-8", errors="replace")
    missing = [why for marker, why in REQUIRED if marker not in text]
    if missing:
        failures.append((rel, missing))

if failures:
    print("::error::Unlocked files found in a PUBLIC repository.\n")
    for rel, missing in failures:
        print(f"  {rel}")
        for why in missing:
            print(f"      - {why}")
    print("\nEvery file here is readable by anyone who sees the URL. Publish")
    print("artifacts through RIA (`share=true`), which encrypts under a")
    print("per-artifact code, or delete the file. Add to ALLOWED_PLAINTEXT only")
    print("if the content is genuinely meant for the whole internet.")
    sys.exit(1)

print(f"OK — {checked} artifact(s) checked, all encrypted behind an access "
      f"code; every other file is allowlisted infrastructure.")
