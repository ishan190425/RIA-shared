#!/usr/bin/env python3
"""Fail if any artifact in this repo is missing from ARTIFACTS.md.

`check_locked.py` proves a published page is unreadable without its code. This
proves it is ACCOUNTABLE — that somebody can say what it is.

Without an index, a public repo accumulates opaque encrypted blobs. The
filenames carry a slug and a timestamp, which is enough to guess at but not
enough to act on: you cannot tell which pages are still meant to be live, which
were one-off tests, or which ones you would want revoked if a code leaked. The
index is the list you would need in order to answer any of those.

What it deliberately does NOT hold is the access code. The ciphertext is in this
repo; a code beside it would put both halves of the lock in the same public
place, which is the exact failure that sending the link and the code as separate
messages exists to prevent. This checks for that too — an index that leaked
codes would be worse than no index.
"""
import pathlib
import re
import sys

ALLOWED_UNINDEXED = {"index.html"}

root = pathlib.Path(__file__).resolve().parent.parent
index = root / "ARTIFACTS.md"

if not index.exists():
    print("::error::ARTIFACTS.md is missing. Every published artifact is listed "
          "there; without it this repo is a pile of unaccountable blobs.")
    sys.exit(1)

text = index.read_text(encoding="utf-8")

missing = []
for path in sorted(root.rglob("*.html")):
    rel = path.relative_to(root)
    if ".github" in rel.parts or str(rel) in ALLOWED_UNINDEXED:
        continue
    if path.name not in text:
        missing.append(rel)

# A 10-char code over the no-look-alikes alphabet. Anchored on word boundaries
# so ordinary filenames and words can't trip it.
CODE_RE = re.compile(r"\b[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{10}\b")
leaked = [m for m in CODE_RE.findall(text)]

if leaked:
    print("::error::ARTIFACTS.md appears to contain an access code.\n")
    print("  The ciphertext is in this same public repo, so a code here hands")
    print("  over both halves of the lock in one place. Remove it — and treat")
    print("  the affected artifact as compromised, because the history keeps it.")
    print(f"\n  looks like a code: {leaked[0]}")
    sys.exit(1)

if missing:
    print("::error::Published artifacts missing from ARTIFACTS.md.\n")
    for rel in missing:
        print(f"  {rel}")
    print("\n  RIA writes this row as part of publishing (_append_to_index in")
    print("  tools/artifact.py), on the same branch as the page, so the two")
    print("  land together. A file here without a row was added some other way.")
    sys.exit(1)

print(f"✓ every artifact is indexed, and no access codes are in the index.")
