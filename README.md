# RIA-shared

Pages published by [RIA](https://github.com/RATHI-CAPITAL-VENTURES/RIA), Ishan's
personal assistant, when a page needs to be **shareable with other people**.

RIA's default is to serve a page from Ishan's Mac over Tailscale Funnel: private
to whoever has the link, and gone the moment the machine sleeps. That is the
right shape for something he's sending himself, and the wrong shape for anything
he wants to hand to someone else.

So a page published with `share=true` lands here instead — GitHub Pages, so the
URL keeps working whether or not the Mac is on.

**This repository is public.** Everything in it is world-readable, and RIA is
told to use it only for pages meant to be shared. Pages carry a `noindex` tag,
which asks search engines to stay away; it is not a privacy control.

Files are named `<slug>-<token>.html`. Nothing here is generated automatically —
each page exists because Ishan asked for one.

## Everything here is locked

Each page is AES-GCM encrypted under its own access code, derived with PBKDF2.
The code is generated when the page is published, given to Ishan once, and
stored nowhere — not on the page, not on his Mac. Without it the file is
ciphertext in the browser, in the raw file, and in a clone.

That matters because a link travels: it gets forwarded, pasted into threads and
screenshotted. A page merely behind a JavaScript prompt would be readable by
anyone who thought to `curl` it.

`.github/check_locked.py` runs on every push and pull request and fails if any
page here is readable without a code. `index.html` is the one exception.
