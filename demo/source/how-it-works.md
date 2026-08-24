# How it works

A second markdown file becomes a second tab. That is the whole navigation model.

## The format

```
vault.enc         salt(16) | iv(12) | ciphertext+tag
data/photos/<id>.enc       | iv(12) | ciphertext+tag
<id>              = HMAC-SHA256(key, filename)[0:24]
```

Photo filenames never reach the server. `sunset.png` is stored under a name derived
from the *key*, not the salt — the salt is public, so keying with it would let anyone
holding the vault check a guessed filename. A directory listing gives away nothing
but the count and the sizes.

## The key

PBKDF2-SHA256, 310,000 rounds, into an AES-256-GCM key. It is held in one
variable in this tab: never in `localStorage`, never in `IndexedDB`, and the
service worker caches nothing at all. Closing the tab is the lock.

## What it cannot do

The host serves this page, and this page handles your password. A hostile host
could serve a modified version that keeps it. That limit applies to every design
that decrypts in a browser, and the README says so plainly rather than leaving
you to work it out later.
