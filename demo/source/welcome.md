# Welcome

Everything on this page arrived as ciphertext. The server that handed it to you
holds `vault.enc` and two `.enc` files, and could not read a word of any of them.
The password lives in your head; the key was derived here, in this tab, and will
be gone the moment you close it.

**This is a public demo.** The password is `demo`, written down in the README, so
the contents are sample text and nothing else. Your own vault is only as private
as your passphrase.

## What survives the round trip

Regular markdown: **bold**, *italic*, ~~struck through~~, `inline code`, and
[links](https://github.com/davidcoray19-dev/encrypted-static-vault).

- Lists
- with several
  - nested items

> Block quotes, for when something needs setting apart.

| Piece | Where it runs |
|-------|---------------|
| `web/` | any static host |
| `sync/sync.js` | your machine, never the server |

```js
const key = await deriveKey(password, salt);   // memory only
```

## Photos

Images are stored as separate encrypted files and decrypted one at a time, so
reading one note does not pull an entire photo collection into memory.

![A sunset](photos/sunset.png)

Tap a photo to open it full screen.

![Tiles](photos/tiles.png)

Links work too: [the same sunset, as a link](photos/sunset.png).
