# Encrypted static vault

Private notes and photos on a web server that never sees them.

**[Live demo](https://davidcoray19-dev.github.io/encrypted-static-vault/)** — the
password is `demo`. It is written here on purpose: the demo vault holds sample text,
and the point is that you can watch it decrypt in your own browser, with a server
that only ever handed you ciphertext.

Markdown and images are encrypted on your own machine. What gets uploaded is
ciphertext and nothing else. The page that reads it is a single HTML file with
no backend, no database and no dependencies — decryption happens in the browser,
with a password the server has never been told.

```
your machine                          any static host
─────────────                         ───────────────
notes.md      ──┐                     data/vault.enc          (opaque)
photos/*.jpg  ──┤  sync.js  ────────▶  data/photos/*.enc      (opaque)
                │  encrypts           index.html              (the reader)
password ───────┘
```

Two pieces, and the split is the whole point:

- **`web/`** — the reader. Static files. Put them anywhere that serves HTTP.
- **`sync/sync.js`** — the writer. Runs on your machine, never on the server.

(`demo/` holds the sample vault behind the link above, built by the same `sync.js`
and published by `.github/workflows/pages.yml`. Nothing else depends on it.)

---

## What this protects against, and what it does not

Worth reading before you trust it with anything.

**It protects against** someone reading your files on the server: a hosting
provider, a backup that ends up somewhere it should not, a misconfigured
directory listing, a stolen server disk, anyone who guesses the URL. All of them
get `vault.enc`, and `vault.enc` is AES-256-GCM ciphertext.

**It does not protect against a malicious or compromised host.** The host serves
`index.html`, and `index.html` is the code that handles your password. A host who
wanted your data could serve a modified page that mails the password home, and you
would not notice. This is the unavoidable limit of every "encrypted in the browser"
design: you are trusting the server for the *code* even while you distrust it for
the *data*. It is a real improvement over storing plaintext — the host has to
actively attack you rather than merely read a file — but it is not end-to-end
encryption in the sense that a signed, installed application would be.

If that distinction matters to you, host the `web/` files yourself, or open them
from a local copy and point them at a remote `data/` directory.

**It does not hide metadata.** Anyone who can fetch the vault learns its size, and
from `data/photos/` the number of photos and how large each one is. The shape of
your collection is visible even though its contents are not.

Filenames are not, and are not guessable. Each photo is stored under
`HMAC-SHA256(key, filename)[0:24]`, keyed with the **derived key** rather than the
salt. That distinction is the whole protection: the salt travels in the clear at the
front of `vault.enc`, so keying with it would let anyone holding the vault compute
the id for a guessed name like `passport.jpg` and check whether it is present. Keyed
with the derived key, computing an id requires the password.

**The password is attackable offline.** Whoever holds a copy of `vault.enc` can
guess at it for as long as they like, on hardware of their choosing. 310,000
PBKDF2 rounds make each guess expensive, not impossible. Use a long passphrase.
A memorable four-word phrase beats a short password with punctuation in it.

---

## How it works

### Format

```
vault.enc         salt(16) │ iv(12) │ ciphertext+tag
data/photos/<id>.enc       │ iv(12) │ ciphertext+tag
<id>              = HMAC-SHA256(key, filename)[0:24]
```

`vault.enc` decrypts to one JSON object: every markdown file as a string, plus a
map from photo filename to `{ id, type }`. Photos are separate files so the page
can decrypt them lazily, as they scroll into view, instead of holding your entire
photo collection in memory to read one note.

The salt is stored with the vault and shared by every file; each file gets its own
random IV. Photo ids are keyed with the derived key, not the salt, so they cannot be
computed by anyone who merely downloaded the vault. Changing the password changes the
key and therefore every id — so a password change re-encrypts and re-uploads
everything, by design.

### Crypto

PBKDF2-SHA256, 310,000 rounds, deriving an AES-256-GCM key. The parameters match
on both sides deliberately: `sync.js` uses Node's `crypto`, the page uses WebCrypto,
and the byte layout is identical so either can read what the other wrote.

GCM means the ciphertext is authenticated. A wrong password fails as a decryption
error rather than producing garbage, and a tampered vault fails the same way — an
attacker cannot quietly alter a note or repoint a photo.

**Why PBKDF2 and not Argon2id.** Argon2id is the better password hash: memory-hard,
far more expensive to attack on a GPU. It is also not in WebCrypto. Using it would
mean shipping a WASM build to every reader, which is a dependency, a larger attack
surface in the one file that handles the password, and a thing that can fail to load.
PBKDF2-SHA256 at 310,000 rounds is what the browser offers natively and what OWASP
currently recommends for it. The honest summary: this is the strongest KDF available
without dependencies, and it is weaker than the strongest KDF that exists. Your
passphrase is doing more work here than the KDF is.

### The key never touches disk

In the browser the derived key lives in one variable, in one tab. It is never put
in `localStorage`, never in `IndexedDB`, never in a cookie. On `pagehide` the key,
the decrypted vault and every decrypted photo blob are dropped, and the service
worker caches nothing at all — see `web/sw.js` for why that one is not an
oversight. Closing the tab is the lock.

---

## Quick start

Requires Node 18 or newer. No dependencies.

```sh
# 1. A source folder with markdown and photos
mkdir -p ~/vault/photos
echo '# First note' > ~/vault/notes.md
cp somewhere/picture.jpg ~/vault/photos/

# 2. Encrypt it into the web directory
node sync/sync.js --source ~/vault --target ./web/data     # asks for a password

# 3. Serve web/ over HTTP and open it
python3 -m http.server -d web 8000
```

Open `http://localhost:8000`, enter the password, and the notes appear.

`file://` will not work — the page fetches `data/vault.enc`, which needs HTTP.

### Writing notes

Plain markdown: headings, lists, tables, code fences, links, bold and italic.
Images resolve by **filename only**, so all three of these find the same photo:

```markdown
![](photos/sunset.jpg)
![](images/sunset.jpg)
![](sunset.jpg)
```

Several `.md` files in the source folder become tabs across the top.

---

## The sync tool

```sh
node sync.js                    # encrypt and transfer
node sync.js --new-password     # change the password (re-encrypts everything)
node sync.js --source <path>    # name the source folder explicitly
node sync.js --all              # re-upload every photo, skipping nothing
```

**Remote targets.** Give a target of the form `host:/path` and it transfers over
`ssh` and `rsync`, using whatever is already in your `~/.ssh/config`:

```sh
node sync.js --source ~/vault --target myserver:/var/www/vault/data
```

**Incremental by default.** Photos are re-encrypted only when their size or
modification time has changed; state lives in `~/.cache/vault-sync/`. Files
deleted from the source are deleted at the target.

This is the same heuristic `rsync` uses by default, and it has the same blind spot:
an edit that preserves both size and mtime goes unnoticed. Hashing every file on
every run would close it, at the cost of reading the entire collection each time —
which is exactly what the incremental path exists to avoid. If you have touched a
file in a way that might have kept its timestamp, run `--all`.

**Mounted secure volumes.** If you keep the plaintext in Cryptomator, gocryptfs
or anything else that appears as a FUSE mount, `sync.js` finds it on its own
while it is unlocked — it looks for a `private/` subfolder, or any mount with
markdown files at the top. This is the arrangement the tool was built for: the
plaintext exists only inside a volume that is itself encrypted at rest, and is
mounted only for the moment you run the sync.

**Config.** `~/.config/vault-sync.json`, so you can stop passing arguments:

```json
{
  "source": "/home/you/.local/share/Cryptomator/mnt/vault/private",
  "target": "myserver:/var/www/vault/data",
  "subfolder": "private"
}
```

Environment variables `VAULT_SOURCE` and `VAULT_TARGET` override the config file.

---

## Deploying

There is nothing to deploy but files. Any static host works: nginx, Apache,
GitHub Pages, S3, a Raspberry Pi. No Node on the server, no database, no build.

Two things are worth getting right:

**Do not cache `data/`.** A stale vault silently shows old content after a sync.

```nginx
location /data/ {
    add_header Cache-Control "no-store";
}
```

**Consider HTTP Basic Auth in front of everything.** The vault is safe in the open
— that is the point — but a password prompt keeps crawlers and idle passers-by
away, and means an attacker cannot even start guessing offline without first
getting past it. If you do, note that browsers fetch `manifest.json` without
credentials by default; `index.html` already carries
`<link rel="manifest" crossorigin="use-credentials">` for exactly that reason.

---

## What this is not

- **Not multi-user.** One password, one vault, and everyone who has the password
  has all of it.
- **Not editable in the browser.** The page is read-only on purpose: writing would
  mean an API, an API means a backend, and a backend means something on the server
  that can be attacked. Edit the markdown on your machine and run the sync.
- **Not a replacement for a password manager or a real E2E notes app.** It is a
  way to read your own private text and pictures from a phone, on a server you do
  not have to trust with them.

---

## Licence

MIT — see [LICENSE](LICENSE).
