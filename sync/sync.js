#!/usr/bin/env node
'use strict';

/* ============================================================================
   sync.js -- encrypts a plaintext folder into the vault the web app reads.

   The plaintext never leaves this machine. What travels to the server is
   ciphertext only, and the server never sees the password.

   Source: a folder of markdown files plus a photo subfolder. Typically a
           mounted encrypted volume (Cryptomator, gocryptfs, VeraCrypt), which
           this script can find on its own while it is unlocked.
   Target: a local directory, or `host:/path` to push over ssh and rsync.

   Photos live in a subfolder named photos/, photos/, images/ or bilder/ -- the
   name does not matter. In the markdown only the filename is used, so
   ![](photos/a.jpg), ![](images/a.jpg) and ![](a.jpg) all resolve to the same
   file.

   Crypto: PBKDF2-SHA256 (310,000 rounds) -> AES-256-GCM, byte-compatible with
   the WebCrypto API the browser uses to read it back.
     vault.enc       : salt(16) | iv(12) | ciphertext+tag
     photos/<id>.enc :           iv(12) | ciphertext+tag
     <id>            = HMAC-SHA256(salt, filename)[0:24]

   Usage:
     node sync.js                    encrypt and transfer
     node sync.js --new-password     set a new password (re-encrypts everything)
     node sync.js --source <path>    name the source folder explicitly
     node sync.js --target <path>    local directory, or host:/path for ssh
     node sync.js --all              skip nothing, re-upload every photo

   Optional config: ~/.config/vault-sync.json
     { "source": "/path/to/unlocked/vault/private",
       "target": "myhost:/var/www/vault/data" }
   ============================================================================ */

const fs       = require('fs');
const os       = require('os');
const path     = require('path');
const crypto   = require('crypto');
const readline = require('readline');
const { execFileSync } = require('child_process');

const ROUNDS      = 310000;
const TARGET_EXAMPLE = '/var/www/vault/data';   // only used in help text
const CONFIG_FILE     = path.join(os.homedir(), '.config', 'vault-sync.json');
const STATE_DIR = path.join(os.homedir(), '.cache', 'vault-sync');

const argv       = process.argv.slice(2);
const NEW_PASSWORD   = argv.includes('--new-password');
const ALL       = argv.includes('--all');
const argSource  = (() => { const i = argv.indexOf('--source'); return i >= 0 ? argv[i + 1] : null; })();
const argTarget  = (() => { const i = argv.indexOf('--target'); return i >= 0 ? argv[i + 1] : null; })();

const MIME = {
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
  '.gif': 'image/gif',  '.webp': 'image/webp', '.avif': 'image/avif',
  '.heic': 'image/heic', '.svg': 'image/svg+xml', '.bmp': 'image/bmp',
  '.pdf': 'application/pdf', '.mp4': 'video/mp4', '.txt': 'text/plain'
};

function readConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch { return {}; }
}

/* ------------------------------------------------------------------ Password */

let rl = null, promptText = '', hide = false, awaitingAnswer = false;

function getRl() {
  if (rl) return rl;
  rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const writeOut = rl._writeToOutput.bind(rl);
  rl._writeToOutput = function (s) {
    if (!hide) return writeOut(s);
    if (s.includes(promptText)) writeOut(promptText);   // show the prompt, not the typing
    else if (s.includes('\n')) writeOut('\n');
  };
  rl.on('close', () => {
    if (awaitingAnswer) { console.error('\nAborted.'); process.exit(1); }
  });
  return rl;
}

function ask(text, hidden) {
  return new Promise(resolve => {
    const r = getRl();
    promptText = text; hide = !!hidden; awaitingAnswer = true;
    r.question(text, answer => {
      awaitingAnswer = false;
      if (hidden) process.stdout.write('\n');
      resolve(answer);
    });
  });
}

function closeRl() { if (rl) { rl.close(); rl = null; } }

/* ---------------------------------------------------------------------- Crypto */

function deriveKey(pw, salt) {
  return crypto.pbkdf2Sync(pw, salt, ROUNDS, 32, 'sha256');
}

function encrypt(key, buf) {
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct     = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, ct, cipher.getAuthTag()]);
}

function decrypt(key, iv, buf) {
  const tag      = buf.subarray(buf.length - 16);
  const ct       = buf.subarray(0, buf.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// Photo filename -> a stable, meaningless id. The web directory should not
// expose original filenames: "tax-return-2024.jpg" tells a passer-by plenty
// even while its contents stay encrypted. Derived from the salt, so a new
// password reshuffles every id as well.
function photoId(salt, name) {
  return crypto.createHmac('sha256', salt).update(name).digest('hex').slice(0, 24);
}

/* --------------------------------------------------------- Target: local / ssh */

function localTarget(dir) {
  fs.mkdirSync(path.join(dir, 'photos'), { recursive: true });
  return {
    name: dir,
    remote: false,
    read(rel) {
      try { return fs.readFileSync(path.join(dir, rel)); } catch { return null; }
    },
    listPhotos() {
      try { return fs.readdirSync(path.join(dir, 'photos')); } catch { return []; }
    },
    write(rel, buf) {
      fs.writeFileSync(path.join(dir, rel), buf, { mode: 0o644 });
    },
    remove(rels) {
      for (const r of rels) { try { fs.unlinkSync(path.join(dir, r)); } catch {} }
    },
    finish() {}
  };
}

function remoteTarget(host, dir) {
  const ssh = (args, opts = {}) =>
    execFileSync('ssh', ['-o', 'BatchMode=yes', host, ...args],
      { maxBuffer: 512 * 1024 * 1024, ...opts });

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-sync-'));
  fs.mkdirSync(path.join(tmp, 'photos'), { recursive: true });
  const pending = [];

  return {
    name: host + ':' + dir,
    remote: true,
    read(rel) {
      try { return ssh(['cat', dir + '/' + rel], { stdio: ['ignore', 'pipe', 'ignore'] }); }
      catch { return null; }
    },
    listPhotos() {
      try {
        return ssh(['ls', '-1', dir + '/photos'], { stdio: ['ignore', 'pipe', 'ignore'] })
          .toString().split('\n').filter(Boolean);
      } catch { return []; }
    },
    write(rel, buf) {
      fs.writeFileSync(path.join(tmp, rel), buf, { mode: 0o644 });
      pending.push(rel);
    },
    remove(rels) {
      if (!rels.length) return;
      ssh(['rm', '-f', ...rels.map(r => dir + '/' + r)], { stdio: 'ignore' });
    },
    finish() {
      if (pending.length) {
        execFileSync('rsync', ['-a', '--files-from=-', tmp + '/', host + ':' + dir + '/'],
          { input: pending.join('\n') + '\n', stdio: ['pipe', 'inherit', 'inherit'] });
      }
      fs.rmSync(tmp, { recursive: true, force: true });
    },
    pendingCount: () => pending.length
  };
}

/* ------------------------------------------------- Source (mounted secure volume) */

function mountCandidates() {
  const home = os.homedir();
  const uid  = process.getuid();
  const bases = [
    path.join(home, '.local/share/Cryptomator/mnt'),
    path.join(home, '.var/app/org.cryptomator.Cryptomator/data/Cryptomator/mnt'),
    path.join(home, 'Cryptomator'),
    '/run/user/' + uid + '/gvfs',
    path.join(home, '.cryptomator')
  ];

  const hits = [];
  for (const base of bases) {
    try {
      for (const e of fs.readdirSync(base)) hits.push(path.join(base, e));
    } catch {}
  }

  // plus everything the system reports as a FUSE mount
  try {
    const mounts = execFileSync('findmnt', ['-rno', 'TARGET,FSTYPE'], { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString().split('\n');
    for (const line of mounts) {
      const [target, type] = line.split(' ');
      if (!target || !type) continue;
      if (/fuse/i.test(type) && !/gvfsd|portal|snap/i.test(target)) hits.push(target);
    }
  } catch {}

  return [...new Set(hits)];
}

function findSource(config) {
  const given = argSource || process.env.VAULT_SOURCE || config.source;
  if (given) {
    if (!fs.existsSync(given)) {
      console.error('Source folder not found: ' + given);
      console.error('Is the encrypted volume unlocked?');
      process.exit(1);
    }
    return given;
  }

  // Look for the subfolder first; failing that take the mount itself, as long
  // as there are markdown files in it.
  const subfolder = config.subfolder || 'private';
  const hasMarkdown = p => {
    try { return fs.readdirSync(p).some(f => /\.md$/i.test(f)); } catch { return false; }
  };
  const checked = [];
  for (const k of mountCandidates()) {
    const candidate = path.join(k, subfolder);
    checked.push(candidate);
    try { if (fs.statSync(candidate).isDirectory()) return candidate; } catch {}
    if (hasMarkdown(k)) return k;
  }

  console.error('No unlocked volume with a folder "' + subfolder + '" or markdown files in it.');
  console.error('\n1. Unlock the volume, then try again.');
  console.error('2. If the mount lives elsewhere, name the path:');
  console.error('     node sync.js --source /path/to/folder');
  console.error('   or set it once in ' + CONFIG_FILE + ':');
  console.error('     { "source": "/path/to/folder", "target": "myhost:' + TARGET_EXAMPLE + '" }');
  if (checked.length) console.error('\nPaths checked:\n  ' + checked.join('\n  '));
  process.exit(1);
}

/* ------------------------------------------------------------------------- Run */

async function main() {
  const config = readConfig();

  // --- decide local vs. remote
  const targetSpec = argTarget || process.env.VAULT_TARGET || config.target;
  if (!targetSpec) {
    console.error('No target given. Where should the encrypted files go?\n');
    console.error('  node sync.js --target ./web/data              a local directory');
    console.error('  node sync.js --target myhost:' + TARGET_EXAMPLE + '   over ssh\n');
    console.error('Or set it once in ' + CONFIG_FILE + ':');
    console.error('  { "target": "myhost:' + TARGET_EXAMPLE + '" }');
    process.exit(1);
  }
  const remote = targetSpec.includes(':');
  const target     = remote
    ? remoteTarget(targetSpec.split(':')[0], targetSpec.split(':').slice(1).join(':'))
    : localTarget(targetSpec);

  // --- locate the source
  const source = remote
    ? findSource(config)
    : (argSource || process.env.VAULT_SOURCE || config.source || path.join(os.homedir(), 'vault'));

  if (!fs.existsSync(source)) { console.error('Source missing: ' + source); process.exit(1); }

  console.log('Source: ' + source);
  console.log('Target: ' + target.name + '\n');

  // --- password
  const existing = target.read('vault.enc');
  let salt, key;

  if (existing && existing.length > 28 && !NEW_PASSWORD) {
    salt = existing.subarray(0, 16);
    const pw = await ask('Password: ', true);
    closeRl();
    key = deriveKey(pw, salt);
    try {
      decrypt(key, existing.subarray(16, 28), existing.subarray(28));
    } catch {
      console.error('Wrong password -- nothing changed.');
      console.error('(Forgotten it? The only way on is: node sync.js --new-password)');
      process.exit(1);
    }
  } else {
    if (NEW_PASSWORD) console.log('Setting a new password -- the whole vault is re-encrypted.');
    else          console.log('No vault at the target yet -- choose a password.');
    const pw1 = await ask('New password: ', true);
    const pw2 = await ask('Repeat: ', true);
    closeRl();
    if (!pw1)        { console.error('Empty password -- aborted.'); process.exit(1); }
    if (pw1 !== pw2) { console.error('Passwords do not match -- aborted.'); process.exit(1); }
    if (pw1.length < 12) console.log('\nNote: the vault is fetchable by anyone who finds the URL, so an attacker can\nguess offline at their own pace. Use a long passphrase, not a short password.');
    salt = crypto.randomBytes(16);
    key  = deriveKey(pw1, salt);
  }

  // --- state from the last run, so unchanged photos are not re-uploaded
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  const stateFile = path.join(STATE_DIR, target.name.replace(/[^a-z0-9]+/gi, '_') + '.json');
  let state = { salt: '', photos: {} };
  try { state = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch {}
  const sameSalt = state.salt === salt.toString('hex');

  // --- collect markdown
  const files = {};
  for (const f of fs.readdirSync(source).sort()) {
    if (!/\.md$/i.test(f)) continue;
    try { if (!fs.statSync(path.join(source, f)).isFile()) continue; } catch { continue; }
    files[f] = fs.readFileSync(path.join(source, f), 'utf8');
  }

  // --- encrypt photos (changed ones only)
  // The folder name does not matter: photos/, photos/, images/, any case
  const photosDir  = ['photos', 'Photos', 'photos', 'Fotos', 'images', 'Images', 'bilder', 'Bilder']
    .map(n => path.join(source, n))
    .find(p => { try { return fs.statSync(p).isDirectory(); } catch { return false; } })
    || path.join(source, 'photos');
  const present = new Set(target.listPhotos());
  const photos     = {};
  const keep  = new Set();
  const newState = {};
  let added = 0, skipped = 0, photoBytes = 0;

  if (fs.existsSync(photosDir)) {
    for (const f of fs.readdirSync(photosDir).sort()) {
      const p = path.join(photosDir, f);
      let st;
      try { st = fs.statSync(p); } catch { continue; }
      if (!st.isFile() || f.startsWith('.')) continue;

      const id = photoId(salt, f);
      photos[f] = { id, type: MIME[path.extname(f).toLowerCase()] || 'application/octet-stream' };
      keep.add(id + '.enc');
      photoBytes += st.size;
      newState[f] = { id, mtimeMs: st.mtimeMs, size: st.size };

      const previous   = state.photos[f];
      const unchanged = sameSalt && !ALL && previous
                        && previous.mtimeMs === st.mtimeMs && previous.size === st.size
                        && present.has(id + '.enc');
      if (unchanged) { skipped++; continue; }

      target.write('photos/' + id + '.enc', encrypt(key, fs.readFileSync(p)));
      added++;
    }
  }

  // --- drop ciphertext at the target whose source file is gone
  const orphans = [...present].filter(f => !keep.has(f)).map(f => 'photos/' + f);
  target.remove(orphans);

  // --- write the vault and transfer everything
  const plaintext = Buffer.from(JSON.stringify({ files, photos, updated: new Date().toISOString() }), 'utf8');
  target.write('vault.enc', Buffer.concat([salt, encrypt(key, plaintext)]));
  target.finish();

  fs.writeFileSync(stateFile, JSON.stringify({ salt: salt.toString('hex'), photos: newState }), { mode: 0o600 });

  // --- report photos linked from markdown that are not in the source
  const missing = new Set();
  for (const md of Object.values(files)) {
    for (const m of md.matchAll(/!?\[[^\]]*\]\(([^)\s]+)\)/g)) {
      if (/^(https?:|mailto:|#)/i.test(m[1])) continue;
      const name = decodeURIComponent(m[1].split('?')[0]).split('/').pop();
      if (!photos[name]) missing.add(name);
    }
  }

  const mb = n => (n / 1048576).toFixed(1) + ' MB';
  console.log('Encrypted:');
  console.log('  ' + Object.keys(files).length + ' markdown file(s): ' + (Object.keys(files).join(', ') || '—'));
  console.log('  ' + Object.keys(photos).length + ' photo(s), ' + mb(photoBytes)
              + ' -- ' + added + ' transferred, ' + skipped + ' unchanged');
  if (orphans.length) console.log('  ' + orphans.length + ' orphaned file(s) removed at the target');
  if (missing.size) console.log('\nWarning -- linked from markdown but missing from '
    + path.basename(photosDir) + '/:\n  ' + [...missing].join('\n  '));
  console.log('\nDone.');
}

main().catch(e => { console.error('\nError: ' + e.message); process.exit(1); });
