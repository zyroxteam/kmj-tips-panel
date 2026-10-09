/**
 * KMJ TIPS — single-file panel + backend API server.
 * Run:  node bot.js            (starts panel + API)
 *       node bot.js --setup    (create first admin, interactive)
 *
 * Zero native dependencies. Works on Node 18+.
 * Data is stored in a JSON file (DB_PATH env, default ./kmj-tips-data.json).
 *
 * Public API:  POST /api/keys/verify   GET /api/update   GET /api/health
 * Admin API (JWT): /api/admin/*  (see docs/API.md)
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

/* ================= config ================= */
const PORT = parseInt(process.env.PORT || '3000', 10);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'kmj-tips-data.json');
const JWT_EXPIRES = process.env.JWT_EXPIRES || '12h';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

let JWT_SECRET = process.env.JWT_SECRET || '';
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  console.log('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
  console.log('! WARNING: JWT_SECRET not set (or too short).');
  console.log('! Using a temporary secret — admin sessions will reset on restart.');
  console.log('! Set JWT_SECRET env var (min 32 chars) for production.');
  console.log('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
}

/* ================= tiny JSON database ================= */
const DB = {
  data: null,
  load() {
    try {
      if (fs.existsSync(DB_PATH)) {
        this.data = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
      }
    } catch (e) { console.log('DB read failed, starting fresh:', e.message); }
    if (!this.data || typeof this.data !== 'object') {
      this.data = {
        seq: { admins: 1, keys: 1, key_events: 1 },
        admins: [],
        keys: [],
        key_events: [],
        app_update: {
          version_name: '1.0.0', version_code: 1,
          title: 'New Update Available',
          changelog: 'Bug fixes and improvements.',
          download_url: '', website_url: '',
          force_update: 0, updated_at: Date.now()
        }
      };
      this.save();
    }
    // backfill safety
    for (const k of ['seq', 'admins', 'keys', 'key_events', 'app_update']) {
      if (!this.data[k]) this.data[k] = k === 'seq' ? { admins: 1, keys: 1, key_events: 1 } : [];
    }
  },
  save() {
    try {
      const tmp = DB_PATH + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(this.data));
      fs.renameSync(tmp, DB_PATH); // atomic
    } catch (e) { console.log('DB save failed:', e.message); }
  },
  next(table) {
    const id = this.data.seq[table] || 1;
    this.data.seq[table] = id + 1;
    return id;
  }
};
DB.load();

/* ================= helpers ================= */
const ok = (res, data) => res.json(Object.assign({ ok: true }, data));
const fail = (res, code, message) => res.status(code).json({ ok: false, error: message });

function requireAdmin(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    if (!token) return fail(res, 401, 'Missing token');
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) { return fail(res, 401, 'Invalid or expired token'); }
}

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function randomSegment(len) {
  const buf = crypto.randomBytes(len);
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHABET[buf[i] % ALPHABET.length];
  return s;
}
function generateKey(prefix) {
  const p = (prefix || 'KMJ').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12) || 'KMJ';
  return p + '-' + randomSegment(4) + '-' + randomSegment(4) + '-' + randomSegment(4) + '-' + randomSegment(4);
}
function isHttpUrl(u) {
  return typeof u === 'string' && /^(https?:\/\/)[^\s/$.?#].[^\s]*$/i.test(u.trim());
}
const findKeyById = (id) => DB.data.keys.find(k => k.id === id);
const findKeyByKey = (k) => DB.data.keys.find(x => x.key === k);

/* ================= app ================= */
const app = express();
if (TRUST_PROXY) app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true });
const verifyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 120, standardHeaders: true });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 600, standardHeaders: true });
app.use('/api/', apiLimiter);

/* ---------- public: key verification ---------- */
app.post('/api/keys/verify', verifyLimiter, (req, res) => {
  try {
    const b = req.body || {};
    const key = b.key, deviceId = typeof b.device_id === 'string' ? b.device_id.slice(0, 128) : '';
    if (typeof key !== 'string' || key.trim().length < 8 || key.trim().length > 64) {
      return res.json({ valid: false, status: 'invalid', message: 'Invalid key format' });
    }
    const row = findKeyByKey(key.trim().toUpperCase());
    if (!row) return res.json({ valid: false, status: 'invalid', message: 'Key not found' });
    const now = Date.now();

    if (row.status === 'revoked') {
      return res.json({ valid: false, status: 'revoked', message: 'This key has been revoked' });
    }
    if (row.status === 'expired' || (row.expires_at && now > row.expires_at)) {
      if (row.status !== 'expired') { row.status = 'expired'; DB.save(); }
      return res.json({ valid: false, status: 'expired', message: 'This key has expired' });
    }
    if (row.single_use && row.device_id && deviceId && row.device_id !== deviceId) {
      row.status = 'used'; DB.save();
      return res.json({ valid: false, status: 'used', message: 'This key is already used on another device' });
    }

    row.use_count = (row.use_count || 0) + 1;
    row.used_at = now;
    if (!row.device_id && deviceId) row.device_id = deviceId;
    DB.data.key_events.push({ id: DB.next('key_events'), key_id: row.id, event: 'verified', device_id: deviceId, created_at: now });
    DB.save();

    return res.json({
      valid: true, status: row.single_use ? 'used' : 'active',
      message: 'Key verified successfully',
      expires_at: row.expires_at || null, label: row.label || ''
    });
  } catch (e) { return fail(res, 500, 'Verification failed'); }
});

/* ---------- public: update info ---------- */
app.get('/api/update', (req, res) => {
  try {
    const u = DB.data.app_update;
    const out = {
      latest_version: u.version_name, version_code: u.version_code,
      update_available: u.version_code > 0 && (u.download_url || '').length > 0,
      force_update: u.force_update === 1, title: u.title,
      changelog: u.changelog, download_url: u.download_url
    };
    if (u.website_url) out.website_url = u.website_url;
    res.json(out);
  } catch (e) { return fail(res, 500, 'Could not load update info'); }
});

app.get('/api/health', (req, res) => ok(res, { service: 'kmj-tips', time: Date.now() }));

/* ---------- admin: setup & login ---------- */
app.post('/api/admin/setup', loginLimiter, (req, res) => {
  try {
    if (DB.data.admins.length > 0) return fail(res, 403, 'Setup is disabled — an admin already exists');
    const b = req.body || {};
    if (typeof b.username !== 'string' || !/^[a-zA-Z0-9_.-]{3,32}$/.test(b.username)) {
      return fail(res, 400, 'Username must be 3-32 chars (letters, numbers, _ . -)');
    }
    if (typeof b.password !== 'string' || b.password.length < 8 || b.password.length > 128) {
      return fail(res, 400, 'Password must be 8-128 characters');
    }
    DB.data.admins.push({ id: DB.next('admins'), username: b.username, password_hash: bcrypt.hashSync(b.password, 12), created_at: Date.now() });
    DB.save();
    return ok(res, { message: 'Admin created. Please log in.' });
  } catch (e) { return fail(res, 500, 'Setup failed'); }
});

app.post('/api/admin/login', loginLimiter, (req, res) => {
  try {
    const b = req.body || {};
    if (typeof b.username !== 'string' || typeof b.password !== 'string') {
      return fail(res, 400, 'Username and password required');
    }
    const admin = DB.data.admins.find(a => a.username === b.username);
    const hash = admin ? admin.password_hash : bcrypt.hashSync('dummy', 4);
    if (!admin || !bcrypt.compareSync(b.password, hash)) {
      return fail(res, 401, 'Invalid username or password');
    }
    const token = jwt.sign({ sub: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    return ok(res, { token, username: admin.username, expires_in: JWT_EXPIRES });
  } catch (e) { return fail(res, 500, 'Login failed'); }
});

app.post('/api/admin/change-password', requireAdmin, (req, res) => {
  try {
    const b = req.body || {};
    if (typeof b.new_password !== 'string' || b.new_password.length < 8 || b.new_password.length > 128) {
      return fail(res, 400, 'New password must be 8-128 characters');
    }
    const admin = DB.data.admins.find(a => a.id === req.admin.sub);
    if (!admin || !bcrypt.compareSync(b.current_password || '', admin.password_hash)) {
      return fail(res, 401, 'Current password is incorrect');
    }
    admin.password_hash = bcrypt.hashSync(b.new_password, 12);
    DB.save();
    return ok(res, { message: 'Password changed' });
  } catch (e) { return fail(res, 500, 'Could not change password'); }
});

/* ---------- admin: stats ---------- */
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  try {
    const counts = { total: DB.data.keys.length, active: 0, used: 0, expired: 0, revoked: 0 };
    for (const k of DB.data.keys) if (counts[k.status] !== undefined) counts[k.status]++;
    const u = DB.data.app_update;
    const days = [], created = [], verified = [];
    const nowDay = new Date(); nowDay.setHours(0, 0, 0, 0);
    for (let i = 13; i >= 0; i--) {
      const start = nowDay.getTime() - i * 86400000, end = start + 86400000;
      days.push(new Date(start).toISOString().slice(5, 10));
      created.push(DB.data.key_events.filter(e => e.event === 'created' && e.created_at >= start && e.created_at < end).length);
      verified.push(DB.data.key_events.filter(e => e.event === 'verified' && e.created_at >= start && e.created_at < end).length);
    }
    const keyById = {};
    for (const k of DB.data.keys) keyById[k.id] = k;
    const recent = DB.data.key_events.slice().sort((a, b2) => b2.created_at - a.created_at).slice(0, 10)
      .map(e => ({ key: (keyById[e.key_id] || {}).key || '?', label: (keyById[e.key_id] || {}).label || '', status: (keyById[e.key_id] || {}).status || '', event: e.event, created_at: e.created_at, device_id: e.device_id }));
    return ok(res, {
      keys: counts,
      current_version: { version_name: u.version_name, version_code: u.version_code, force_update: u.force_update === 1 },
      chart: { days, created, verified }, recent_activity: recent
    });
  } catch (e) { return fail(res, 500, 'Could not load stats'); }
});

/* ---------- admin: keys ---------- */
app.get('/api/admin/keys', requireAdmin, (req, res) => {
  try {
    const status = req.query.status, q = (req.query.q || '').trim().toLowerCase();
    const limit = Math.min(Math.max(parseInt(req.query.limit || '50', 10) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset || '0', 10) || 0, 0);
    let rows = DB.data.keys.slice().sort((a, b2) => b2.created_at - a.created_at);
    if (['active', 'used', 'expired', 'revoked'].includes(status)) rows = rows.filter(k => k.status === status);
    if (q) rows = rows.filter(k => k.key.toLowerCase().includes(q) || (k.label || '').toLowerCase().includes(q));
    const total = rows.length;
    rows = rows.slice(offset, offset + limit).map(k => ({
      id: k.id, key: k.key, prefix: k.prefix, label: k.label, status: k.status,
      single_use: k.single_use, created_at: k.created_at, expires_at: k.expires_at,
      used_at: k.used_at, device_id: k.device_id, use_count: k.use_count
    }));
    return ok(res, { total, limit, offset, keys: rows });
  } catch (e) { return fail(res, 500, 'Could not list keys'); }
});

app.post('/api/admin/keys', requireAdmin, (req, res) => {
  try {
    const b = req.body || {};
    let prefix = typeof b.prefix === 'string' ? b.prefix.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12) : '';
    if (!prefix) prefix = 'KMJ';
    const label = typeof b.label === 'string' ? b.label.trim().slice(0, 64) : '';
    let count = parseInt(b.count, 10);
    if (!Number.isFinite(count) || count < 1 || count > 100) count = 1;
    let expiresAt = null;
    if (b.expiry_days === 1 || b.expiry_days === 7 || b.expiry_days === 30) {
      expiresAt = Date.now() + b.expiry_days * 86400000;
    } else if (b.expiry_days !== null && b.expiry_days !== undefined && b.expiry_days !== 'lifetime') {
      return fail(res, 400, 'expiry_days must be 1, 7, 30 or null (lifetime)');
    }
    const singleUse = b.single_use === true || b.single_use === 1 ? 1 : 0;
    const made = [], now = Date.now(), existing = new Set(DB.data.keys.map(k => k.key));
    for (let i = 0; i < count; i++) {
      let k = generateKey(prefix), guard = 0;
      while (existing.has(k) && guard++ < 10) k = generateKey(prefix);
      existing.add(k);
      const id = DB.next('keys');
      DB.data.keys.push({ id, key: k, prefix, label, status: 'active', single_use: singleUse, created_at: now, expires_at: expiresAt, used_at: 0, device_id: '', use_count: 0 });
      DB.data.key_events.push({ id: DB.next('key_events'), key_id: id, event: 'created', device_id: '', created_at: now });
      made.push({ id, key: k });
    }
    DB.save();
    return ok(res, { generated: made.length, keys: made });
  } catch (e) { return fail(res, 500, 'Could not generate keys'); }
});

app.post('/api/admin/keys/:id/revoke', requireAdmin, (req, res) => {
  try {
    const row = findKeyById(parseInt(req.params.id, 10));
    if (!row) return fail(res, 404, 'Key not found');
    row.status = 'revoked';
    DB.data.key_events.push({ id: DB.next('key_events'), key_id: row.id, event: 'revoked', device_id: '', created_at: Date.now() });
    DB.save();
    return ok(res, { message: 'Key revoked' });
  } catch (e) { return fail(res, 500, 'Could not revoke key'); }
});

app.delete('/api/admin/keys/:id', requireAdmin, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const idx = DB.data.keys.findIndex(k => k.id === id);
    if (idx === -1) return fail(res, 404, 'Key not found');
    DB.data.keys.splice(idx, 1);
    DB.data.key_events = DB.data.key_events.filter(e => e.key_id !== id);
    DB.save();
    return ok(res, { message: 'Key deleted' });
  } catch (e) { return fail(res, 500, 'Could not delete key'); }
});

app.get('/api/admin/keys/export', requireAdmin, (req, res) => {
  try {
    const esc = (v) => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
    const lines = ['key,prefix,label,status,single_use,created_at,expires_at,use_count'];
    const rows = DB.data.keys.slice().sort((a, b2) => b2.created_at - a.created_at);
    for (const r of rows) {
      lines.push([r.key, r.prefix, r.label, r.status, r.single_use,
        new Date(r.created_at).toISOString(),
        r.expires_at ? new Date(r.expires_at).toISOString() : 'lifetime',
        r.use_count].map(esc).join(','));
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="kmj-keys-export.csv"');
    res.send(lines.join('\n'));
  } catch (e) { return fail(res, 500, 'Export failed'); }
});

/* ---------- admin: update management ---------- */
app.get('/api/admin/update', requireAdmin, (req, res) => {
  try { return ok(res, { update: DB.data.app_update }); }
  catch (e) { return fail(res, 500, 'Could not load update info'); }
});

app.put('/api/admin/update', requireAdmin, (req, res) => {
  try {
    const b = req.body || {};
    if (typeof b.version_name !== 'string' || !/^[A-Za-z0-9._-]{1,32}$/.test(b.version_name.trim())) {
      return fail(res, 400, 'version_name is invalid (e.g. 1.2.0)');
    }
    const vc = parseInt(b.version_code, 10);
    if (!Number.isFinite(vc) || vc < 0 || vc > 2100000000) {
      return fail(res, 400, 'version_code must be a positive integer');
    }
    if (typeof b.download_url !== 'string' || !isHttpUrl(b.download_url)) {
      return fail(res, 400, 'download_url must be a valid http(s) URL');
    }
    if (b.website_url && b.website_url.trim() && !isHttpUrl(b.website_url)) {
      return fail(res, 400, 'website_url must be a valid http(s) URL or empty');
    }
    DB.data.app_update = {
      version_name: b.version_name.trim(), version_code: vc,
      title: (b.title || 'New Update Available').toString().slice(0, 120),
      changelog: (b.changelog || '').toString().slice(0, 4000),
      download_url: b.download_url.trim(),
      website_url: (b.website_url || '').toString().trim(),
      force_update: b.force_update ? 1 : 0, updated_at: Date.now()
    };
    DB.save();
    return ok(res, { message: 'Update info saved' });
  } catch (e) { return fail(res, 500, 'Could not save update info'); }
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return fail(res, 404, 'Not found');
  next();
});

/* ================= setup CLI ================= */
function ask(q, hidden) {
  return new Promise((resolve) => {
    if (!hidden) {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      rl.question(q, (a) => { rl.close(); resolve(a); });
      return;
    }
    const stdin = process.stdin;
    // Non-TTY (piped) stdin has no setRawMode — fall back to visible input.
    if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      return new Promise((res2) => rl.question(q, (a) => { rl.close(); res2(a); }));
    }
    let pw = '';
    process.stdout.write(q);
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    const onData = (ch) => {
      if (ch === '\n' || ch === '\r' || ch === '\u0004') {
        stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', onData);
        process.stdout.write('\n'); resolve(pw);
      } else if (ch === '\u0003') { process.exit(1); }
      else if (ch === '\u007f') { pw = pw.slice(0, -1); }
      else { pw += ch; }
    };
    stdin.on('data', onData);
  });
}

async function runSetup() {
  if (DB.data.admins.length > 0) { console.log('An admin already exists. Setup is disabled.'); process.exit(0); }
  // Piped (non-TTY) stdin: read all lines upfront — sequential readline
  // interfaces are unreliable on piped streams.
  const pipedLines = await readPipedLines();
  let lineIdx = 0;
  const ask2 = async (q, hidden) => {
    if (pipedLines) {
      const v = (pipedLines[lineIdx++] || '').replace(/\r$/, '');
      process.stdout.write(q + (hidden ? '********\n' : v + '\n'));
      return v;
    }
    return ask(q, hidden);
  };
  console.log('=== KMJ TIPS — create the first admin ===');
  const username = (await ask2('Username (3-32 chars): ')).trim();
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) { console.log('Invalid username.'); process.exit(1); }
  const pw1 = await ask2('Password (min 8 chars): ', true);
  const pw2 = await ask2('Repeat password: ', true);
  if (pw1 !== pw2) { console.log('Passwords do not match.'); process.exit(1); }
  if (pw1.length < 8 || pw1.length > 128) { console.log('Password must be 8-128 chars.'); process.exit(1); }
  DB.data.admins.push({ id: DB.next('admins'), username, password_hash: bcrypt.hashSync(pw1, 12), created_at: Date.now() });
  DB.save();
  console.log('Admin "' + username + '" created. Start with: node bot.js');
  process.exit(0);
}

function readPipedLines() {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    if (stdin.isTTY) return resolve(null);
    let data = '';
    stdin.setEncoding('utf8');
    stdin.on('data', (c) => { data += c; });
    stdin.on('end', () => resolve(data.split('\n')));
    stdin.resume();
  });
}

/* ================= boot ================= */
if (process.argv.includes('--setup')) {
  runSetup();
} else {
  app.listen(PORT, () => {
    console.log('KMJ TIPS panel running on http://localhost:' + PORT);
    if (DB.data.admins.length === 0) {
      console.log('No admin yet — run "node bot.js --setup" or use "First run?" on the login page.');
    }
  });
}
