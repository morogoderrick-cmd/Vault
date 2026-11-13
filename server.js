// Zero-knowledge vault server: it only ever stores scrambled (encrypted) data.
const express = require('express'), crypto = require('crypto'), path = require('path'), { Pool } = require('pg');
const SECRET = process.env.SESSION_SECRET;
if (!SECRET || SECRET.length < 32) { console.error('Set SESSION_SECRET to 32+ random characters.'); process.exit(1); }
const DB = process.env.DATABASE_URL;
if (!DB) { console.error('Set DATABASE_URL to your Postgres connection string.'); process.exit(1); }
const pool = new Pool({ connectionString: DB, ssl: /localhost|127\.0\.0\.1/.test(DB) ? false : { rejectUnauthorized: false } });
pool.query(`create table if not exists users(username text primary key, salt bytea not null, hash bytea not null,
  blob text, version int not null default 0, created timestamptz default now())`).catch(e => { console.error(e.message); process.exit(1); });

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.set({ 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
  if (req.path.startsWith('/api')) res.set('Cache-Control', 'no-store');
  next();
});

const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
const mkToken = u => { const p = Buffer.from(JSON.stringify({ u, e: Date.now() + 12 * 3600e3 })).toString('base64url'); return p + '.' + sign(p); };
function who(req) {
  const c = (req.headers.cookie || '').split(/;\s*/).find(x => x.startsWith('vt='));
  if (!c) return null;
  const [p, s] = c.slice(3).split('.'); if (!p || !s) return null;
  const ok = sign(p); if (s.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(ok))) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url')); return o.e > Date.now() ? o.u : null; } catch { return null; }
}
const cookie = (res, t, age) => res.append('Set-Cookie', `vt=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
const scrypt = (a, s) => new Promise((ok, no) => crypto.scrypt(a, s, 64, (e, k) => e ? no(e) : ok(k)));
const wrap = f => (req, res) => f(req, res).catch(e => { console.error(e.message); res.status(500).json({ error: 'Server error. Please try again.' }); });
const need = (req, res, next) => { const u = who(req); if (!u) return res.status(401).json({ error: 'Please log in again.' }); req.u = u; next(); };
const okUser = u => /^[a-z0-9_.-]{3,20}$/.test(u), okAuth = a => typeof a === 'string' && /^[A-Za-z0-9+/=_-]{40,64}$/.test(a);

const fails = new Map();
const limited = k => { const f = fails.get(k); return f && f.n >= 8 && Date.now() < f.t; };
const bad = k => { const f = fails.get(k) || { n: 0 }; f.n++; f.t = Date.now() + 15 * 60e3; fails.set(k, f); };
setInterval(() => { for (const [k, f] of fails) if (Date.now() > f.t) fails.delete(k); }, 600e3).unref();

app.post('/api/signup', wrap(async (req, res) => {
  const u = String(req.body.username || '').toLowerCase(), a = req.body.auth, k = 'su:' + req.ip;
  if (!okUser(u) || !okAuth(a)) return res.status(400).json({ error: 'Use a username of 3 to 20 letters, numbers, dots, dashes or underscores.' });
  if (limited(k)) return res.status(429).json({ error: 'Too many sign-ups from this network. Try again later.' });
  const salt = crypto.randomBytes(16), hash = await scrypt(a, salt);
  try { await pool.query('insert into users(username,salt,hash) values($1,$2,$3)', [u, salt, hash]); }
  catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'That username is taken.' }); throw e; }
  for (let i = 0; i < 3; i++) bad(k); // about 2 sign-ups per hour per network
  cookie(res, mkToken(u), 43200); res.json({ ok: true });
}));
app.post('/api/login', wrap(async (req, res) => {
  const u = String(req.body.username || '').toLowerCase(), a = req.body.auth, k = req.ip + ':' + u;
  if (!okUser(u) || !okAuth(a)) return res.status(400).json({ error: 'Wrong username or master password.' });
  if (limited(k)) return res.status(429).json({ error: 'Too many tries. Wait 15 minutes.' });
  const row = (await pool.query('select salt,hash from users where username=$1', [u])).rows[0];
  const h = await scrypt(a, row ? row.salt : Buffer.alloc(16));
  if (!row || !crypto.timingSafeEqual(h, row.hash)) { bad(k); return res.status(401).json({ error: 'Wrong username or master password.' }); }
  fails.delete(k); cookie(res, mkToken(u), 43200); res.json({ ok: true });
}));
app.post('/api/logout', (req, res) => { cookie(res, '', 0); res.json({ ok: true }); });
app.get('/api/vault', need, wrap(async (req, res) => {
  const row = (await pool.query('select blob,version from users where username=$1', [req.u])).rows[0];
  if (!row) return res.status(401).json({ error: 'Please log in again.' });
  res.json({ blob: row.blob, version: row.version });
}));
app.put('/api/vault', need, wrap(async (req, res) => {
  const { blob, version } = req.body;
  if (typeof blob !== 'string' || blob.length > 900000 || !Number.isInteger(version)) return res.status(400).json({ error: 'Bad request.' });
  const r = await pool.query('update users set blob=$1, version=version+1 where username=$2 and version=$3 returning version', [blob, req.u, version]);
  if (!r.rowCount) return res.status(409).json({ error: 'This vault changed on another device. Reloading the latest version.' });
  res.json({ version: r.rows[0].version });
}));
app.post('/api/change-password', need, wrap(async (req, res) => {
  const { auth, newAuth, blob, version } = req.body, k = 'cp:' + req.u;
  if (!okAuth(auth) || !okAuth(newAuth) || typeof blob !== 'string' || blob.length > 900000 || !Number.isInteger(version)) return res.status(400).json({ error: 'Bad request.' });
  if (limited(k)) return res.status(429).json({ error: 'Too many tries. Wait 15 minutes.' });
  const row = (await pool.query('select salt,hash from users where username=$1', [req.u])).rows[0];
  if (!row || !crypto.timingSafeEqual(await scrypt(auth, row.salt), row.hash)) { bad(k); return res.status(403).json({ error: 'Your current master password is wrong.' }); }
  const salt = crypto.randomBytes(16), hash = await scrypt(newAuth, salt);
  const r = await pool.query('update users set salt=$1, hash=$2, blob=$3, version=version+1 where username=$4 and version=$5 returning version', [salt, hash, blob, req.u, version]);
  if (!r.rowCount) return res.status(409).json({ error: 'This vault changed on another device. Reload and try again.' });
  res.json({ version: r.rows[0].version });
}));
app.use(express.static(path.join(__dirname, 'public')));
app.listen(process.env.PORT || 3000, () => console.log('Vault running'));
