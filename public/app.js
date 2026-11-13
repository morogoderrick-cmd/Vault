'use strict';
const $ = id => document.getElementById(id), enc = new TextEncoder(), dec = new TextDecoder();
let key = null, user = '', items = [], version = 0, editId = null, idle = null, mode = 'login', busy = false;
const b64 = b => { let s = ''; for (const x of new Uint8Array(b)) s += String.fromCharCode(x); return btoa(s); };
const ub = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
const btn = (t, f, c) => { const b = el('button', c || '', t); b.type = 'button'; b.onclick = f; return b; };

async function api(m, u, b) {
  const r = await fetch(u, { method: m, headers: b ? { 'Content-Type': 'application/json' } : {}, body: b ? JSON.stringify(b) : undefined, credentials: 'same-origin' });
  let j = {}; try { j = await r.json(); } catch {}
  if (r.status === 401 && key) lock('Your session ended. Please log in again.');
  if (!r.ok) throw new Error(j.error || 'Something went wrong.');
  return j;
}
// One slow derivation makes two separate secrets: an encryption key (never leaves this device)
// and a login token (sent to the server, which can't use it to decrypt anything).
async function derive(u, pw) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode('vault-v2:' + u), iterations: 600000, hash: 'SHA-256' }, base, 256);
  const mk = await crypto.subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = async t => crypto.subtle.sign('HMAC', mk, enc.encode(t));
  return { key: await crypto.subtle.importKey('raw', await sig('enc'), 'AES-GCM', false, ['encrypt', 'decrypt']), auth: b64(await sig('auth')) };
}
async function seal(data, k = key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return JSON.stringify({ v: 2, iv: b64(iv), data: b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(JSON.stringify(data)))) });
}
async function open(blob, k = key) {
  const o = JSON.parse(blob);
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub(o.iv) }, k, ub(o.data))));
}
async function load() { const r = await api('GET', '/api/vault'); version = r.version; items = r.blob ? await open(r.blob) : []; render(); }
async function persist() {
  try { const r = await api('PUT', '/api/vault', { blob: await seal(items), version }); version = r.version; $('status').textContent = 'Saved and synced.'; }
  catch (e) { alert(e.message); if (/another device/.test(e.message)) { await load(); } else $('status').textContent = 'Not saved: ' + e.message; }
}

function setMode(m) {
  mode = m; $('aw2').hidden = m !== 'signup'; $('aerr').textContent = '';
  $('ago').textContent = m === 'signup' ? 'Create account' : 'Log in';
  $('aswap').textContent = m === 'signup' ? 'Have an account? Log in' : 'New here? Create an account';
  $('amsg').textContent = m === 'signup' ? 'Pick a username and a master password. Your vault will be available on every device you log in from.' : 'Log in to open your vault.';
}
$('aswap').onclick = () => setMode(mode === 'login' ? 'signup' : 'login');
$('ago').onclick = async () => {
  if (busy) return;
  const u = $('au').value.trim().toLowerCase(), pw = $('ap').value, err = $('aerr'); err.textContent = '';
  if (!/^[a-z0-9_.-]{3,20}$/.test(u)) { err.textContent = 'Username: 3 to 20 letters, numbers, dots, dashes or underscores.'; return; }
  if (mode === 'signup') {
    if (pw.length < 10) { err.textContent = 'Use at least 10 characters.'; return; }
    if (pw !== $('ap2').value) { err.textContent = 'The passwords don’t match.'; return; }
  } else if (!pw) return;
  busy = true; $('ago').textContent = 'Working…';
  try {
    const d = await derive(u, pw);
    await api('POST', mode === 'signup' ? '/api/signup' : '/api/login', { username: u, auth: d.auth });
    key = d.key; user = u; await load();
    $('auth').hidden = true; $('app').hidden = false; $('who').textContent = user; $('status').textContent = ''; resetForm(); bump();
  } catch (e) { key = null; err.textContent = e.message; }
  busy = false; setMode(mode);
};
['au', 'ap', 'ap2'].forEach(i => $(i).addEventListener('keydown', e => { if (e.key === 'Enter') $('ago').click(); }));

function lock(msg) {
  const was = key; key = null; items = []; clearTimeout(idle);
  if (was) api('POST', '/api/logout').catch(() => {});
  $('app').hidden = true; $('auth').hidden = false;
  ['au', 'ap', 'ap2', 'fSite', 'fUser', 'fPass', 'fNotes', 'cpo', 'cpn', 'cpn2', 'oldpw', 'q'].forEach(i => { $(i).value = ''; });
  $('list').replaceChildren(); setMode('login'); if (msg) $('aerr').textContent = msg;
}
$('out').onclick = () => lock();
const bump = () => { clearTimeout(idle); if (key) idle = setTimeout(() => lock('Logged out after 5 minutes of inactivity.'), 5 * 60000); };
['click', 'keydown', 'touchstart'].forEach(e => document.addEventListener(e, () => { if (key) bump(); }));
document.addEventListener('keydown', e => { if (e.key === 'Escape' && key) lock(); });

const safeUrl = u => { u = u.trim(); if (!u) return ''; if (!/^https?:\/\//i.test(u)) u = 'https://' + u; try { return new URL(u).href; } catch { return ''; } };
function addRow(l = '', u = '') {
  const r = el('div', 'row lr'), a = el('input', 'l'), b = el('input', 'u');
  a.setAttribute('list', 'lbls'); a.placeholder = 'Label (e.g. Frontend)'; a.setAttribute('aria-label', 'Link label'); a.value = l;
  b.placeholder = 'https://example.com/admin'; b.inputMode = 'url'; b.setAttribute('aria-label', 'Link address'); b.value = u;
  r.append(a, b, btn('Remove', () => { if ($('rows').children.length > 1) r.remove(); else { a.value = ''; b.value = ''; } }));
  $('rows').append(r);
}
const links = () => Array.from($('rows').children).map(r => ({ label: r.children[0].value.trim(), url: safeUrl(r.children[1].value) })).filter(l => l.url);
$('more').onclick = () => addRow();

function strength() {
  const p = $('fPass').value, e = $('strength'); if (!p) { e.textContent = ''; return; }
  const k = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(r => r.test(p)).length;
  const s = p.length >= 16 && k >= 3 ? 'Strong' : p.length >= 10 && k >= 3 ? 'Good' : p.length >= 8 && k >= 2 ? 'Fair' : 'Weak';
  e.textContent = 'Strength: ' + s + (items.some(x => x.pass === p && x.id !== editId) ? ' · already used for another website' : '');
}
$('fPass').oninput = strength;
$('show').onclick = () => { const t = $('fPass').type === 'password'; $('fPass').type = t ? 'text' : 'password'; $('show').textContent = t ? 'Hide' : 'Show'; };
$('gen').onclick = () => {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789' + ($('sym').checked ? '!@#$%^&*-_=+' : '');
  $('fPass').value = Array.from(crypto.getRandomValues(new Uint32Array(16)), x => c[x % c.length]).join('');
  $('fPass').type = 'text'; $('show').textContent = 'Hide'; strength();
};
function resetForm() {
  editId = null; ['fSite', 'fUser', 'fPass', 'fNotes'].forEach(i => { $(i).value = ''; });
  $('fPass').type = 'password'; $('show').textContent = 'Show'; $('rows').replaceChildren(); addRow(); strength();
  $('ftitle').textContent = 'Add a password'; $('add').textContent = 'Save'; $('cancel').hidden = true; $('ferr').textContent = '';
}
$('cancel').onclick = resetForm;
$('add').onclick = async () => {
  const site = $('fSite').value.trim(), pass = $('fPass').value;
  if (!site || !pass) { $('ferr').textContent = 'Add a website name and a password.'; return; }
  const rec = { site, links: links(), user: $('fUser').value.trim(), pass, notes: $('fNotes').value.trim() }, old = items.find(x => x.id === editId);
  if (old) Object.assign(old, rec); else items.push({ id: crypto.randomUUID(), ...rec });
  await persist(); resetForm(); render();
};
function edit(e) {
  resetForm(); editId = e.id; $('fSite').value = e.site; $('fUser').value = e.user || ''; $('fPass').value = e.pass; $('fNotes').value = e.notes || '';
  $('rows').replaceChildren(); (e.links && e.links.length ? e.links : [{ label: '', url: '' }]).forEach(l => addRow(l.label, l.url));
  $('ftitle').textContent = 'Edit ' + e.site; $('add').textContent = 'Update'; $('cancel').hidden = false; $('fbox').open = true; strength();
  $('fbox').scrollIntoView({ behavior: 'smooth' });
}
async function copy(t, b, lab, ms, clr) {
  try { await navigator.clipboard.writeText(t); b.textContent = 'Copied'; } catch { b.textContent = 'Copy failed'; }
  setTimeout(() => { b.textContent = lab; if (clr) navigator.clipboard.writeText('').catch(() => {}); }, ms);
}
function render() {
  const t = $('q').value.trim().toLowerCase(), L = $('list'); L.replaceChildren();
  const sh = items.filter(e => e.site.toLowerCase().includes(t)).sort((a, b) => (!!b.fav - !!a.fav) || a.site.localeCompare(b.site));
  if (!sh.length) { L.append(el('p', 'muted', items.length ? 'No websites match your search.' : 'Your vault is empty. Add your first password above.')); return; }
  for (const e of sh) {
    const d = el('div', 'entry'), m = el('div', 'muted'); d.append(el('h2', '', (e.fav ? '★ ' : '') + e.site));
    for (const l of e.links || []) {
      const r = el('div'); if (l.label) r.append(el('strong', '', l.label + ': '));
      if (/^https?:\/\//i.test(l.url)) { const a = el('a', '', l.url); a.href = l.url; a.target = '_blank'; a.rel = 'noopener noreferrer'; r.append(a); } else r.append(l.url);
      m.append(r);
    }
    if (e.user) m.append(el('div', '', e.user)); if (e.notes) m.append(el('div', 'notes', e.notes)); d.append(m);
    const p = el('div', 'pw', '••••••••••'), row = el('div', 'row'); let sw = false;
    row.append(
      btn('Show', ev => { sw = !sw; p.textContent = sw ? e.pass : '••••••••••'; ev.target.textContent = sw ? 'Hide' : 'Show'; }),
      btn('Copy password', ev => copy(e.pass, ev.target, 'Copy password', 20000, true)),
      ...(e.user ? [btn('Copy username', ev => copy(e.user, ev.target, 'Copy username', 2000))] : []),
      btn(e.fav ? 'Unpin' : 'Pin', async () => { e.fav = !e.fav; await persist(); render(); }),
      btn('Edit', () => edit(e)),
      btn('Remove', async () => { if (!confirm('Delete ' + e.site + '?')) return; items = items.filter(x => x.id !== e.id); await persist(); render(); }, 'bad'));
    d.append(p, row); L.append(d);
  }
}
$('q').oninput = render;

$('exp').onclick = async () => {
  const a = el('a'); a.href = URL.createObjectURL(new Blob([await seal(items)], { type: 'application/json' }));
  a.download = 'vault-backup.json'; a.click(); URL.revokeObjectURL(a.href);
};
$('igo').onclick = async () => {
  const f = $('ifile').files[0], msg = $('imsg'); msg.textContent = '';
  if (!f) { msg.textContent = 'Choose a backup file first.'; return; }
  try {
    const o = JSON.parse(await f.text()); let got;
    if (o.salt && o.iv && o.data) { // older standalone vault
      const pw = $('oldpw').value; if (!pw) { msg.textContent = 'Type the old vault’s master password.'; return; }
      const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
      const k = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: ub(o.salt), iterations: 600000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      got = JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub(o.iv) }, k, ub(o.data))));
    } else got = await open(JSON.stringify(o));
    let n = 0;
    for (const e of got) {
      if (!e || !e.site || !e.pass) continue;
      const lk = e.links || (e.url ? [{ label: '', url: e.url }] : []);
      if (items.some(x => x.site === e.site && (x.user || '') === (e.user || '') && x.pass === e.pass)) continue;
      items.push({ id: crypto.randomUUID(), site: e.site, links: lk, user: e.user || '', pass: e.pass, notes: e.notes || '', fav: !!e.fav }); n++;
    }
    await persist(); render(); $('ifile').value = ''; $('oldpw').value = ''; msg.textContent = n + ' entries imported.';
  } catch { msg.textContent = 'Could not open that backup. Check the file and the master password.'; }
};
$('cpgo').onclick = async () => {
  const m = $('cpmsg'), n = $('cpn').value; m.textContent = '';
  if (n.length < 10) { m.textContent = 'Use at least 10 characters.'; return; }
  if (n !== $('cpn2').value) { m.textContent = 'The new passwords don’t match.'; return; }
  m.textContent = 'Working…';
  try {
    const o = await derive(user, $('cpo').value), nw = await derive(user, n);
    const r = await api('POST', '/api/change-password', { auth: o.auth, newAuth: nw.auth, blob: await seal(items, nw.key), version });
    key = nw.key; version = r.version; ['cpo', 'cpn', 'cpn2'].forEach(i => { $(i).value = ''; });
    m.textContent = 'Master password changed. Export a new backup: older backups need the old password.';
  } catch (e) { m.textContent = e.message; }
};
setMode('login');
