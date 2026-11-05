// WebSec Start — серверная часть (Netlify Functions v2 + Netlify Blobs).
// Хранит аккаунты, прогресс и рейтинг. Внешние сервисы не нужны.
//
//   GET    /api/ping
//   POST   /api/register   { username, password }
//   POST   /api/login      { username, password }
//   POST   /api/logout                      (Authorization: Bearer <token>)
//   GET    /api/me                          → профиль и прогресс
//   PUT    /api/progress   { lessons, missions }
//   DELETE /api/me                          → удалить аккаунт
//   GET    /api/scoreboard

import crypto from 'node:crypto';
import { promisify } from 'node:util';

const pbkdf2 = promisify(crypto.pbkdf2);

// Сколько шагов в каждой лаборатории (должно совпадать с LAB_DEFS в index.html)
const STEPS = { a01:3, a02:3, a03:3, a04:3, a05:4, a06:3, a07:3, a08:3, a09:3, a10:3, b01:4, b02:4 };
const CORE = Object.keys(STEPS).filter(k => k[0] === 'a');
const BONUS = Object.keys(STEPS).filter(k => k[0] === 'b');
const MISSIONS = Array.from({ length: 10 }, (_, i) => 'm' + (i + 1));

const ITER = 120000;                       // итерации PBKDF2
const SESSION_TTL = 30 * 24 * 3600 * 1000; // 30 дней
const MAX_FAILS = 8;                       // неверных паролей подряд до блокировки
const LOCK_MS = 10 * 60 * 1000;            // блокировка на 10 минут
const USER_RE = /^[A-Za-z0-9_.-]{3,20}$/;

class HttpError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

let _stores = null;
export function __useStores(s) { _stores = s; }   // для тестов
async function getStores() {
  if (_stores) return _stores;
  const { getStore } = await import('@netlify/blobs');
  _stores = { users: getStore('users'), sessions: getStore('sessions') };
  return _stores;
}

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
});

async function readBody(req) {
  const text = await req.text();
  if (text.length > 20000) throw new HttpError(413, 'too_large');
  if (!text) return {};
  try { return JSON.parse(text); } catch { throw new HttpError(400, 'bad_json'); }
}

async function hashPw(pw, salt) {
  return (await pbkdf2(pw, salt, ITER, 32, 'sha256')).toString('hex');
}
function safeEq(a, b) {
  const x = Buffer.from(a, 'hex'), y = Buffer.from(b, 'hex');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// Приводим присланный клиентом прогресс к известной форме
function sanitize(lessons, missions) {
  const L = {};
  for (const id of Object.keys(STEPS)) {
    const l = lessons && typeof lessons === 'object' ? lessons[id] : null;
    if (!l || typeof l !== 'object') continue;
    const labSteps = {};
    for (let i = 0; i < STEPS[id]; i++) if (l.labSteps && l.labSteps[i] === true) labSteps[i] = true;
    let status = l.status === 'passed' ? 'passed' : 'read';
    if (status === 'passed' && !labSteps[STEPS[id] - 1]) status = 'read';
    L[id] = { status, labSteps };
  }
  const M = {};
  for (const m of MISSIONS) if (missions && missions[m] === true) M[m] = true;
  return { lessons: L, missions: M };
}

function score(rec) {
  const L = rec.lessons || {};
  let flags = 0, steps = 0, bonus = 0;
  for (const id of CORE) {
    if (L[id] && L[id].status === 'passed') flags++;
    if (L[id] && L[id].labSteps) steps += Object.keys(L[id].labSteps).length;
  }
  for (const id of BONUS) if (L[id] && L[id].status === 'passed') bonus++;
  return { flags, steps, bonus, missions: Object.keys(rec.missions || {}).length };
}

async function newSession(stores, key) {
  const token = crypto.randomBytes(32).toString('hex');
  await stores.sessions.setJSON(token, { u: key, exp: Date.now() + SESSION_TTL });
  return token;
}

async function auth(req, stores) {
  const m = (req.headers.get('authorization') || '').match(/^Bearer ([a-f0-9]{64})$/);
  if (!m) throw new HttpError(401, 'unauthorized');
  const sess = await stores.sessions.get(m[1], { type: 'json' });
  if (!sess || sess.exp < Date.now()) {
    if (sess) await stores.sessions.delete(m[1]);
    throw new HttpError(401, 'unauthorized');
  }
  const rec = await stores.users.get('u_' + sess.u, { type: 'json' });
  if (!rec) throw new HttpError(401, 'unauthorized');
  return { token: m[1], key: sess.u, rec };
}

const profile = rec => ({ username: rec.username, lessons: rec.lessons || {}, missions: rec.missions || {} });

async function route(req) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, '').replace(/\/$/, '');
  const method = req.method;

  if (path === 'ping' && method === 'GET') return json({ ok: true });

  const stores = await getStores();

  if (path === 'register' && method === 'POST') {
    const { username, password } = await readBody(req);
    if (typeof username !== 'string' || !USER_RE.test(username)) throw new HttpError(400, 'bad_user');
    if (typeof password !== 'string' || password.length < 6 || password.length > 200) throw new HttpError(400, 'short_pass');
    const key = username.toLowerCase();
    if (await stores.users.get('u_' + key, { type: 'json' })) throw new HttpError(409, 'taken');
    const salt = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    const rec = {
      username, salt, hash: await hashPw(password, salt), iter: ITER,
      createdAt: now, updatedAt: now, lastFlagAt: 0,
      lessons: {}, missions: {}, fails: 0, lockUntil: 0
    };
    const w = await stores.users.setJSON('u_' + key, rec, { onlyIfNew: true });
    if (w && w.modified === false) throw new HttpError(409, 'taken');
    return json({ token: await newSession(stores, key), ...profile(rec) }, 201);
  }

  if (path === 'login' && method === 'POST') {
    const { username, password } = await readBody(req);
    if (typeof username !== 'string' || typeof password !== 'string') throw new HttpError(401, 'bad_creds');
    const key = username.trim().toLowerCase();
    const rec = USER_RE.test(key) ? await stores.users.get('u_' + key, { type: 'json' }) : null;
    if (!rec) { await hashPw(password.slice(0, 200), 'x'.repeat(32)); throw new HttpError(401, 'bad_creds'); }
    if (rec.lockUntil && rec.lockUntil > Date.now()) throw new HttpError(429, 'locked');
    const ok = safeEq(await hashPw(password.slice(0, 200), rec.salt), rec.hash);
    if (!ok) {
      rec.fails = (rec.fails || 0) + 1;
      if (rec.fails >= MAX_FAILS) { rec.lockUntil = Date.now() + LOCK_MS; rec.fails = 0; }
      await stores.users.setJSON('u_' + key, rec);
      throw new HttpError(rec.lockUntil > Date.now() ? 429 : 401, rec.lockUntil > Date.now() ? 'locked' : 'bad_creds');
    }
    if (rec.fails || rec.lockUntil) { rec.fails = 0; rec.lockUntil = 0; await stores.users.setJSON('u_' + key, rec); }
    return json({ token: await newSession(stores, key), ...profile(rec) });
  }

  if (path === 'logout' && method === 'POST') {
    const a = await auth(req, stores);
    await stores.sessions.delete(a.token);
    return json({ ok: true });
  }

  if (path === 'me' && method === 'GET') {
    const a = await auth(req, stores);
    return json(profile(a.rec));
  }

  if (path === 'me' && method === 'DELETE') {
    const a = await auth(req, stores);
    await stores.users.delete('u_' + a.key);
    await stores.sessions.delete(a.token);
    return json({ ok: true });
  }

  if (path === 'progress' && method === 'PUT') {
    const a = await auth(req, stores);
    const body = await readBody(req);
    const { lessons, missions } = sanitize(body.lessons, body.missions);
    const before = score(a.rec);
    a.rec.lessons = lessons;
    a.rec.missions = missions;
    a.rec.updatedAt = Date.now();
    const after = score(a.rec);
    if (after.flags + after.bonus > before.flags + before.bonus) a.rec.lastFlagAt = Date.now();
    await stores.users.setJSON('u_' + a.key, a.rec);
    return json({ ok: true, ...after });
  }

  if (path === 'scoreboard' && method === 'GET') {
    const list = await stores.users.list({ prefix: 'u_' });
    const keys = (list.blobs || []).map(b => b.key).slice(0, 500);
    const recs = await Promise.all(keys.map(k => stores.users.get(k, { type: 'json' })));
    const rows = recs.filter(Boolean)
      .map(r => ({ username: r.username, ...score(r), lastFlagAt: r.lastFlagAt || 0 }))
      .filter(r => r.flags + r.bonus + r.steps > 0)
      .sort((a, b) => (b.flags - a.flags) || (b.bonus - a.bonus) || (b.steps - a.steps) ||
                      ((a.lastFlagAt || Infinity) - (b.lastFlagAt || Infinity)))
      .slice(0, 50);
    return json({ rows });
  }

  throw new HttpError(404, 'not_found');
}

export default async (req) => {
  try {
    return await route(req);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.code }, e.status);
    console.error(e);
    return json({ error: 'server_error' }, 500);
  }
};

export const config = { path: '/api/*' };
