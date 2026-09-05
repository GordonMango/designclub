/**
 * Design Club — application intake + password-protected admin.
 *
 * Public:
 *   POST /api/apply              store one application
 *
 * Admin (password required):
 *   POST /api/admin/login        exchange the password for a session cookie
 *   POST /api/admin/logout       clear the session cookie
 *   GET  /api/admin/applications list every application
 *   DELETE /api/admin/applications/:id  remove one
 *
 * The password lives in the ADMIN_PASSWORD secret, never in this file:
 *   npx wrangler secret put ADMIN_PASSWORD
 *
 * Sessions are stateless HMAC-signed tokens in an HttpOnly cookie. The signing
 * key is derived from the password, so changing the password logs everyone out.
 */

const ROLES = [
  'Vice President / Operations Lead',
  'Director of Competitions',
  'Secretariat of Outreach',
  'Director of Sponsorship & Fundraising',
  'Social Media Managers',
  'Engineering Mentors',
  'CAD & Mechanical Design Mentors',
  'Coding & AI Mentors',
  'Electronics & Robotics Mentors',
  'Research & Pitch Writers',
  'Prototype & Fabrication Assistants',
  'Event & Workshop Assistants',
  'General member',
];

const GRADES = ['5', '6', '7', '8', '9', '10', '11', '12'];
const LIMITS = { name: 100, email: 200, why: 2000, experience: 1000 };

const APPLY_RATE_LIMIT = 5;      // submissions per IP per hour
const LOGIN_RATE_LIMIT = 8;      // password attempts per IP per 15 min
const SESSION_TTL_SECONDS = 60 * 60 * 8;
const COOKIE = 'dc_admin';

/* ---------- small helpers ---------- */

const enc = new TextEncoder();

const json = (status, body, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });

const clean = (v) => (typeof v === 'string' ? v.trim() : '');

const b64url = (bytes) => {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const fromB64url = (str) => {
  const pad = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(pad + '==='.slice((pad.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

function readCookie(request, name) {
  const header = request.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return '';
}

/* ---------- auth ---------- */

async function signingKey(password) {
  // Derive the HMAC key from the password so rotating it invalidates sessions.
  const digest = await crypto.subtle.digest('SHA-256', enc.encode('dc:' + password));
  return crypto.subtle.importKey('raw', digest, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

async function issueToken(password) {
  const payload = b64url(enc.encode(JSON.stringify({ exp: Date.now() + SESSION_TTL_SECONDS * 1000 })));
  const key = await signingKey(password);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return payload + '.' + b64url(new Uint8Array(sig));
}

async function tokenValid(password, token) {
  const [payload, sig] = String(token || '').split('.');
  if (!payload || !sig) return false;
  try {
    const key = await signingKey(password);
    const ok = await crypto.subtle.verify('HMAC', key, fromB64url(sig), enc.encode(payload));
    if (!ok) return false;
    const { exp } = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    return typeof exp === 'number' && Date.now() < exp;
  } catch {
    return false;
  }
}

async function passwordMatches(supplied, actual) {
  // Compare digests so the check takes the same time regardless of input.
  const [a, b] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(supplied)),
    crypto.subtle.digest('SHA-256', enc.encode(actual)),
  ]);
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.min(x.length, y.length); i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function requireAuth(request, env) {
  if (!env.ADMIN_PASSWORD) return false;
  return tokenValid(env.ADMIN_PASSWORD, readCookie(request, COOKIE));
}

function sessionCookie(request, value, maxAge) {
  const secure = new URL(request.url).protocol === 'https:' ? ' Secure;' : '';
  return `${COOKIE}=${value}; Path=/; HttpOnly;${secure} SameSite=Strict; Max-Age=${maxAge}`;
}

/* ---------- public: apply ---------- */

function validate(f) {
  const name = clean(f.name);
  const email = clean(f.email);
  const grade = clean(f.grade);
  const role = clean(f.role);
  const why = clean(f.why);
  const experience = clean(f.experience);

  if (!name) return { error: 'Please enter your name.' };
  if (name.length > LIMITS.name) return { error: 'That name is too long.' };

  // Intentionally loose — real addresses vary more than most regexes allow.
  if (!email || !/^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(email))
    return { error: 'Please enter a valid email address.' };
  if (email.length > LIMITS.email) return { error: 'That email is too long.' };

  if (!GRADES.includes(grade)) return { error: 'Please choose your grade.' };
  if (!ROLES.includes(role)) return { error: 'Please choose a role.' };

  if (!why) return { error: 'Please tell us why you want to join.' };
  if (why.length > LIMITS.why) return { error: 'Please keep it under 2000 characters.' };
  if (experience.length > LIMITS.experience)
    return { error: 'Please keep experience under 1000 characters.' };

  return { value: { name, email, grade, role, why, experience } };
}

async function handleApply(request, env) {
  if (!env.DB) return json(500, { error: 'Applications are not configured yet.' });

  let form;
  try {
    const ct = request.headers.get('content-type') || '';
    form = ct.includes('application/json')
      ? await request.json()
      : Object.fromEntries(await request.formData());
  } catch {
    return json(400, { error: 'Could not read that submission.' });
  }

  // Honeypot: a real person never fills a hidden field. Accept silently so
  // bots get a success and do not retry.
  if (clean(form.website)) return json(200, { ok: true });

  const { error, value } = validate(form);
  if (error) return json(400, { error });

  const ip = request.headers.get('cf-connecting-ip') || 'unknown';

  try {
    const recent = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM applications
       WHERE ip = ? AND created_at > datetime('now', '-1 hour')`
    ).bind(ip).first();

    if (recent && recent.n >= APPLY_RATE_LIMIT)
      return json(429, { error: 'Too many submissions. Please try again later.' });

    await env.DB.prepare(
      `INSERT INTO applications (name, email, grade, role, experience, why, ip, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      value.name, value.email, value.grade, value.role, value.experience, value.why,
      ip, (request.headers.get('user-agent') || '').slice(0, 300)
    ).run();
  } catch (err) {
    console.error('application insert failed', err);
    return json(500, { error: 'Something went wrong saving that. Please try again.' });
  }

  return json(200, { ok: true });
}

/* ---------- admin ---------- */

async function handleLogin(request, env) {
  if (!env.ADMIN_PASSWORD)
    return json(500, { error: 'No admin password is set. Run: wrangler secret put ADMIN_PASSWORD' });

  const ip = request.headers.get('cf-connecting-ip') || 'unknown';

  // Throttle guessing before checking anything.
  if (env.DB) {
    const tries = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM login_attempts
       WHERE ip = ? AND created_at > datetime('now', '-15 minutes')`
    ).bind(ip).first();
    if (tries && tries.n >= LOGIN_RATE_LIMIT)
      return json(429, { error: 'Too many attempts. Wait 15 minutes and try again.' });
  }

  let supplied = '';
  try {
    supplied = clean((await request.json()).password);
  } catch {
    return json(400, { error: 'Could not read that request.' });
  }

  if (!(await passwordMatches(supplied, env.ADMIN_PASSWORD))) {
    if (env.DB) {
      await env.DB.prepare('INSERT INTO login_attempts (ip) VALUES (?)').bind(ip).run();
    }
    return json(401, { error: 'Incorrect password.' });
  }

  // Clear the failure record on success so a legitimate typo streak resets.
  if (env.DB) {
    await env.DB.prepare('DELETE FROM login_attempts WHERE ip = ?').bind(ip).run();
  }

  const token = await issueToken(env.ADMIN_PASSWORD);
  return json(200, { ok: true }, { 'set-cookie': sessionCookie(request, token, SESSION_TTL_SECONDS) });
}

async function handleList(request, env) {
  const rows = await env.DB.prepare(
    `SELECT id, name, email, grade, role, experience, why, created_at
     FROM applications ORDER BY id DESC`
  ).all();
  return json(200, { ok: true, applications: rows.results || [] });
}

async function handleDelete(request, env, id) {
  if (!Number.isInteger(id)) return json(400, { error: 'Bad id.' });
  await env.DB.prepare('DELETE FROM applications WHERE id = ?').bind(id).run();
  return json(200, { ok: true });
}

/* ---------- router ---------- */

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (pathname === '/api/apply') {
      if (request.method !== 'POST') return json(405, { error: 'Method not allowed.' });
      return handleApply(request, env);
    }

    if (pathname === '/api/admin/login') {
      if (request.method !== 'POST') return json(405, { error: 'Method not allowed.' });
      return handleLogin(request, env);
    }

    if (pathname === '/api/admin/logout') {
      return json(200, { ok: true }, { 'set-cookie': sessionCookie(request, '', 0) });
    }

    if (pathname.startsWith('/api/admin/')) {
      if (!env.DB) return json(500, { error: 'Database is not configured yet.' });
      if (!(await requireAuth(request, env))) return json(401, { error: 'Not signed in.' });

      if (pathname === '/api/admin/applications' && request.method === 'GET')
        return handleList(request, env);

      const del = pathname.match(/^\/api\/admin\/applications\/(\d+)$/);
      if (del && request.method === 'DELETE')
        return handleDelete(request, env, Number(del[1]));

      return json(404, { error: 'Not found.' });
    }

    return env.ASSETS.fetch(request);
  },
};
