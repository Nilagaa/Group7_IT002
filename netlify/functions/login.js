const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

const MAX_ATTEMPTS = 5;          // failed attempts before lockout
const LOCK_SECONDS = 30;         // lockout length (matches the front end)
const WINDOW_MS = 5 * 60 * 1000; // failures older than this are forgotten

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function keyHash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 32);
}

function json(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extraHeaders },
    body: JSON.stringify(body),
  };
}

function parseBody(event) {
  const raw = event.isBase64Encoded
    ? Buffer.from(event.body || '', 'base64').toString('utf8')
    : event.body || '';
  try {
    return JSON.parse(raw);
  } catch (e) {
    return Object.fromEntries(new URLSearchParams(raw));
  }
}

async function getState(store, key) {
  const now = Date.now();
  const s = (await store.get(key, { type: 'json' })) || { count: 0, firstAt: now, lockedUntil: 0 };
  // Reset if the lock has expired or the failure window has passed
  if ((s.lockedUntil && s.lockedUntil <= now) || (!s.lockedUntil && now - s.firstAt > WINDOW_MS)) {
    return { count: 0, firstAt: now, lockedUntil: 0 };
  }
  return s;
}

async function registerFailure(store, key, state) {
  const now = Date.now();
  if (state.count === 0) state.firstAt = now;
  state.count += 1;
  if (state.count >= MAX_ATTEMPTS) state.lockedUntil = now + LOCK_SECONDS * 1000;
  await store.setJSON(key, state);
  return state;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return json(405, { error: 'Method not allowed' });
  }

  try {
    const { username, password } = parseBody(event);

    if (!username || !password) {
      return json(400, { error: 'Username and password required' });
    }
    if (String(username).length > 64 || String(password).length > 64) {
      return json(400, { error: 'Input too long' });
    }

    const ip =
      event.headers['x-nf-client-connection-ip'] ||
      (event.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
      'unknown';

    const users = getStore({
      name: 'users',
      consistency: 'strong',
      siteID: process.env.NETLIFY_SITE_ID,
      token: process.env.NETLIFY_TOKEN,
    });
    const attempts = getStore({
      name: 'login-attempts',
      consistency: 'strong',
      siteID: process.env.NETLIFY_SITE_ID,
      token: process.env.NETLIFY_TOKEN,
    });

    const ipKey = `ip-${keyHash(ip)}`;
    const userKey = `user-${keyHash(String(username).toLowerCase())}`;
    const [ipState, userState] = await Promise.all([
      getState(attempts, ipKey),
      getState(attempts, userKey),
    ]);

    // Already locked? Reject before doing any password work.
    const now = Date.now();
    const lockedUntil = Math.max(ipState.lockedUntil, userState.lockedUntil);
    if (lockedUntil > now) {
      const retryAfter = Math.ceil((lockedUntil - now) / 1000);
      return json(
        429,
        { success: false, error: 'Too many failed attempts.', locked: true, retry_after: retryAfter, attempts_remaining: 0 },
        { 'Retry-After': String(retryAfter) }
      );
    }

    const userData = await users.get(String(username).toLowerCase(), { type: 'json' });
    const valid = userData && hashPassword(password) === userData.passwordHash;

    if (!valid) {
      const [newIp, newUser] = await Promise.all([
        registerFailure(attempts, ipKey, ipState),
        registerFailure(attempts, userKey, userState),
      ]);

      const newLock = Math.max(newIp.lockedUntil, newUser.lockedUntil);
      if (newLock > Date.now()) {
        return json(
          429,
          { success: false, error: 'Too many failed attempts.', locked: true, retry_after: LOCK_SECONDS, attempts_remaining: 0 },
          { 'Retry-After': String(LOCK_SECONDS) }
        );
      }

      return json(401, {
        success: false,
        error: 'Invalid username or password',
        attempts_remaining: MAX_ATTEMPTS - Math.max(newIp.count, newUser.count),
      });
    }

    // Success: clear this account's failure counter (IP counter is left alone on purpose)
    await attempts.delete(userKey);

    const token = crypto.randomBytes(32).toString('hex');
    return json(200, { success: true, token, privilege: userData.privilege || 'user' });

  } catch (err) {
    console.error('Login error:', err);
    return json(500, { error: 'Internal server error' });
  }
};