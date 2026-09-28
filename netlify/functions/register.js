const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  try {
    const { username, password } = JSON.parse(event.body);

    if (!username || !password) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Username and password required' }) };
    }
    if (username.length < 3) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Username must be at least 3 characters' }) };
    }
    if (password.length < 6) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Password must be at least 6 characters' }) };
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Username can only contain letters, numbers, and underscores' }) };
    }

    const store = getStore({
      name: 'users',
      consistency: 'strong',
      siteID: process.env.NETLIFY_SITE_ID,
      token: process.env.NETLIFY_TOKEN,
    });

    const key = username.toLowerCase();
    const existing = await store.get(key);

    if (existing) {
      return {
        statusCode: 409,
        body: JSON.stringify({ success: false, error: 'Username is already taken' })
      };
    }

    await store.setJSON(key, {
      username,
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString()
    });

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: true, message: 'Account created successfully' })
    };

  } catch (err) {
    console.error('Register error:', err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message || 'Internal server error' })
    };
  }
};
