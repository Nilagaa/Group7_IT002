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

    const store = getStore({
      name: 'users',
      consistency: 'strong',
      siteID: process.env.NETLIFY_SITE_ID,
      token: process.env.NETLIFY_TOKEN,
    });

    const userData = await store.get(username.toLowerCase(), { type: 'json' });

    if (!userData) {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'Invalid username or password' })
      };
    }

    if (hashPassword(password) !== userData.passwordHash) {
      return {
        statusCode: 401,
        body: JSON.stringify({ success: false, error: 'Invalid username or password' })
      };
    }

    const token = Buffer.from(`${username}:${Date.now()}:${Math.random()}`).toString('base64');

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ success: true, token })
    };

  } catch (err) {
    console.error('Login error:', err);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: err.message || 'Internal server error' })
    };
  }
};
