// The express-vulnerable fixture with every weakness fixed.
//
// This exists to prove the other half of each check: that it stays silent on
// correct code. A scanner that fires on both files is not detecting anything,
// it is just pattern-matching on the domain.
//
// Each fix is annotated with what it addresses, because the interesting part
// is usually not that the fix exists but where it sits: the ownership check
// belongs in the query, not after it.

const express = require('express');
const jwt = require('jsonwebtoken');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { users, orders, profiles } = require('./data');

const app = express();
app.use(express.json());

// FIX: the signing key comes from the environment, so it is not in the
// repository and can be rotated without a code change.
const JWT_SECRET = process.env.JWT_SIGNING_KEY;

// FIX: an explicit allowlist instead of reflecting whatever origin asked.
const ALLOWED_ORIGINS = new Set(['http://localhost:5173', 'https://app.example.invalid']);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');
  }
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');

  // FIX: response hardening headers, set once for every route.
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('Content-Security-Policy', "default-src 'self'");
  res.header('Referrer-Policy', 'no-referrer');
  next();
});

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Bearer\s+/i, '');
  const user = users[token];
  if (!user) {
    return res.status(401).json({ error: 'authentication required' });
  }
  req.user = user;
  next();
}

// FIX: the signature is verified and the algorithm list is pinned, so the
// token cannot be re-signed with a different algorithm or left unsigned.
function identifyFromJwt(req) {
  const token = req.headers['x-session-jwt'];
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return null;
  }
}

app.get('/health', (req, res) => {
  res.json({ ok: true });
});

// FIX: the authenticated principal is part of the lookup, so a record
// belonging to someone else is never loaded. A miss returns 404 rather than
// 403, so the endpoint does not confirm that another user's record exists.
app.get('/api/orders/:id', authenticate, (req, res) => {
  const order = orders.find((o) => o.id === Number(req.params.id) && o.userId === req.user.id);
  if (!order) {
    return res.status(404).json({ error: 'not found' });
  }
  res.json(order);
});

// FIX: authentication is required, and the lookup is scoped to the caller.
app.get('/api/profiles/:id', authenticate, (req, res) => {
  const profile = profiles.find((p) => p.id === Number(req.params.id) && p.userId === req.user.id);
  if (!profile) {
    return res.status(404).json({ error: 'not found' });
  }
  res.json(profile);
});

// FIX: the accepted fields are named explicitly, and the owner comes from the
// session rather than from the request.
app.post('/api/orders', authenticate, (req, res) => {
  const { item, total } = req.body;
  if (typeof item !== 'string' || !Number.isFinite(total)) {
    return res.status(400).json({ error: 'item and total are required' });
  }
  const order = { id: Date.now(), userId: req.user.id, item, total };
  orders.push(order);
  res.status(201).json(order);
});

// FIX: the role is read from the server's own record of the caller, not from
// anything the caller sent.
app.post('/api/admin/promote', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.json({ promoted: true, by: req.user.id });
});

// FIX: the search term is a bound parameter, so it is data and never syntax.
app.get('/api/search', authenticate, (req, res) => {
  const db = getDatabase();
  const sql = 'SELECT id, item FROM orders WHERE item LIKE ? AND user_id = ?';
  db.query(sql, [`%${String(req.query.q || '')}%`, req.user.id], (err, rows) => {
    if (err) {
      return fail(res, err);
    }
    res.json(rows);
  });
});

// FIX: the resolved path is checked against the directory it must stay inside,
// which holds even when the input contains encoded traversal sequences.
const UPLOAD_ROOT = path.resolve(__dirname, 'uploads');

app.get('/api/files/:name', authenticate, (req, res) => {
  const resolved = path.resolve(UPLOAD_ROOT, req.params.name);
  if (resolved !== UPLOAD_ROOT && !resolved.startsWith(UPLOAD_ROOT + path.sep)) {
    return res.status(400).json({ error: 'invalid filename' });
  }
  fs.readFile(resolved, 'utf8', (err, body) => {
    if (err) {
      return res.status(404).json({ error: 'not found' });
    }
    res.type('text/plain').send(body);
  });
});

// FIX: only an allowlisted host is fetched, and the address it resolves to is
// checked, because a name can resolve to an internal address.
const IMPORT_ALLOWED_HOSTS = new Set(['feeds.example.invalid']);

app.post('/api/import', authenticate, async (req, res) => {
  let url;
  try {
    url = new URL(String(req.body.url));
  } catch {
    return res.status(400).json({ error: 'invalid url' });
  }
  if (url.protocol !== 'https:' || !IMPORT_ALLOWED_HOSTS.has(url.hostname)) {
    return res.status(400).json({ error: 'host not allowed' });
  }
  try {
    const response = await fetch(url, { redirect: 'error' });
    const body = await response.text();
    res.json({ bytes: body.length });
  } catch (err) {
    fail(res, err);
  }
});

// FIX: the argument-array form, which never involves a shell, plus a check
// that the filename is one we expect.
app.post('/api/convert', authenticate, (req, res) => {
  const name = String(req.body.filename || '');
  if (!/^[A-Za-z0-9_.-]+$/.test(name)) {
    return res.status(400).json({ error: 'invalid filename' });
  }
  const input = path.resolve(UPLOAD_ROOT, name);
  if (!input.startsWith(UPLOAD_ROOT + path.sep)) {
    return res.status(400).json({ error: 'invalid filename' });
  }
  execFile('convert', [input, path.join(UPLOAD_ROOT, 'out.png')], (err, stdout) => {
    if (err) {
      return fail(res, err);
    }
    res.json({ output: stdout });
  });
});

// FIX: a cryptographic source, so the token cannot be reproduced.
app.post('/api/reset', (req, res) => {
  const resetToken = crypto.randomBytes(32).toString('hex');
  res.json({ resetToken });
});

// FIX: a password hash with a work factor and a per-password salt.
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`;
}

// FIX: a dedicated public directory, so source and config are not served.
app.use('/files', express.static(path.join(__dirname, 'public')));

// FIX: httpOnly keeps the cookie away from scripts, secure keeps it off plain
// HTTP, and sameSite limits cross-site sending.
app.post('/api/login', (req, res) => {
  res.cookie('session', 'userA-token', {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 86400000,
  });
  res.json({ ok: true });
});

// FIX: the error is logged on the server and the caller gets a generic
// message with a correlation id to quote.
function fail(res, err) {
  const correlationId = crypto.randomUUID();
  console.error(`[${correlationId}]`, err);
  return res.status(500).json({ error: 'internal error', correlationId });
}

app.use((err, req, res, next) => {
  fail(res, err);
});

function getDatabase() {
  return {
    query(sql, params, cb) {
      const callback = typeof params === 'function' ? params : cb;
      const owner = Array.isArray(params) ? params[1] : null;
      callback(
        null,
        orders.filter((o) => !owner || o.userId === owner).map((o) => ({ id: o.id, item: o.item })),
      );
    },
  };
}

const port = Number(process.env.PORT || 3000);
if (require.main === module) {
  app.listen(port, '127.0.0.1', () => {
    console.log(`vk-fixture-express-patched listening on http://127.0.0.1:${port}`);
  });
}

module.exports = { app, hashPassword, identifyFromJwt };
