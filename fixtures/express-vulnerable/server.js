// Deliberately vulnerable Express fixture for Vibe Killer's test suite.
//
// NOT A REAL APPLICATION. DO NOT DEPLOY. Every weakness here is intentional
// and is paired with a check in Vibe Killer; the file next to this one,
// ../express-patched/server.js, is the same application with each one fixed,
// so the test suite can prove each check both fires and stays silent.
//
// The shape is copied from what code generators actually produce: the
// authentication middleware is correct and well-used, and the authorization
// is simply missing from the data access.

const express = require('express');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { users, orders, profiles } = require('./data');

const app = express();
app.use(express.json());

// VULN: the signing secret is in the source, so anyone who can read the
// repository can mint a token for any user.
const JWT_SECRET = 'supersecret';

// VULN: the origin is reflected and credentials are allowed, so any site a
// logged-in user visits can call this API as them and read the response.
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  next();
});

// Authentication. This part is fine: it is the authorization that is missing.
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

// VULN: decodes the token without verifying its signature, so the claims are
// whatever the caller put in them.
function identifyFromJwt(req) {
  const header = req.headers['x-session-jwt'];
  if (!header) return null;
  return jwt.decode(header);
}

app.get('/health', (req, res) => {
  res.json({ ok: true });
});

// VULN (idor.sequential-id-access): authenticated, then looks the order up by
// the id in the URL with no ownership check. Any logged-in user can read any
// order by changing the number.
app.get('/api/orders/:id', authenticate, (req, res) => {
  const order = orders.find((o) => o.id === Number(req.params.id));
  if (!order) {
    return res.status(404).json({ error: 'not found' });
  }
  res.json(order);
});

// VULN (authz.unprotected-endpoint): no authentication middleware at all, and
// it returns another user's profile.
app.get('/api/profiles/:id', (req, res) => {
  const profile = profiles.find((p) => p.id === Number(req.params.id));
  if (!profile) {
    return res.status(404).json({ error: 'not found' });
  }
  res.json(profile);
});

// VULN (authz.mass-assignment): the whole request body is written into the
// record, so a caller can set fields the UI never exposes.
app.post('/api/orders', authenticate, (req, res) => {
  const order = { id: Date.now(), ...req.body };
  orders.push(order);
  res.status(201).json(order);
});

// VULN (authz.client-supplied-role): the role comes from the request body, and
// the client controls the request body.
app.post('/api/admin/promote', authenticate, (req, res) => {
  if (req.body.role === 'admin') {
    return res.json({ promoted: true, by: req.user.id });
  }
  res.status(403).json({ error: 'forbidden' });
});

// VULN (injection.sql-string-built-from-input): the search term is
// concatenated into the statement, so it becomes part of the query's syntax.
app.get('/api/search', authenticate, (req, res) => {
  const db = getDatabase();
  const sql = "SELECT id, item FROM orders WHERE item LIKE '%" + req.query.q + "%'";
  db.query(sql, (err, rows) => {
    if (err) {
      // VULN (misconfig.error-detail-disclosed): the driver error goes
      // straight to the caller, disclosing the query and the library.
      return res.status(500).json({ error: err.message, stack: err.stack });
    }
    res.json(rows);
  });
});

// VULN (traversal.path-built-from-input): the filename is joined without
// being resolved and checked, so ../ escapes the directory.
app.get('/api/files/:name', authenticate, (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.params.name);
  fs.readFile(filePath, 'utf8', (err, body) => {
    if (err) {
      return res.status(404).json({ error: 'not found' });
    }
    res.type('text/plain').send(body);
  });
});

// VULN (ssrf.user-supplied-url-fetched): the server fetches a URL the caller
// supplied, which lends it the server's network position.
app.post('/api/import', authenticate, async (req, res) => {
  const response = await fetch(req.body.url);
  const body = await response.text();
  res.json({ bytes: body.length });
});

// VULN (injection.command-built-from-input): the request value is interpolated
// into a shell command.
app.post('/api/convert', authenticate, (req, res) => {
  exec(`convert ${req.body.filename} /tmp/out.png`, (err, stdout) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ output: stdout });
  });
});

// VULN (crypto.predictable-token): a password reset token from Math.random is
// predictable, so it can be guessed.
app.post('/api/reset', (req, res) => {
  const resetToken = Math.random().toString(36).slice(2);
  res.json({ resetToken });
});

// VULN (crypto.password-fast-digest): a general-purpose digest with no work
// factor and no salt.
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// VULN (misconfig.static-exposure): the static root is the project directory,
// so source and config are served.
app.use('/files', express.static(__dirname));

// VULN (auth.session-cookie-unprotected): no httpOnly, no secure, no sameSite.
app.post('/api/login', (req, res) => {
  res.cookie('session', 'userA-token', { maxAge: 86400000 });
  res.json({ ok: true });
});

// VULN (misconfig.error-detail-disclosed): the global handler returns the
// stack trace to the caller.
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// A stand-in database, so the error-disclosure path is exercisable without a
// real one.
//
// It fails the way a real parser does: only when the statement's quotes are
// unbalanced. That matters for the fixture to be worth anything. An earlier
// version errored on any quote at all, which meant it also errored on the
// literal quotes in its own LIKE clause — so every request failed identically,
// and a differential check could draw no conclusion from that and correctly
// declined to report one. A fixture that is broken for every input does not
// demonstrate injection; it demonstrates a broken fixture.
function getDatabase() {
  return {
    query(sql, cb) {
      const quotes = (sql.match(/'/g) || []).length;
      if (quotes % 2 !== 0) {
        const err = new Error(`ER_PARSE_ERROR: You have an error in your SQL syntax near '${sql.slice(-24)}'`);
        err.stack = `Error: ${err.message}\n    at Object.<anonymous> (${__filename}:1:1)\n    at node_modules/mysql/lib/protocol/Parser.js:437:18`;
        return cb(err);
      }
      cb(null, orders.map((o) => ({ id: o.id, item: o.item })));
    },
  };
}

const port = Number(process.env.PORT || 3000);
if (require.main === module) {
  app.listen(port, '127.0.0.1', () => {
    console.log(`vk-fixture-express-vulnerable listening on http://127.0.0.1:${port}`);
  });
}

module.exports = { app, hashPassword, identifyFromJwt, JWT_SECRET };
