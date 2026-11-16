// Behaviour fixture for the JavaScript rules in access-control.yaml.
//
// NOT AN APPLICATION. See the header of misconfiguration.py.
//
// The route handlers are kept apart on purpose: idor-missing-ownership-check
// needs a path parameter and route-without-auth-middleware needs a mutating
// method, so a `DELETE /orders/:id` would be a finding for both and neither
// annotation would say which rule was being pinned.

const express = require('express');

const app = express();
const db = { execute: async () => [[]] };
const Profile = { update: () => {}, create: () => {} };

function requireAuth(req, res, next) {
  next();
}

// --- idor-missing-ownership-check-express --------------------------------

// ruleid: idor-missing-ownership-check-express
app.get('/orders/:id', async (req, res) => {
  const [rows] = await db.execute('SELECT item FROM orders WHERE id = ?', [req.params.id]);
  res.json(rows[0]);
});

// ok: idor-missing-ownership-check-express
app.get('/orders-scoped/:id', async (req, res) => {
  const [rows] = await db.execute(
    'SELECT item FROM orders WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.id],
  );
  res.json(rows[0]);
});

// A handler that reads the filesystem is serving a file, not a record, and
// traversal.path-built-from-input owns that question.
// ok: idor-missing-ownership-check-express
app.get('/files/:name', async (req, res) => {
  res.sendFile(req.params.name, { root: 'public' });
});

// --- route-without-auth-middleware-express ------------------------------

// ruleid: route-without-auth-middleware-express
app.post('/orders', async (req, res) => {
  await db.execute('INSERT INTO orders (item) VALUES (?)', [req.body.item]);
  res.json({ ok: true });
});

// Middleware between the path and the handler, so the route is protected.
// ok: route-without-auth-middleware-express
app.post('/orders-guarded', requireAuth, async (req, res) => {
  res.json({ ok: true });
});

// A route that is public by design is a decision, not an oversight.
// ok: route-without-auth-middleware-express
app.post('/login', async (req, res) => {
  res.json({ ok: true });
});

// --- mass-assignment-request-body-spread --------------------------------
//
// In plain functions rather than routes, so route-without-auth-middleware
// stays out of it.

function saveProfile(req) {
  // ruleid: mass-assignment-request-body-spread
  return Profile.update(req.body);
}

function createProfile(req) {
  // ruleid: mass-assignment-request-body-spread
  return Profile.create({ ...req.body });
}

function saveProfileExplicitly(req) {
  // ok: mass-assignment-request-body-spread
  return Profile.update({ displayName: req.body.displayName });
}

// --- authorization-decided-client-side ----------------------------------

function isAdminFromBody(req) {
  // ruleid: authorization-decided-client-side
  if (req.body.role === 'admin') {
    return true;
  }
  return false;
}

function isAdminFromQuery(req) {
  // ruleid: authorization-decided-client-side
  if (req.query.role === 'admin') {
    return true;
  }
  return false;
}

function isAdminFromSession(req) {
  // The decision comes from the server's own view of the caller.
  // ok: authorization-decided-client-side
  if (req.user.role === 'admin') {
    return true;
  }
  return false;
}

module.exports = {
  app, saveProfile, createProfile, saveProfileExplicitly,
  isAdminFromBody, isAdminFromQuery, isAdminFromSession,
};
