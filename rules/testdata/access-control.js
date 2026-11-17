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

// Serialising the record's owner into the response is not an ownership
// check, and it used to read as one: the exclusion asked whether "user_id"
// appeared anywhere in the handler, so this one line switched the rule off.
// The query below is the same unscoped query as the first case.
// ruleid: idor-missing-ownership-check-express
app.get('/orders-serialised/:id', async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM orders WHERE id = ?', [req.params.id]);
  res.json({ id: rows[0].id, user_id: rows[0].user_id, item: rows[0].item });
});

// Scoped, and the scoping is in the query rather than on req.user, because
// this handler resolves the caller itself. The column is compared, so there
// is nothing to report.
// ok: idor-missing-ownership-check-express
app.get('/orders-resolved/:id', async (req, res) => {
  const callerId = await principalFor(req.headers.authorization);
  const [rows] = await db.execute(
    'SELECT item FROM orders WHERE id = ? AND user_id = ?',
    [req.params.id, callerId],
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
