// Vibe Killer runtime agent for Express.
//
// THIS IS YOUR CODE. Vibe Killer prints it; you add it, you read it, and you
// delete it when you are finished. Nothing is injected into your process and
// nothing is left behind, because the tool never put anything there.
//
// What it does: for each request, it reports the route, the status, which
// authorization middleware actually ran, and the shape of the database
// statements that were issued. It posts that to a sink on loopback that only
// exists while a scan is running.
//
// What it deliberately does not do: send parameter values. Statements are
// reported with their placeholders intact and only a count of bound
// parameters, so none of your data reaches the scanner. The sink refuses an
// observation that looks like it carries values.
//
// Install:
//
//   1. Save this file next to your app, as vibekiller-agent.js
//   2. At the TOP of your app setup, before your routes:
//
//        const vk = require('./vibekiller-agent');
//        app.use(vk.middleware());
//
//   3. Mark your auth middleware so the agent can see it fire. Wrap it:
//
//        app.get('/api/orders/:id', vk.authCheck('authenticate', authenticate), handler);
//
//      or, if the middleware is mounted globally, call vk.noteAuth(req, 'name')
//      from inside it.
//
//   4. To report queries, wrap your database client once:
//
//        const db = vk.observeQueries(realDb);
//
//   5. Run the scan, then remove the three lines above.
//
// The sink URL comes from the VIBEKILLER_SINK environment variable, which the
// scan prints. With it unset the agent does nothing at all, so leaving the
// code in place on a machine that is not being scanned has no effect.

'use strict';

const http = require('http');
const { AsyncLocalStorage } = require('async_hooks');

const SINK = process.env.VIBEKILLER_SINK || '';
const SCHEMA_VERSION = '1.0';
const CORRELATION_HEADER = 'x-vibekiller-probe';

// Per-request state, so a query issued deep in a service layer can be
// attributed to the request that caused it without threading a context
// through every function.
const store = new AsyncLocalStorage();

function current() {
  return store.getStore() || null;
}

/** Record that a named authorization check ran for this request. */
function noteAuth(req, name) {
  const state = current();
  if (state && name) state.authChecks.push(name);
}

/** Wrap an auth middleware so the agent sees it run. */
function authCheck(name, middleware) {
  return function (req, res, next) {
    noteAuth(req, name);
    return middleware(req, res, next);
  };
}

/**
 * Record a statement. `sql` must keep its placeholders: never pass a string
 * with values already substituted into it.
 */
function noteQuery(sql, paramCount, durationMs) {
  const state = current();
  if (!state || !sql) return;
  state.queries.push({
    sql: String(sql),
    param_count: Number(paramCount) || 0,
    duration_ms: Number(durationMs) || 0,
  });
}

/**
 * Wrap a database client so its query method reports statement shapes.
 * Works with the common `query(sql, params, cb)` and `query(sql, params)`
 * signatures used by pg, mysql2 and knex's raw client.
 */
function observeQueries(client, methodName = 'query') {
  const original = client[methodName];
  if (typeof original !== 'function') return client;

  const wrapped = function (...args) {
    const started = Date.now();
    const sql = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].text) || '';
    const params = Array.isArray(args[1]) ? args[1] : [];

    const finish = () => noteQuery(sql, params.length, Date.now() - started);

    const result = original.apply(client, args);
    if (result && typeof result.then === 'function') {
      return result.then(
        (value) => {
          finish();
          return value;
        },
        (err) => {
          finish();
          throw err;
        },
      );
    }
    finish();
    return result;
  };

  // A shallow clone, so the caller's own client object is not modified.
  return Object.assign(Object.create(Object.getPrototypeOf(client)), client, {
    [methodName]: wrapped,
  });
}

function post(observation) {
  if (!SINK) return;

  let url;
  try {
    url = new URL(SINK);
  } catch {
    return;
  }
  // Loopback only. The sink is always local, and refusing anything else means
  // a stray environment variable cannot turn this into an exfiltration path.
  if (url.hostname !== '127.0.0.1' && url.hostname !== 'localhost' && url.hostname !== '::1') {
    return;
  }

  const body = JSON.stringify(observation);
  const req = http.request(
    {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 2000,
    },
    (res) => res.resume(),
  );
  // Reporting is best effort: it must never affect the application.
  req.on('error', () => {});
  req.on('timeout', () => req.destroy());
  req.write(body);
  req.end();
}

/** The Express middleware. Mount it before your routes. */
function middleware() {
  return function (req, res, next) {
    if (!SINK) return next();

    const state = { authChecks: [], queries: [], started: Date.now() };

    store.run(state, () => {
      res.on('finish', () => {
        post({
          schema_version: SCHEMA_VERSION,
          correlation_id: req.headers[CORRELATION_HEADER] || '',
          method: req.method,
          path: req.originalUrl ? req.originalUrl.split('?')[0] : req.url,
          route: (req.route && req.route.path) || '',
          status: res.statusCode,
          handler: (req.route && req.route.stack && req.route.stack[0] && req.route.stack[0].name) || '',
          auth_checks: state.authChecks,
          principal: (req.user && (req.user.id || req.user.sub)) || '',
          queries: state.queries,
          duration_ms: Date.now() - state.started,
        });
      });
      next();
    });
  };
}

module.exports = { middleware, authCheck, noteAuth, noteQuery, observeQueries };
