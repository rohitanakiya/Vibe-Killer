// Behaviour fixture for the JavaScript rules in injection.yaml.
//
// NOT AN APPLICATION. See the header of misconfiguration.py.

const express = require('express');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const app = express();
const db = { query: () => {}, execute: () => {} };
const User = { findOne: () => {}, find: () => {}, deleteOne: () => {} };
const UPLOAD_ROOT = path.join(__dirname, 'uploads');

// --- sql-built-by-string-concatenation -----------------------------------

app.get('/orders', (req, res) => {
  // ruleid: sql-built-by-string-concatenation
  db.query('SELECT item FROM orders WHERE id = ' + req.query.id, (e, rows) => res.json(rows));
});

app.get('/orders-bound', (req, res) => {
  // ok: sql-built-by-string-concatenation
  db.query('SELECT item FROM orders WHERE id = ?', [req.query.id], (e, rows) => res.json(rows));
});

app.get('/orders-parsed', (req, res) => {
  const id = parseInt(req.query.id, 10);
  // ok: sql-built-by-string-concatenation
  db.query('SELECT item FROM orders WHERE id = ' + id, (e, rows) => res.json(rows));
});

// --- nosql-query-built-from-request-object -------------------------------

app.post('/login', (req, res) => {
  // ruleid: nosql-query-built-from-request-object
  User.findOne({ email: req.body.email });
  res.json({ ok: true });
});

app.post('/wholesale', (req, res) => {
  // The whole body as the filter, which is how an operator object such as
  // { $ne: null } gets in.
  // ruleid: nosql-query-built-from-request-object
  User.findOne(req.body);
  res.json({ ok: true });
});

app.post('/login-coerced', (req, res) => {
  // ok: nosql-query-built-from-request-object
  User.findOne({ email: String(req.body.email) });
  res.json({ ok: true });
});

// --- shell-command-built-from-input --------------------------------------

app.post('/convert', (req, res) => {
  // ruleid: shell-command-built-from-input
  exec('convert ' + req.body.name + ' out.png', () => res.json({ ok: true }));
});

app.post('/uptime', (req, res) => {
  // ok: shell-command-built-from-input
  exec('uptime', () => res.json({ ok: true }));
});

// --- eval-of-request-data ------------------------------------------------

app.get('/calc', (req, res) => {
  // ruleid: eval-of-request-data
  res.json({ value: eval(req.query.expr) });
});

app.get('/calc-parsed', (req, res) => {
  // ok: eval-of-request-data
  res.json({ value: JSON.parse(req.query.expr) });
});

// --- path-built-from-request-value ---------------------------------------

app.get('/files/:name', (req, res) => {
  // ruleid: path-built-from-request-value
  fs.readFile(path.join(UPLOAD_ROOT, req.params.name), (e, buf) => res.send(buf));
});

app.get('/files-based/:name', (req, res) => {
  const name = path.basename(req.params.name);
  // ok: path-built-from-request-value
  fs.readFile(path.join(UPLOAD_ROOT, name), (e, buf) => res.send(buf));
});

app.get('/banner', (req, res) => {
  // ok: path-built-from-request-value
  fs.readFile(path.join(UPLOAD_ROOT, 'banner.png'), (e, buf) => res.send(buf));
});

module.exports = app;
