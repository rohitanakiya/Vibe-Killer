// Behaviour fixture for the JavaScript rules in misconfiguration.yaml.
//
// NOT AN APPLICATION. See the header of misconfiguration.py: a `ruleid:` line
// must match, an `ok:` line must not, and `semgrep --test` enforces both.

const express = require('express');
const serveIndex = require('serve-index');
const path = require('path');
const https = require('https');
const cors = require('cors');

const app = express();

// --- cors-wildcard-with-credentials --------------------------------------

// ruleid: cors-wildcard-with-credentials
app.use(cors({ origin: true, credentials: true }));

// ok: cors-wildcard-with-credentials
app.use(cors({ origin: 'https://app.example.invalid', credentials: true }));

app.use((req, res, next) => {
  // ruleid: cors-wildcard-with-credentials
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  next();
});

app.use((req, res, next) => {
  // ok: cors-wildcard-with-credentials
  res.setHeader('Access-Control-Allow-Origin', 'https://app.example.invalid');
  next();
});

// --- error-detail-returned-to-caller -------------------------------------

app.use((err, req, res, next) => {
  // ruleid: error-detail-returned-to-caller
  res.status(500).json({ error: err.message });
});

app.use((err, req, res, next) => {
  // ruleid: error-detail-returned-to-caller
  res.status(500).send(err.stack);
});

app.use((err, req, res, next) => {
  // ok: error-detail-returned-to-caller
  res.status(500).json({ error: 'internal error' });
});

// --- unsafe-fetch-of-user-supplied-url -----------------------------------

app.post('/import', async (req, res) => {
  // ruleid: unsafe-fetch-of-user-supplied-url
  const upstream = await fetch(req.body.url);
  res.json({ ok: upstream.ok });
});

app.post('/import-parsed', async (req, res) => {
  // A parsed URL is this rule's marker for validation, which the rule's own
  // comment records as a deliberate trade.
  const target = new URL(req.body.url);
  // ok: unsafe-fetch-of-user-supplied-url
  const upstream = await fetch(target);
  res.json({ ok: upstream.ok });
});

app.post('/import-fixed', async (req, res) => {
  // ok: unsafe-fetch-of-user-supplied-url
  const upstream = await fetch('https://feeds.example.invalid/latest');
  res.json({ ok: upstream.ok });
});

// --- directory-listing-or-whole-tree-served ------------------------------

// ruleid: directory-listing-or-whole-tree-served
app.use('/files', express.static(__dirname));

// ruleid: directory-listing-or-whole-tree-served
app.use('/listing', serveIndex(path.join(__dirname, 'public')));

// ok: directory-listing-or-whole-tree-served
app.use('/assets', express.static(path.join(__dirname, 'public')));

// `index: false` turns off serving index.html. It does not enable a listing,
// and express.static has no listing of its own to enable, so this is a
// correct configuration rather than a finding.
// ok: directory-listing-or-whole-tree-served
app.use('/noindex', express.static(path.join(__dirname, 'public'), { index: false }));

// --- tls-verification-disabled -------------------------------------------

// ruleid: tls-verification-disabled
const laxAgent = new https.Agent({ rejectUnauthorized: false });

// ruleid: tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// ok: tls-verification-disabled
const strictAgent = new https.Agent({ rejectUnauthorized: true });

module.exports = { app, laxAgent, strictAgent };
