// Behaviour fixture for the JavaScript rules in auth-and-crypto.yaml.
//
// NOT AN APPLICATION. See the header of misconfiguration.py.

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const session = require('express-session');

const SIGNING_KEY = process.env.FIXTURE_JWT_SECRET;

// --- jwt-decoded-without-verification ------------------------------------

function decodeUnverified(token) {
  // ruleid: jwt-decoded-without-verification
  return jwt.decode(token);
}

function decodeUnverifiedComplete(token) {
  // ruleid: jwt-decoded-without-verification
  return jwt.decode(token, { complete: true });
}

function verifyIgnoringExpiry(token) {
  // ruleid: jwt-decoded-without-verification
  return jwt.verify(token, SIGNING_KEY, { ignoreExpiration: true });
}

function verifyProperly(token) {
  // ok: jwt-decoded-without-verification
  return jwt.verify(token, SIGNING_KEY, { algorithms: ['HS256'] });
}

// --- jwt-accepts-unsigned-algorithm --------------------------------------

function verifyAcceptingNone(token) {
  // ruleid: jwt-accepts-unsigned-algorithm
  return jwt.verify(token, SIGNING_KEY, { algorithms: ['HS256', 'none'] });
}

function verifyAcceptingOnlyNone(token) {
  // ruleid: jwt-accepts-unsigned-algorithm
  return jwt.verify(token, SIGNING_KEY, { algorithms: ['none'] });
}

function verifyPinned(token) {
  // ok: jwt-accepts-unsigned-algorithm
  return jwt.verify(token, SIGNING_KEY, { algorithms: ['RS256'] });
}

// --- jwt-signed-with-hardcoded-or-weak-secret ----------------------------
//
// The expiry is set on these so that token-expiry-not-set stays out of it;
// each rule gets its own lines.

function signWithALiteral(payload) {
  // ruleid: jwt-signed-with-hardcoded-or-weak-secret
  return jwt.sign(payload, 'dev-secret', { expiresIn: '1h' });
}

function signWithTheEnvironment(payload) {
  // ok: jwt-signed-with-hardcoded-or-weak-secret
  return jwt.sign(payload, SIGNING_KEY, { expiresIn: '1h' });
}

// --- token-expiry-not-set ------------------------------------------------

function signWithoutExpiry(payload) {
  // ruleid: token-expiry-not-set
  return jwt.sign(payload, SIGNING_KEY);
}

function signWithOptionsButNoExpiry(payload) {
  // Options present, expiry absent. The rule used to bind exactly two
  // arguments, so this signed-forever token was invisible to it.
  // ruleid: token-expiry-not-set
  return jwt.sign(payload, SIGNING_KEY, { algorithm: 'HS256' });
}

function signWithExpiry(payload) {
  // ok: token-expiry-not-set
  return jwt.sign(payload, SIGNING_KEY, { expiresIn: '15m' });
}

function signWithExpiryInThePayload(claims) {
  // ok: token-expiry-not-set
  return jwt.sign({ ...claims, exp: 1767225600 }, SIGNING_KEY);
}

// --- password-hashed-with-fast-digest ------------------------------------

function hashPasswordSha256(password) {
  // ruleid: password-hashed-with-fast-digest
  return crypto.createHash('sha256').update(password).digest('hex');
}

function hashPasswordMd5(password) {
  // ruleid: password-hashed-with-fast-digest
  return crypto.createHash('md5').update(password).digest('hex');
}

function checksumABlob(blob) {
  // ok: password-hashed-with-fast-digest
  return crypto.createHash('sha256').update(blob).digest('hex');
}

// --- secret-compared-with-equality ---------------------------------------

function checkApiKey(apiKey, expected) {
  // ruleid: secret-compared-with-equality
  return apiKey === expected;
}

function checkApiKeyConstantTime(apiKey, expected) {
  // ok: secret-compared-with-equality
  return crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(expected));
}

function checkAPageNumber(page, last) {
  // ok: secret-compared-with-equality
  return page === last;
}

// --- predictable-randomness-for-security-value ---------------------------

function makeResetToken() {
  // ruleid: predictable-randomness-for-security-value
  const resetToken = Math.random().toString(36).slice(2);
  return resetToken;
}

function pickABanner(banners) {
  // ok: predictable-randomness-for-security-value
  const banner = banners[Math.floor(Math.random() * banners.length)];
  return banner;
}

function makeResetTokenProperly() {
  // ok: predictable-randomness-for-security-value
  const resetToken = crypto.randomBytes(32).toString('hex');
  return resetToken;
}

// --- session-cookie-missing-protections ----------------------------------

function setSessionCookie(res, value) {
  // ruleid: session-cookie-missing-protections
  res.cookie('sid', value, { secure: true, sameSite: 'lax' });
}

function setSessionCookieProperly(res, value) {
  // ok: session-cookie-missing-protections
  res.cookie('sid', value, { httpOnly: true, secure: true, sameSite: 'lax' });
}

function configureSession(app) {
  // ruleid: session-cookie-missing-protections
  app.use(session({ secret: SIGNING_KEY, cookie: { secure: true } }));
}

module.exports = {
  decodeUnverified, decodeUnverifiedComplete, verifyIgnoringExpiry, verifyProperly,
  verifyAcceptingNone, verifyAcceptingOnlyNone, verifyPinned,
  signWithALiteral, signWithTheEnvironment,
  signWithoutExpiry, signWithOptionsButNoExpiry, signWithExpiry, signWithExpiryInThePayload,
  hashPasswordSha256, hashPasswordMd5, checksumABlob,
  checkApiKey, checkApiKeyConstantTime, checkAPageNumber,
  makeResetToken, pickABanner, makeResetTokenProperly,
  setSessionCookie, setSessionCookieProperly, configureSession,
};
