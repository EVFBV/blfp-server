const db = require('../db');
const { createRequestSignature, verifyRequestSignature } = require('../security-logic');

const WINDOW_MS = 120 * 1000;
const usedNonces = new Map();

function pruneNonces(now) {
  for (const [nonce, expiresAt] of usedNonces) {
    if (expiresAt <= now) usedNonces.delete(nonce);
  }
}

function requestSignature(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD') return next();

  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const timestamp = req.headers['x-timestamp'];
  const nonce = req.headers['x-nonce'];
  const signature = req.headers['x-signature'];
  if (!req.user || !token || !timestamp || !nonce || !signature) {
    return res.status(401).json({ error: '请求签名缺失' });
  }

  const now = Date.now();
  const timestampMs = Number(timestamp);
  if (!Number.isFinite(timestampMs) || Math.abs(now - timestampMs) > WINDOW_MS) {
    return res.status(401).json({ error: '请求签名已过期' });
  }

  pruneNonces(now);
  if (usedNonces.has(nonce)) return res.status(409).json({ error: '请求已被处理' });

  const signatureInput = {
    method: req.method,
    url: req.originalUrl,
    timestamp,
    nonce,
    body: req.body,
    token,
    secret: db.getJwtSecret(),
    signature,
  };
  if (!verifyRequestSignature(signatureInput)) {
    return res.status(401).json({ error: '请求签名无效' });
  }

  usedNonces.set(nonce, now + WINDOW_MS);
  next();
}

module.exports = requestSignature;
