const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const FRP_REMOTE_PORT_MIN = 2000;
const FRP_REMOTE_PORT_MAX = 5000;
const ROOM_CODE_PATTERN = /^\d{6}$/;
const MEMBER_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MESSAGE_FIELDS = {
  create: new Set(['type', 'mode', 'userId', 'username', 'mcPort', 'frp', 'isPublic']),
  join: new Set(['type', 'room']),
  close: new Set(['type', 'room']),
  leave: new Set(['type', 'room']),
  signal: new Set(['type', 'to', 'data']),
  chat: new Set(['type', 'text', 'username', 'userId']),
};

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyFields(value, fields) {
  return Object.keys(value).every((key) => fields.has(key));
}

function isPort(value, min = 1, max = 65535) {
  return Number.isInteger(value) && value >= min && value <= max;
}

function isRoomCode(value) {
  return typeof value === 'string' && ROOM_CODE_PATTERN.test(value);
}

function isSignalData(value) {
  return value !== undefined && value !== null && typeof value !== 'function' && typeof value !== 'symbol';
}

function validateMessage(msg) {
  if (!isPlainObject(msg) || typeof msg.type !== 'string' || !Object.hasOwn(MESSAGE_FIELDS, msg.type)) return false;
  if (!hasOnlyFields(msg, MESSAGE_FIELDS[msg.type])) return false;
  if (msg.type === 'chat') {
    if (typeof msg.text !== 'string' || !msg.text.length || msg.text.length > 500) return false;
    if (msg.username !== undefined && (typeof msg.username !== 'string' || msg.username.length > 100)) return false;
    if (msg.userId !== undefined && (!Number.isInteger(msg.userId) || msg.userId < 1)) return false;
    return true;
  }
  if (msg.type === 'create') {
    if (msg.mode !== 'easytier' && msg.mode !== 'frp') return false;
    if (!isPort(msg.mcPort) || typeof msg.isPublic !== 'boolean') return false;
    if (msg.userId !== undefined && (!Number.isInteger(msg.userId) || msg.userId < 1)) return false;
    if (msg.username !== undefined && (typeof msg.username !== 'string' || !msg.username.length || msg.username.length > 100)) return false;
    if (msg.mode === 'easytier') return msg.frp === undefined;
    return isPlainObject(msg.frp)
      && hasOnlyFields(msg.frp, new Set(['host', 'port', 'node']))
      && typeof msg.frp.host === 'string'
      && msg.frp.host.length > 0
      && msg.frp.host.length <= 253
      && isPort(msg.frp.port, FRP_REMOTE_PORT_MIN, FRP_REMOTE_PORT_MAX)
      && Number.isInteger(msg.frp.node)
      && msg.frp.node > 0;
  }
  if (msg.type === 'join' || msg.type === 'close' || msg.type === 'leave') return isRoomCode(msg.room);
  return (msg.to === undefined || (typeof msg.to === 'string' && MEMBER_ID_PATTERN.test(msg.to))) && isSignalData(msg.data);
}

function requestBodyHash(body) {
  return crypto.createHash('sha256').update(JSON.stringify(body || {})).digest('hex');
}

function createRequestSignature({ method, url, timestamp, nonce, body, token, secret }) {
  const payload = `${method}\n${url.split('?')[0]}\n${timestamp}\n${nonce}\n${requestBodyHash(body)}`;
  const key = crypto.createHash('sha256').update(token + secret).digest();
  return crypto.createHmac('sha256', key).update(payload).digest('hex');
}

function verifyJwtToken(token, secret) {
  try {
    return jwt.verify(token, secret, { algorithms: ['HS256'] });
  } catch {
    return null;
  }
}

function verifyRequestSignature(input) {
  const expected = createRequestSignature(input);
  let supplied;
  try {
    supplied = Buffer.from(input.signature, 'hex');
  } catch {
    return false;
  }
  const expectedBuffer = Buffer.from(expected, 'hex');
  return supplied.length === expectedBuffer.length && crypto.timingSafeEqual(supplied, expectedBuffer);
}

module.exports = { validateMessage, createRequestSignature, verifyJwtToken, verifyRequestSignature };
