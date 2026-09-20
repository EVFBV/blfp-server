const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createRequestSignature, validateMessage, verifyJwtToken, verifyRequestSignature } = require('./security-logic');

const validCreate = {
  type: 'create',
  mode: 'easytier',
  userId: 7,
  username: 'alice',
  mcPort: 25565,
  isPublic: false,
};

const validMemberId = '550e8400-e29b-41d4-a716-446655440000';

 test('接受合法的 EasyTier 创建消息', () => {
  assert.equal(validateMessage(validCreate), true);
});

test('拒绝未知字段、非法端口和错误模式', () => {
  assert.equal(validateMessage({ ...validCreate, extra: true }), false);
  assert.equal(validateMessage({ ...validCreate, mcPort: 0 }), false);
  assert.equal(validateMessage({ ...validCreate, mode: 'p2p' }), false);
});

test('校验 FRP 创建消息的节点和远端端口边界', () => {
  const message = { ...validCreate, mode: 'frp', frp: { host: 'relay.example', port: 2000, node: 1 } };
  assert.equal(validateMessage(message), true);
  assert.equal(validateMessage({ ...message, frp: { ...message.frp, port: 1999 } }), false);
  assert.equal(validateMessage({ ...message, frp: { ...message.frp, port: 5001 } }), false);
  assert.equal(validateMessage({ ...message, frp: { ...message.frp, extra: 'x' } }), false);
});

test('校验房间号、成员 ID 和 signal 数据', () => {
  assert.equal(validateMessage({ type: 'join', room: '123456' }), true);
  assert.equal(validateMessage({ type: 'join', room: '12345' }), false);
  assert.equal(validateMessage({ type: 'signal', to: validMemberId, data: { candidate: 'x' } }), true);
  assert.equal(validateMessage({ type: 'signal', to: 'not-a-member', data: {} }), false);
  assert.equal(validateMessage({ type: 'signal', data: null }), false);
});

test('JWT 仅接受 HS256 且拒绝无效 token', () => {
  const token = jwt.sign({ id: 7 }, 'test-secret', { algorithm: 'HS256' });
  assert.deepEqual(verifyJwtToken(token, 'test-secret').id, 7);
  assert.equal(verifyJwtToken(token, 'wrong-secret'), null);
  assert.equal(verifyJwtToken('not-a-token', 'test-secret'), null);
});

test('请求签名绑定方法、路径、时间戳、nonce 和请求体', () => {
  const input = {
    method: 'POST',
    url: '/api/rooms?ignored=query',
    timestamp: '1760000000000',
    nonce: 'nonce-1',
    body: { room: '123456' },
    token: 'jwt-token',
    secret: 'test-secret',
  };
  const signature = createRequestSignature(input);
  assert.equal(verifyRequestSignature({ ...input, signature }), true);
  assert.equal(verifyRequestSignature({ ...input, body: { room: '654321' }, signature }), false);
  assert.equal(verifyRequestSignature({ ...input, method: 'PUT', signature }), false);
  assert.equal(verifyRequestSignature({ ...input, signature: `${signature}00` }), false);
});

test('et-port-update 消息被接受（房主切换随机端口时通知访客）', () => {
  const { validateMessage } = require('./security-logic');
  assert.strictEqual(validateMessage({ type: 'et-port-update', port: 51234 }), true);
  assert.strictEqual(validateMessage({ type: 'et-port-update', port: 25565 }), true);
  /* 非法端口必须拒绝 */
  assert.strictEqual(validateMessage({ type: 'et-port-update', port: 0 }), false);
  assert.strictEqual(validateMessage({ type: 'et-port-update', port: 70000 }), false);
  assert.strictEqual(validateMessage({ type: 'et-port-update', port: 'abc' }), false);
  /* 多余字段必须拒绝（防注入其他字段） */
  assert.strictEqual(validateMessage({ type: 'et-port-update', port: 25565, extra: 1 }), false);
});
