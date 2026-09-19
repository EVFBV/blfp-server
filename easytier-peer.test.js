const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizePeer, parsePeers, validatePeers } = require('./easytier-peer');

test('接受并规范化支持的 EasyTier peer', () => {
  assert.equal(normalizePeer(' TCP://Node.Example.com:11010 '), 'tcp://node.example.com:11010');
  assert.equal(normalizePeer('udp://127.0.0.1:1'), 'udp://127.0.0.1:1');
  assert.equal(normalizePeer('ws://node.example.com:80'), 'ws://node.example.com:80');
  assert.equal(normalizePeer('wss://node.example.com:443'), 'wss://node.example.com:443');
});

test('拒绝协议、主机、端口或附加部分非法的 peer', () => {
  for (const peer of ['', 'http://node.example.com:80', 'tcp://node.example.com', 'tcp://:11010', 'tcp://node.example.com:0', 'tcp://node.example.com:65536', 'tcp://user@node.example.com:11010', 'tcp://node.example.com:11010/path', 'tcp://node.example.com:11010?x=1']) {
    assert.equal(normalizePeer(peer), null);
  }
});

test('解析 peer 时去除非法项和规范化后的重复项', () => {
  assert.deepEqual(parsePeers('tcp://NODE.example.com:11010\ntcp://node.example.com:11010,udp://node.example.com:11010\ninvalid'), [
    'tcp://node.example.com:11010',
    'udp://node.example.com:11010',
  ]);
});

test('完整校验要求至少一个且每项唯一合法', () => {
  assert.deepEqual(validatePeers('tcp://node.example.com:11010\nwss://node.example.com:443'), [
    'tcp://node.example.com:11010',
    'wss://node.example.com:443',
  ]);
  assert.equal(validatePeers(''), null);
  assert.equal(validatePeers('tcp://node.example.com:11010\ninvalid'), null);
  assert.equal(validatePeers('tcp://NODE.example.com:11010\ntcp://node.example.com:11010'), null);
});
