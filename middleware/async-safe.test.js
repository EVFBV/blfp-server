const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const { makeAsyncSafe } = require('./async-safe');

function startApp(router) {
  const app = express();
  app.use('/api', makeAsyncSafe(router));
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    res.status(500).json({ error: '服务器内部错误' });
  });
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function get(port, urlPath) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: urlPath }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
}

test('async 处理器抛错 → 返回 500，进程存活（模拟数据库中断）', async () => {
  const router = express.Router();
  router.get('/boom', async () => { throw new Error('模拟数据库连接中断'); });
  const server = await startApp(router);
  const port = server.address().port;
  const res = await get(port, '/api/boom');
  assert.strictEqual(res.status, 500);
  assert.match(res.body, /服务器内部错误/);
  const res2 = await get(port, '/api/boom');
  assert.strictEqual(res2.status, 500, '第二次请求仍能正常处理说明进程没崩');
  server.close();
});

test('同步异常同样被捕获', async () => {
  const router = express.Router();
  router.get('/sync-boom', () => { throw new Error('同步抛错'); });
  const server = await startApp(router);
  const res = await get(server.address().port, '/api/sync-boom');
  assert.strictEqual(res.status, 500);
  server.close();
});

test('正常异步处理器不受影响', async () => {
  const router = express.Router();
  router.get('/ok', async (req, res) => { res.json({ ok: true }); });
  const server = await startApp(router);
  const res = await get(server.address().port, '/api/ok');
  assert.strictEqual(res.status, 200);
  assert.match(res.body, /"ok":true/);
  server.close();
});

test('server.js 注册了进程级兜底处理器', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.match(src, /process\.on\('unhandledRejection'/);
  assert.match(src, /process\.on\('uncaughtException'/);
});

test('所有 API 路由挂载都经过异步安全包装', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const unwrapped = src.match(/app\.use\('\/api\/[a-z-]+', require\(/g) || [];
  assert.strictEqual(unwrapped.length, 0, '存在未包装的路由挂载: ' + unwrapped.join(', '));
});
