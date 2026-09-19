/**
 * BLFP 聊天 / 公告 专用服务器（无数据库依赖）
 *
 * 用途：与主服务器（server.js，端口 4000）分离部署，专职处理
 *   1. 聊天室消息中继（WebSocket /ws）
 *   2. 公告的读取与发布（HTTP /api/settings/announcement）
 *
 * 不需要 MySQL：只需与主服务器相同的 JWT 密钥（config.json 的 jwtSecret 字段，或 JWT_SECRET 环境变量）
 *   —— token 里已含 { id, username, role }，可直接鉴权，无需查库。
 *
 * 启动：
 *   PORT=4001 node chat-server.js
 *   （若 config.json 不在此目录：JWT_SECRET=xxx PORT=4001 node chat-server.js）
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { WebSocketServer, WebSocket } = require('ws');

const PORT = Number(process.env.PORT) || 4001;
const HOST = process.env.HOST || '0.0.0.0';
const ANNOUNCE_FILE = process.env.ANNOUNCE_FILE || path.join(__dirname, 'data', 'chat-announcement.json');
const MAX_TEXT = 500;
const RATE_WINDOW_MS = 10000;
const RATE_LIMIT = 30;   /* 每 10 秒最多 30 条 */

/* ---------- JWT 密钥：环境变量优先，其次 config.json（只读文件，不连数据库） ---------- */
function loadJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const candidates = [
    path.join(__dirname, 'config.json'),
    process.env.CONFIG_PATH,
    path.join(__dirname, '..', 'server', 'config.json'),
  ].filter(Boolean);
  for (const file of candidates) {
    try {
      const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (cfg && cfg.jwtSecret) {
        console.log('[Chat] 已从 ' + file + ' 读取 JWT 密钥');
        return cfg.jwtSecret;
      }
    } catch (e) { /* 继续尝试下一个 */ }
  }
  console.error('[Chat] 未找到 JWT 密钥！请设置 JWT_SECRET 环境变量，或把主服务器的 config.json 放到本目录。');
  return null;
}
const JWT_SECRET = loadJwtSecret();
/* 密钥指纹（便于与主服务器比对，确认两边密钥一致；不可逆） */
function secretFingerprint(secret) {
  if (!secret) return '(无)';
  return require('crypto').createHash('sha256').update(String(secret)).digest('hex').slice(0, 12);
}

/* ---------- 公告持久化（本地 JSON 文件，无需数据库） ---------- */
function readAnnouncement() {
  try {
    const raw = fs.readFileSync(ANNOUNCE_FILE, 'utf8');
    const data = JSON.parse(raw);
    return {
      title: String(data.title || ''),
      content: String(data.content || ''),
      enabled: data.enabled !== false,
      updatedAt: data.updatedAt || '',
      version: String(data.version || '1'),
    };
  } catch (e) {
    return { title: '', content: '', enabled: false, updatedAt: '', version: '1' };
  }
}
function writeAnnouncement(data) {
  try {
    fs.mkdirSync(path.dirname(ANNOUNCE_FILE), { recursive: true });
    fs.writeFileSync(ANNOUNCE_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('[Chat] 公告写入失败:', e.message);
  }
}

/* ---------- 工具 ---------- */
function sendJson(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(text),
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  });
  res.end(text);
}
function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { req.destroy(); resolve(null); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch (e) { resolve(null); }
    });
    req.on('error', () => resolve(null));
  });
}
function authUser(req) {
  if (!JWT_SECRET) return null;
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    return payload && payload.id ? payload : null;
  } catch (e) { return null; }
}

/* ---------- HTTP ---------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  const pathname = url.pathname;

  if (req.method === 'OPTIONS') return sendJson(res, 204, {});

  /* 健康检查：本服务不依赖数据库，永远 ready */
  if (pathname === '/api/health') {
    return sendJson(res, 200, { ok: true, ready: true, service: 'chat', connections: wss ? wss.clients.size : 0, ts: Date.now() });
  }

  /* 公告读取（公开） */
  if (pathname === '/api/settings/announcement' && req.method === 'GET') {
    return sendJson(res, 200, readAnnouncement());
  }

  /* 公告发布/更新（需 admin 或 dev 身份，角色取自 token，不查库） */
  if (pathname === '/api/settings/announcement' && req.method === 'POST') {
    const user = authUser(req);
    if (!user) return sendJson(res, 401, { error: '未登录或登录已过期（本服务 JWT 密钥指纹 ' + secretFingerprint(JWT_SECRET) + '，需与主服务器一致）' });
    if (user.role !== 'admin' && user.role !== 'dev') return sendJson(res, 403, { error: '需要管理员或开发者权限' });
    const body = await readBody(req);
    if (!body) return sendJson(res, 400, { error: '请求体不合法' });
    const title = String(body.title || '').trim().slice(0, 100);
    const content = String(body.content || '').trim().slice(0, 2000);
    if (!title || !content) return sendJson(res, 400, { error: '公告标题和内容不能为空' });
    const data = { title, content, enabled: true, updatedAt: new Date().toISOString(), version: String(Date.now()) };
    writeAnnouncement(data);
    const delivered = broadcastAnnouncement(title, content);
    console.log('[Chat] 公告已发布 by ' + user.username + '（广播给 ' + delivered + ' 个连接）');
    return sendJson(res, 200, { ok: true, delivered });
  }

  return sendJson(res, 404, { error: '未找到该接口' });
});

/* ---------- WebSocket 聊天中继 ---------- */
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 64 * 1024 });

function broadcast(message) {
  const text = JSON.stringify(message);
  let n = 0;
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) { try { client.send(text); n += 1; } catch (e) {} }
  });
  return n;
}
function broadcastAnnouncement(title, content) {
  return broadcast({
    type: 'chat',
    system: true,
    text: ('📢 ' + (title ? title + '：' : '') + String(content || '')).slice(0, 800),
    at: Date.now(),
  });
}

wss.on('connection', (ws, request) => {
  let url;
  try { url = new URL(request.url, 'http://localhost'); } catch (e) { return ws.close(1008, 'bad request'); }
  const token = url.searchParams.get('token') || '';
  let payload = null;
  try { payload = jwt.verify(token, JWT_SECRET || '', { algorithms: ['HS256'] }); } catch (e) {}
  if (!payload || !payload.id) {
    try { ws.send(JSON.stringify({ type: 'error', error: '未登录或登录已过期' })); } catch (e) {}
    return ws.close(1008, 'unauthorized');
  }
  ws.user = { id: payload.id, username: payload.username, role: payload.role };
  ws.messageTimestamps = [];
  ws.isAlive = true;

  console.log('[Chat] 连接: ' + ws.user.username + '（在线 ' + wss.clients.size + '）');

  /* 连接即推送当前公告（有内容时） */
  const ann = readAnnouncement();
  if (ann.content && ann.enabled) {
    try {
      ws.send(JSON.stringify({
        type: 'chat',
        system: true,
        text: ('📢 ' + (ann.title ? ann.title + '：' : '') + ann.content).slice(0, 800),
        at: Date.now(),
      }));
    } catch (e) {}
  }

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch (e) { return; }
    if (!msg || typeof msg !== 'object') return;

    if (msg.type === 'chat') {
      const text = String(msg.text || '').trim().slice(0, MAX_TEXT);
      if (!text) return;
      /* 限流 */
      const now = Date.now();
      ws.messageTimestamps = ws.messageTimestamps.filter((t) => now - t < RATE_WINDOW_MS);
      if (ws.messageTimestamps.length >= RATE_LIMIT) {
        try { ws.send(JSON.stringify({ type: 'error', error: '发送过于频繁，请稍后再试' })); } catch (e) {}
        return;
      }
      ws.messageTimestamps.push(now);
      /* 用户名/ID 以 token 为准，防止伪造 */
      broadcast({ type: 'chat', text, username: ws.user.username || 'Unknown', userId: ws.user.id, at: now });
      return;
    }

    if (msg.type === 'ping') {
      try { ws.send(JSON.stringify({ type: 'pong', at: Date.now() })); } catch (e) {}
    }
  });

  ws.on('close', () => console.log('[Chat] 断开: ' + ws.user.username + '（在线 ' + wss.clients.size + '）'));
  ws.on('error', () => {});
});

/* 心跳：清理死连接 */
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch (e) {}
  });
}, 30000);
wss.on('close', () => clearInterval(heartbeat));

server.listen(PORT, HOST, () => {
  console.log('[Chat] 聊天/公告服务器已启动: http://' + HOST + ':' + PORT);
  console.log('[Chat] WebSocket: ws://' + HOST + ':' + PORT + '/ws?token=<JWT>');
  console.log('[Chat] 公告接口: GET/POST http://' + HOST + ':' + PORT + '/api/settings/announcement');
  console.log('[Chat] 数据库: 不需要（公告存于 ' + ANNOUNCE_FILE + '）');
  console.log('[Chat] JWT 密钥指纹: ' + secretFingerprint(JWT_SECRET) + '  ← 必须与主服务器一致，否则客户端会报"未登录或登录已过期"');
});
