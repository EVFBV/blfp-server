const express = require('express');
const cookieParser = require('cookie-parser');
const http = require('http');
const path = require('path');

const { initSignaling, getLiveRooms, getPublicRooms, forceCloseRoom } = require('./signaling');
const { authMiddleware, adminOnly } = require('./middleware/auth');
const requestSignature = require('./middleware/request-signature');
const { getInstallState, initialize, upgrade } = require('./install-service');

const app = express();
const PORT = process.env.PORT || 4000;
const db = require('./db');

app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());

app.use('/api/install', (req, res, next) => {
  const host = requestHost(req);
  if (host === CONSOLE_HOST || ['localhost', '127.0.0.1', '::1'].includes(host)) return next();
  return res.status(404).json({ error: 'Not found' });
});

app.get('/api/install/state', async (req, res) => {
  try {
    res.json(await getInstallState());
  } catch (error) {
    res.status(503).json({ installed: false, error: error.message });
  }
});

app.post('/api/install', async (req, res) => {
  try {
    const result = await initialize(req.body);
    res.status(201).json({ installed: result.installed });
  } catch (error) {
    const status = error.message === '系统已完成初始化' || error.message === '管理员账号已存在' ? 409 : 400;
    res.status(status).json({ error: error.message });
  }
});

app.post('/api/install/upgrade', async (req, res) => {
  try {
    const result = await upgrade(req.body);
    res.json({ upgraded: result.upgraded });
  } catch (error) {
    const status = error.message.includes('尚未完成初始化') ? 409 : 400;
    res.status(status).json({ error: error.message });
  }
});

const signedApiPaths = ['/api/admin', '/api/nodes', '/api/easytier-nodes', '/api/rooms', '/api/settings', '/api/friends', '/api/qq', '/api/chat'];

app.use('/api', (req, res, next) => {
  if (req.path === '/health' || req.path === '/install/state' || req.path === '/install') return next();
  if (!db.isReady()) return res.status(503).json({ error: '数据库尚未就绪' });
  if (!db.isInstalled()) return res.status(503).json({ error: '系统尚未完成初始化' });
  next();
});

app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const requiresSignature = (req.path !== '/api/qq/webhook' && signedApiPaths.some((prefix) => req.path === prefix || req.path.startsWith(prefix + '/')))
    || req.path === '/api/auth/change-password' || req.path === '/api/auth/presence';
  if (!requiresSignature) return next();
  authMiddleware(req, res, () => requestSignature(req, res, next));
});

// ============ API 路由 ============
app.use('/api/auth', require('./routes/auth'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/nodes', require('./routes/nodes'));
app.use('/api/easytier-nodes', require('./routes/easytier-nodes'));
app.get('/api/rooms/public', authMiddleware, async (req, res) => res.json(getPublicRooms()));
app.use('/api/rooms', require('./routes/rooms'));
app.use('/api/settings', require('./routes/settings'));
app.use('/api/friends', require('./routes/friends'));
app.use('/api/chat', require('./routes/chat'));
app.use('/api/qq', require('./routes/qq'));
app.use('/api/frp', require('./routes/frp-sessions'));

// 在线房间（内存实时状态，供后台展示）
app.get('/api/admin/live-rooms', authMiddleware, adminOnly, async (req, res) => {
  res.json(getLiveRooms());
});

app.post('/api/admin/live-rooms/:code/close', authMiddleware, adminOnly, async (req, res) => {
  const ok = await forceCloseRoom(req.params.code);
  res.json({ ok });
});

// 统计（首页 + 后台总览）
app.get('/api/stats', authMiddleware, async (req, res) => {
  const users = (await db.one('SELECT COUNT(*) as c FROM users')).c;
  const nodesTotal = (await db.one('SELECT COUNT(*) as c FROM frp_nodes')).c;
  const nodes = (await db.one('SELECT COUNT(*) as c FROM frp_nodes WHERE enabled=1')).c;
  const easytierNodesTotal = (await db.one('SELECT COUNT(*) as c FROM easytier_nodes')).c;
  const easytierNodes = (await db.one('SELECT COUNT(*) as c FROM easytier_nodes WHERE enabled=1')).c;
  const liveRooms = getLiveRooms().length;
  res.json({ users, nodesTotal, nodes, easytierNodesTotal, easytierNodes, liveRooms });
});

// 健康检查
app.get('/api/health', async (req, res) => res.json({ ok: true, ready: db.isReady(), ts: Date.now() }));

// ============ 静态前端：按域名隔离宣传站与控制台 ============
const landingDir = path.join(__dirname, 'landing');
const consoleDir = path.join(__dirname, 'public');
const PUBLIC_HOST = (process.env.PUBLIC_HOST || 'www.blfp.cn').toLowerCase();
const CONSOLE_HOST = (process.env.CONSOLE_HOST || 'p.blfp.cn').toLowerCase();

function requestHost(req) {
  return String(req.hostname || req.headers.host || '').split(':')[0].toLowerCase();
}
function staticForHost(host, root) {
  const serve = express.static(root, { index: false, setHeaders: (res, path) => {
    if (path.endsWith('.html') || path.endsWith('.js') || path.endsWith('.css')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  } });
  return (req, res, next) => requestHost(req) === host ? serve(req, res, next) : next();
}

app.use(staticForHost(PUBLIC_HOST, landingDir));
app.use(staticForHost(CONSOLE_HOST, consoleDir));

// 本地调试：console 和 landing 两个目录都需要服务静态文件（先 console 再 landing）
const serveConsoleStatic = express.static(consoleDir, { index: false, setHeaders: (res, path) => {
  if (path.endsWith('.html') || path.endsWith('.js') || path.endsWith('.css')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
} });
const serveLandingStatic = express.static(landingDir, { index: false, setHeaders: (res, path) => {
  if (path.endsWith('.html') || path.endsWith('.js') || path.endsWith('.css')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
} });
app.use((req, res, next) => {
  const host = requestHost(req);
  if (host !== 'localhost' && host !== '127.0.0.1' && host !== '::1') return next();
  serveConsoleStatic(req, res, () => serveLandingStatic(req, res, next));
});

// 带扩展名的静态资源未找到时返回真实 404，禁止被 SPA 兜底伪装成 200 HTML。
app.get(/^\/(?!api|ws).*\.[a-zA-Z0-9]+$/, async (req, res) => {
  res.status(404).type('text/plain').send('Static asset not found');
});

// 全平台下载悬浮页（任意域名可访问）
app.get('/download', (req, res) => res.sendFile(path.join(landingDir, 'download.html')));

// 宣传域名只提供宣传页，控制台域名根路径直接进入登录/管理页面。
app.get(/^\/(?!api|ws).*/, (req, res, next) => {
  const host = requestHost(req);
  if (host === PUBLIC_HOST) return res.sendFile(path.join(landingDir, 'index.html'));
  if (host === CONSOLE_HOST) return res.sendFile(path.join(consoleDir, 'index.html'));

  // 本地调试：/console 使用控制台，其余路径显示宣传页。
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
    if (req.path === '/console' || req.path.startsWith('/console/')) {
      return res.sendFile(path.join(consoleDir, 'index.html'));
    }
    return res.sendFile(path.join(landingDir, 'index.html'));
  }
  next();
});

// ============ 启动 ============
const server = http.createServer(app);
initSignaling(server);

async function start() {
  try {
    const hasDatabaseConfig = db.hasDatabaseConfig();
    if (hasDatabaseConfig) {
      await db.initSchema();
      await db.execute('DELETE FROM rooms');
    }
    server.listen(PORT, () => {
      console.log(`[Server] HTTP + Web 已启动: http://localhost:${PORT}`);
      console.log(`[Server] 安装模式: ${hasDatabaseConfig ? '已配置数据库，正常运行' : '未配置数据库，等待系统初始化'}`);
      console.log(`[Server] 宣传首页: https://${PUBLIC_HOST}/`);
      console.log(`[Server] 用户与管理控制台: https://${CONSOLE_HOST}/`);
    });
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
}

start();
