const router = require('express').Router();
const net = require('net');
const db = require('../db');
const { authMiddleware, adminOnly } = require('../middleware/auth');

// 通过 TCP 连接测试单个节点的连通性（frps 端口）
// 返回 { online: 布尔, latency: 毫秒|null }
function testNodeConnectivity(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let settled = false;

    // 统一收尾：确保 socket 被销毁避免句柄泄漏
    const finish = (online) => {
      if (settled) return;
      settled = true;
      const latency = online ? Date.now() - start : null;
      socket.destroy();
      resolve({ online, latency });
    };

    socket.setTimeout(timeout);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));

    try {
      socket.connect(port, host);
    } catch {
      finish(false);
    }
  });
}

// 获取启用的节点列表（客户端调用）
router.get('/', authMiddleware, async (req, res) => {
  const nodes = await db.query('SELECT id, name, host, port, token, region, bandwidth, tls_enabled FROM frp_nodes WHERE enabled = 1');
  res.json(nodes);
});

// 以下为管理员接口
router.get('/all', authMiddleware, adminOnly, async (req, res) => {
  res.json(await db.query('SELECT * FROM frp_nodes ORDER BY id DESC', []));
});

router.post('/', authMiddleware, adminOnly, async (req, res) => {
  const { name, host, port, token, region, bandwidth, tls_enabled } = req.body;
  if (!name || !host) return res.status(400).json({ error: '节点名称和地址不能为空' });

  const { insertId } = await db.execute(
    'INSERT INTO frp_nodes (name, host, port, token, region, bandwidth, tls_enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, UNIX_TIMESTAMP())',
    [name, host, port || 7000, token || null, region || '未知', bandwidth || '未知', tls_enabled ? 1 : 0]
  );

  res.json({ ok: true, id: Number(insertId) });
});

router.put('/:id', authMiddleware, adminOnly, async (req, res) => {
  const { name, host, port, token, region, bandwidth, enabled, tls_enabled } = req.body;
  const fields = [];
  const vals = [];

  if (name !== undefined) { fields.push('name = ?'); vals.push(name); }
  if (host !== undefined) { fields.push('host = ?'); vals.push(host); }
  if (port !== undefined) { fields.push('port = ?'); vals.push(port); }
  if (token !== undefined) { fields.push('token = ?'); vals.push(token); }
  if (region !== undefined) { fields.push('region = ?'); vals.push(region); }
  if (bandwidth !== undefined) { fields.push('bandwidth = ?'); vals.push(bandwidth); }
  if (enabled !== undefined) { fields.push('enabled = ?'); vals.push(enabled ? 1 : 0); }
  if (tls_enabled !== undefined) { fields.push('tls_enabled = ?'); vals.push(tls_enabled ? 1 : 0); }

  if (!fields.length) return res.status(400).json({ error: '无可更新字段' });
  vals.push(req.params.id);
  await db.execute(`UPDATE frp_nodes SET ${fields.join(', ')} WHERE id = ?`, [...vals]);
  res.json({ ok: true });
});

router.delete('/:id', authMiddleware, adminOnly, async (req, res) => {
  await db.execute('DELETE FROM frp_nodes WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
});

// 批量测试所有节点连通性（并发）
// 返回 [{ id, online, latency }]
router.get('/status-all', authMiddleware, adminOnly, async (req, res) => {
  const nodes = await db.query('SELECT id, host, port FROM frp_nodes');
  const results = await Promise.all(
    nodes.map(async (n) => {
      const r = await testNodeConnectivity(n.host, n.port || 7000);
      return { id: n.id, online: r.online, tcpReachable: r.online, latency: r.latency, authenticated: null, authenticationNote: '仅测试 TCP 端口连通性，未验证 frp token' };
    })
  );
  res.json({ ok: true, results });
});

// 测试单个节点连通性
// 返回 { ok, online, latency }
router.post('/:id/test', authMiddleware, adminOnly, async (req, res) => {
  const node = await db.one('SELECT id, host, port FROM frp_nodes WHERE id = ?', [req.params.id]);
  if (!node) return res.status(404).json({ error: '节点不存在' });
  const r = await testNodeConnectivity(node.host, node.port || 7000);
  res.json({ ok: true, online: r.online, tcpReachable: r.online, latency: r.latency, authenticated: null, authenticationNote: '仅测试 TCP 端口连通性，未验证 frp token' });
});

module.exports = router;
