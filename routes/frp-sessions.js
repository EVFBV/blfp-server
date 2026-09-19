const router = require('express').Router();
const db = require('../db');
const { authMiddleware, adminOnly } = require('../middleware/auth');
const signaling = require('../signaling');

router.post('/report', authMiddleware, async (req, res) => {
  const body = req.body || {};
  const tunnelName = String(body.tunnelName || '');
  const remotePort = Number(body.remotePort);
  const nodeId = body.nodeId === undefined || body.nodeId === null ? null : Number(body.nodeId);
  const roomCode = body.roomCode === undefined || body.roomCode === null ? null : String(body.roomCode);
  if (!/^[A-Za-z0-9]{6}$/.test(tunnelName)) return res.status(400).json({ error: '隧道名必须为 6 位大小写字母+数字' });
  if (!Number.isInteger(remotePort) || remotePort < 1 || remotePort > 65535) return res.status(400).json({ error: '端口无效' });
  if (roomCode !== null && !/^\d{6}$/.test(roomCode)) return res.status(400).json({ error: '房间号无效' });
  const now = Math.floor(Date.now() / 1000);
  const existing = await db.query('SELECT id FROM frp_sessions WHERE user_id = ? AND tunnel_name = ? LIMIT 1', [req.user.id, tunnelName]);
  if (existing.length) {
    await db.execute('UPDATE frp_sessions SET remote_port = ?, node_id = ?, room_code = COALESCE(?, room_code), username = ?, updated_at = ? WHERE id = ?', [remotePort, nodeId, roomCode, req.user.username, now, existing[0].id]);
  } else {
    await db.execute('INSERT INTO frp_sessions (user_id, username, room_code, node_id, tunnel_name, remote_port, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [req.user.id, req.user.username, roomCode, nodeId, tunnelName, remotePort, now, now]);
  }
  if (roomCode) signaling.applyFrpReport(req.user.id, roomCode, remotePort);
  res.json({ ok: true });
});

router.get('/sessions', authMiddleware, adminOnly, async (req, res) => {
  const rows = await db.query(`SELECT s.id, s.user_id, s.username, s.room_code, s.node_id, s.tunnel_name, s.remote_port, s.created_at, s.updated_at, n.host AS node_host, n.name AS node_name
    FROM frp_sessions s LEFT JOIN frp_nodes n ON n.id = s.node_id
    ORDER BY s.updated_at DESC LIMIT 100`);
  res.json(rows.map((r) => ({
    id: Number(r.id),
    userId: Number(r.user_id),
    username: r.username,
    roomCode: r.room_code,
    nodeId: r.node_id === null ? null : Number(r.node_id),
    nodeName: r.node_name || '未知节点',
    tunnelName: r.tunnel_name,
    remotePort: Number(r.remote_port),
    endpoint: r.node_host ? `${r.node_host}:${r.remote_port}` : null,
    createdAt: Number(r.created_at),
    updatedAt: Number(r.updated_at),
  })));
});

module.exports = router;
