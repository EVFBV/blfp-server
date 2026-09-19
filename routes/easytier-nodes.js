const router = require('express').Router();
const net = require('net');
const db = require('../db');
const { normalizePeer } = require('../easytier-peer');
const { authMiddleware, adminOnly } = require('../middleware/auth');

const KINDS = ['relay', 'signaling'];

function parsePeerTarget(peer) {
  let url;
  try { url = new URL(String(peer)); } catch { return null; }
  const host = url.hostname;
  const port = url.port ? Number(url.port) : (url.protocol === 'wss://' ? 443 : 11010);
  if (!host || !port) return null;
  return { host, port };
}

function testPeer(peer, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const target = parsePeerTarget(peer);
    if (!target) return resolve({ ok: false, ms: null, error: 'peer 地址无法解析' });
    const started = Date.now();
    const socket = net.connect({ host: target.host, port: target.port });
    const finish = (ok, error) => {
      socket.destroy();
      resolve({ ok, ms: ok ? Date.now() - started : null, error: error || null });
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false, '连接超时'));
    socket.once('error', (err) => finish(false, err.code || err.message || '连接失败'));
  });
}

router.get('/client', authMiddleware, async (req, res) => {
  const rows = await db.query('SELECT id, name, peer, kind FROM easytier_nodes WHERE enabled = 1 ORDER BY id ASC');
  res.json(rows.map((r) => ({ id: Number(r.id), name: r.name, peer: r.peer, kind: r.kind || 'relay' })));
});

router.use(authMiddleware, adminOnly);

router.get('/', async (req, res) => {
  res.json(await db.query('SELECT id, name, peer, kind, enabled, created_at FROM easytier_nodes ORDER BY id DESC'));
});

router.get('/test-all', async (req, res) => {
  const rows = await db.query('SELECT id, name, peer, kind, enabled FROM easytier_nodes ORDER BY id ASC');
  const results = await Promise.all(rows.map(async (r) => {
    const t = await testPeer(r.peer);
    return { id: Number(r.id), name: r.name, kind: r.kind || 'relay', enabled: !!Number(r.enabled), ...t };
  }));
  res.json(results);
});

router.post('/', async (req, res) => {
  const name = String(req.body.name || '').trim();
  const peer = normalizePeer(req.body.peer);
  const kind = KINDS.includes(String(req.body.kind)) ? String(req.body.kind) : 'relay';
  if (!name || !peer) return res.status(400).json({ error: '节点名称和 peer 地址不能为空，且必须为 tcp/udp/ws/wss://host:port' });
  if (name.length > 128) return res.status(400).json({ error: '节点名称过长' });
  try {
    const { insertId } = await db.execute('INSERT INTO easytier_nodes (name, peer, kind, enabled, created_at) VALUES (?, ?, ?, ?, UNIX_TIMESTAMP())', [name, peer, kind, req.body.enabled === false ? 0 : 1]);
    res.status(201).json({ ok: true, id: Number(insertId) });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'peer 地址已存在' });
    throw error;
  }
});

router.post('/:id/test', async (req, res) => {
  const rows = await db.query('SELECT id, name, peer, kind FROM easytier_nodes WHERE id = ?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: '节点不存在' });
  const t = await testPeer(rows[0].peer);
  res.json({ id: Number(rows[0].id), name: rows[0].name, peer: rows[0].peer, kind: rows[0].kind || 'relay', ...t });
});

router.put('/:id', async (req, res) => {
  const fields = [];
  const values = [];
  if (req.body.name !== undefined) { const name = String(req.body.name).trim(); if (!name || name.length > 128) return res.status(400).json({ error: '节点名称无效' }); fields.push('name = ?'); values.push(name); }
  if (req.body.peer !== undefined) { const peer = normalizePeer(req.body.peer); if (!peer) return res.status(400).json({ error: 'peer 地址必须为 tcp/udp/ws/wss://host:port' }); fields.push('peer = ?'); values.push(peer); }
  if (req.body.kind !== undefined) { const kind = KINDS.includes(String(req.body.kind)) ? String(req.body.kind) : 'relay'; fields.push('kind = ?'); values.push(kind); }
  if (req.body.enabled !== undefined) { fields.push('enabled = ?'); values.push(req.body.enabled ? 1 : 0); }
  if (!fields.length) return res.status(400).json({ error: '无可更新字段' });
  values.push(req.params.id);
  try {
    const result = await db.execute(`UPDATE easytier_nodes SET ${fields.join(', ')} WHERE id = ?`, values);
    if (!result.affectedRows) return res.status(404).json({ error: '节点不存在' });
    res.json({ ok: true });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'peer 地址已存在' });
    throw error;
  }
});

router.patch('/:id/enabled', async (req, res) => {
  const result = await db.execute('UPDATE easytier_nodes SET enabled = ? WHERE id = ?', [req.body.enabled ? 1 : 0, req.params.id]);
  if (!result.affectedRows) return res.status(404).json({ error: '节点不存在' });
  res.json({ ok: true });
});

router.delete('/:id', async (req, res) => {
  await db.execute('DELETE FROM easytier_nodes WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
});

module.exports = router;
