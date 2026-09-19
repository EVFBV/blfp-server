const router = require('express').Router();
const db = require('../db');
const { authMiddleware } = require('../middleware/auth');
const { getLiveRooms } = require('../signaling');

router.use(authMiddleware);

function publicUser(user) {
  const live = getLiveRooms().find((room) => room.host_id === user.id || room.host === user.username);
  return {
    id: user.id,
    username: user.username,
    title: user.title || '',
    theme: user.theme || 'dark',
    online: !!(user.last_seen_at && Date.now() - user.last_seen_at * 1000 < 90000),
    room: live ? { code: live.room_code, mode: live.mode, total: live.total } : null,
  };
}

router.get('/search', async (req, res) => {
  const keyword = String(req.query.q || '').trim();
  if (!keyword) return res.json([]);
  const users = await db.query(
    'SELECT id, username, title, theme, last_seen_at FROM users WHERE banned = 0 AND id != ? AND username LIKE ? LIMIT 20',
    [req.user.id, `%${keyword}%`]
  );
  res.json(users.map(publicUser));
});

router.get('/', async (req, res) => {
  const rows = await db.query(
    `SELECT u.id, u.username, u.title, u.theme, u.last_seen_at
     FROM friendships f JOIN users u ON u.id = f.friend_id
     WHERE f.user_id = ? AND f.status = 'accepted' AND u.banned = 0
     ORDER BY u.username`,
    [req.user.id]
  );
  res.json(rows.map(publicUser));
});

router.get('/requests', async (req, res) => {
  const rows = await db.query(
    `SELECT f.id AS friendship_id, f.created_at AS requested_at,
            u.id, u.username, u.title, u.theme, u.last_seen_at
     FROM friendships f JOIN users u ON u.id = f.user_id
     WHERE f.friend_id = ? AND f.status = 'pending' AND u.banned = 0
     ORDER BY f.created_at DESC`,
    [req.user.id]
  );
  res.json(rows.map(r => ({ ...publicUser(r), friendship_id: r.friendship_id, requested_at: r.requested_at })));
});

router.get('/history', async (req, res) => {
  const rows = await db.query(
    `SELECT f.id AS friendship_id, f.status, f.created_at AS sent_at,
            u.id, u.username, u.title, u.theme
     FROM friendships f JOIN users u ON u.id = f.friend_id
     WHERE f.user_id = ? AND f.status IN ('pending','rejected')
     ORDER BY f.created_at DESC LIMIT 50`,
    [req.user.id]
  );
  res.json(rows.map(r => ({ id: r.id, username: r.username, title: r.title, theme: r.theme, status: r.status, friendship_id: r.friendship_id, sent_at: r.sent_at })));
});

router.post('/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!id || id === req.user.id) return res.status(400).json({ error: '参数无效' });
  if (!await db.one('SELECT id FROM users WHERE id = ? AND banned = 0', [id])) return res.status(404).json({ error: '用户不存在' });

  const existing = await db.one(
    'SELECT id, status FROM friendships WHERE user_id = ? AND friend_id = ?',
    [req.user.id, id]
  );
  if (existing) {
    if (existing.status === 'accepted') return res.status(409).json({ error: '已经是好友' });
    if (existing.status === 'pending') return res.status(409).json({ error: '申请已发送，等待对方确认' });
    await db.execute('UPDATE friendships SET status = ?, created_at = UNIX_TIMESTAMP() WHERE id = ?', ['pending', existing.id]);
    return res.json({ ok: true, message: '好友申请已重新发送' });
  }

  await db.execute(
    "INSERT INTO friendships (user_id, friend_id, status, created_at) VALUES (?, ?, 'pending', UNIX_TIMESTAMP())",
    [req.user.id, id]
  );
  res.json({ ok: true, message: '好友申请已发送' });
});

router.post('/:id/accept', async (req, res) => {
  const senderId = Number(req.params.id);
  if (!senderId) return res.status(400).json({ error: '参数无效' });

  const req_row = await db.one(
    "SELECT id FROM friendships WHERE user_id = ? AND friend_id = ? AND status = 'pending'",
    [senderId, req.user.id]
  );
  if (!req_row) return res.status(404).json({ error: '未找到待处理的好友申请' });

  await db.transaction(async (tx) => {
    await tx.execute("UPDATE friendships SET status = 'accepted' WHERE id = ?", [req_row.id]);
    await tx.execute(
      "INSERT INTO friendships (user_id, friend_id, status, created_at) VALUES (?, ?, 'accepted', UNIX_TIMESTAMP()) ON DUPLICATE KEY UPDATE status = 'accepted'",
      [req.user.id, senderId]
    );
  });
  res.json({ ok: true });
});

router.post('/:id/reject', async (req, res) => {
  const senderId = Number(req.params.id);
  if (!senderId) return res.status(400).json({ error: '参数无效' });

  await db.execute(
    "UPDATE friendships SET status = 'rejected' WHERE user_id = ? AND friend_id = ? AND status = 'pending'",
    [senderId, req.user.id]
  );
  res.json({ ok: true });
});

router.delete('/:id', async (req, res) => {
  await db.execute(
    'DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
    [req.user.id, Number(req.params.id), Number(req.params.id), req.user.id]
  );
  res.json({ ok: true });
});

module.exports = router;
