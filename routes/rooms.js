const router = require('express').Router();
const { authMiddleware } = require('../middleware/auth');
const { closeRoomsByHost, getRoomInfo } = require('../signaling');

router.post('/create', authMiddleware, (req, res) => {
  res.status(410).json({ error: 'REST 创建房间已停用，请使用 WebSocket 信令创建房间' });
});

router.get('/:code', authMiddleware, (req, res) => {
  const { code } = req.params;
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: '房间号格式错误' });

  const room = getRoomInfo(code);
  if (!room) return res.status(404).json({ error: '房间不存在或已关闭' });
  res.json(room);
});

router.delete('/close', authMiddleware, async (req, res) => {
  await closeRoomsByHost(req.user.id, '房主已关闭房间');
  res.json({ ok: true });
});

module.exports = router;
