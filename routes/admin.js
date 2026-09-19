const router = require('express').Router();
const db = require('../db');
const { authMiddleware, adminOnly } = require('../middleware/auth');
const bcrypt = require('bcryptjs');
const { forceCloseRoom, getLiveRooms } = require('../signaling');

const usernameRe = /^[A-Za-z0-9_\-\u4e00-\u9fa5]{3,20}$/;
function escapeLike(str) {
  return String(str).replace(/[\\%_]/g, (m) => '\\' + m);
}

// 所有管理路由都需要 admin 权限
router.use(authMiddleware, adminOnly);

// ============ 用户管理 ============
router.get('/users', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const keyword = escapeLike(req.query.keyword || '');

  const where = keyword ? 'WHERE username LIKE ?' : '';
  const params = keyword ? [`%${keyword}%`] : [];

  const total = (await db.one(`SELECT COUNT(*) as c FROM users ${where}`, params)).c;
  const nowSec = Math.floor(Date.now() / 1000);
  const users = await db.query(
    `SELECT id, username, role, email, title, theme, qq_id, banned, ban_until, created_at,
      CASE WHEN banned = 1 AND (ban_until IS NULL OR ban_until > ?) THEN 1 ELSE 0 END AS active_ban
     FROM users ${where} ORDER BY id DESC LIMIT ? OFFSET ?`
  , [nowSec, ...params, limit, offset]);

  res.json({ total, page, users });
});

router.post('/users', async (req, res) => {
  const { username, password, role, email, title, theme } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  if (!['user', 'sponsor', 'admin'].includes(role)) return res.status(400).json({ error: '角色只能为 user、sponsor 或 admin' });
  if (!usernameRe.test(username)) return res.status(400).json({ error: '用户名仅支持中英文、数字、下划线和连字符，长度 3-20 位' });

  const hash = await bcrypt.hash(password, 10);
  const validThemes = ['role', 'dark', 'light', 'gold', 'violet', 'ice', 'emerald'];
  const defaultTheme = (role === 'sponsor' ? 'gold' : role === 'admin' ? 'gold' : 'dark');
  const resolvedTheme = theme && validThemes.includes(theme) ? theme : defaultTheme;
  try {
    const { insertId } = await db.execute(
      'INSERT INTO users (username, password, role, email, title, theme, created_at) VALUES (?, ?, ?, ?, ?, ?, UNIX_TIMESTAMP())'
    , [username, hash, role || 'user', email || null, title || '', resolvedTheme]);
    res.json({ ok: true, id: Number(insertId) });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY' || String(e.message).includes('UNIQUE')) return res.status(409).json({ error: '用户名或邮箱已存在' });
    res.status(500).json({ error: '创建失败' });
  }
});

router.put('/users/:id', async (req, res) => {
  const { id } = req.params;
  const { role, banned, ban_days, email, title, theme, password } = req.body;

  if (banned === 1 && parseInt(id) === req.user.id) {
    return res.status(400).json({ error: '不能封禁自己' });
  }

  const fields = [];
  const vals = [];
  if (role !== undefined && !['admin', 'sponsor', 'user'].includes(role)) {
    return res.status(400).json({ error: '角色只能为 user、sponsor 或 admin' });
  }
  if (role !== undefined) { fields.push('role = ?'); vals.push(role); }
  if (banned !== undefined) {
    fields.push('banned = ?'); vals.push(banned ? 1 : 0);
    if (banned) {
      const days = parseInt(ban_days);
      if (days > 0) {
        const banUntil = Math.floor(Date.now() / 1000) + days * 86400;
        fields.push('ban_until = ?'); vals.push(banUntil);
      } else {
        fields.push('ban_until = ?'); vals.push(null);
      }
    } else {
      fields.push('ban_until = ?'); vals.push(null);
    }
  }
  if (email !== undefined) { fields.push('email = ?'); vals.push(email); }
  if (title !== undefined) { fields.push('title = ?'); vals.push(String(title).slice(0, 80)); }
  if (theme !== undefined) { fields.push('theme = ?'); vals.push(['role', 'dark', 'light', 'gold', 'violet', 'ice', 'emerald'].includes(theme) ? theme : 'dark'); }
  if (password) { fields.push('password = ?'); vals.push(await bcrypt.hash(password, 10)); }

  if (!fields.length) return res.status(400).json({ error: '无可更新字段' });
  vals.push(id);
  await db.execute(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, [...vals]);
  res.json({ ok: true });
});

router.delete('/users/:id', async (req, res) => {
  const { id } = req.params;
  if (parseInt(id) === req.user.id) return res.status(400).json({ error: '不能删除自己' });
  await db.execute('DELETE FROM users WHERE id = ?', [id]);
  res.json({ ok: true });
});

// ============ 房间管理 ============
router.get('/rooms', async (req, res) => {
  res.json(getLiveRooms());
});

router.delete('/rooms/:code', async (req, res) => {
  res.json({ ok: await forceCloseRoom(req.params.code, '管理员关闭了房间') });
});

module.exports = router;
