const db = require('../db');
const { verifyJwtToken } = require('../security-logic');

/**
 * 验证 JWT token（从 Authorization Header 或 Cookie 读取）
 */
async function authMiddleware(req, res, next) {
  let token = null;

  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) return res.status(401).json({ error: '未登录' });

  try {
    const payload = verifyJwtToken(token, db.getJwtSecret());
    if (!payload) return res.status(401).json({ error: 'Token 无效或已过期' });
    const user = await db.one('SELECT id, username, role, banned, ban_until FROM users WHERE id = ?', [payload.id]);
    if (!user) return res.status(401).json({ error: '用户不存在或已被删除' });
    const nowSec = Math.floor(Date.now() / 1000);
    const activeBan = user.banned && (!user.ban_until || user.ban_until > nowSec);
    if (activeBan) return res.status(403).json({ error: '账号已被封禁' });
    req.user = { id: user.id, username: user.username, role: user.role };
    next();
  } catch {
    return res.status(401).json({ error: 'Token 无效或已过期' });
  }
}

/**
 * 仅允许 admin 角色访问
 */
function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: '需要管理员权限' });
  }
  next();
}

/**
 * 仅允许 admin 或 dev 角色
 */
function adminOrDev(req, res, next) {
  if (req.user?.role !== 'admin' && req.user?.role !== 'dev') {
    return res.status(403).json({ error: '需要管理员或开发者权限' });
  }
  next();
}

module.exports = { authMiddleware, adminOnly, adminOrDev };
