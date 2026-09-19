const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../db');
const { authMiddleware } = require('../middleware/auth');
const { sendCodeMail } = require('../mailer');

const CODE_TTL = 10 * 60 * 1000; // 验证码有效期 10 分钟
const RATE_WINDOW = 15 * 60 * 1000;
const RATE_MAX = 10;
const CODE_RATE_MAX = 5;
const FAILURE_MAX = 5;
const LOCK_TTL = 15 * 60 * 1000;
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const usernameRe = /^[A-Za-z0-9_\-\u4e00-\u9fa5]{3,20}$/;
const rateWindows = new Map();
const failureLocks = new Map();
const pendingTfa = new Map();
const pendingQqVerify = new Map();

function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function clientIp(req) {
  return req.socket.remoteAddress || req.ip || 'unknown';
}

function applyRateLimit(req, res, scope, identifier, max = RATE_MAX) {
  const now = Date.now();
  const identifiers = Array.isArray(identifier) ? identifier : [identifier];
  const keys = [`${scope}:ip:${clientIp(req)}`, ...identifiers.map((value) => `${scope}:id:${value}`)];
  const active = keys.map((key) => {
    const entries = (rateWindows.get(key) || []).filter((time) => now - time < RATE_WINDOW);
    rateWindows.set(key, entries);
    return entries;
  });
  if (active.some((entries) => entries.length >= max)) {
    res.status(429).json({ error: '请求过于频繁，请稍后再试' });
    return false;
  }
  keys.forEach((key, index) => rateWindows.set(key, [...active[index], now]));
  return true;
}

function lockError(identifier) {
  const now = Date.now();
  const state = failureLocks.get(identifier);
  if (!state || !state.lockedUntil || state.lockedUntil <= now) return null;
  return '错误次数过多，请稍后再试';
}

function recordFailure(identifier) {
  const now = Date.now();
  const state = failureLocks.get(identifier);
  const failures = state && state.resetAt > now ? state.failures + 1 : 1;
  const lockedUntil = failures >= FAILURE_MAX ? now + LOCK_TTL : 0;
  failureLocks.set(identifier, { failures, resetAt: now + RATE_WINDOW, lockedUntil });
  return Boolean(lockedUntil);
}

function clearFailures(identifier) {
  failureLocks.delete(identifier);
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    db.getJwtSecret(),
    { algorithm: 'HS256', expiresIn: '7d' }
  );
}

// 发送邮箱验证码（注册 / 登录通用）
/* 验证码配置（客户端登录页加载时调用；未接 geetest 时返回关闭） */
router.get('/captcha-config', async (req, res) => {
  res.json({ enabled: false, gt: '', challenge: '' });
});

router.post('/send-code', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const { purpose } = req.body;
  if (!email || !emailRe.test(email)) return res.status(400).json({ error: '邮箱格式不正确' });
  if (!applyRateLimit(req, res, 'send-code', email, CODE_RATE_MAX)) return;

  const p = purpose === 'login' ? 'login' : 'register';
  const existing = await db.one('SELECT id FROM users WHERE lower(email) = ?', [email]);
  if (p === 'register' && existing) return res.status(409).json({ error: '该邮箱已注册' });
  if (p === 'login' && !existing) return res.status(404).json({ error: '该邮箱未注册' });

  const recent = await db.one(
    'SELECT created_at FROM email_codes WHERE email = ? ORDER BY id DESC LIMIT 1'
  , [email]);
  if (recent && Date.now() - recent.created_at * 1000 < 60 * 1000) {
    return res.status(429).json({ error: '发送过于频繁，请稍后再试' });
  }

  const code = String(crypto.randomInt(100000, 1000000));
  const expiresAt = Date.now() + CODE_TTL;
  const result = await db.execute('INSERT INTO email_codes (email, code, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, UNIX_TIMESTAMP())', [email, code, p, expiresAt]);

  try {
    await sendCodeMail(email, code);
    res.json({ ok: true, message: '验证码已发送，请查收邮件' });
  } catch (e) {
    await db.execute('DELETE FROM email_codes WHERE id = ?', [result.insertId]);
    console.error('[Mail] send-code 失败:', e && (e.stack || e.message));
    res.status(500).json({ error: '邮件发送失败，请稍后重试；若持续失败请联系管理员' });
  }
});

// 校验验证码（成功即消费）
async function verifyCode(email, code, purpose, consume = true) {
  const lockKey = `code:${purpose}:${email}`;
  const locked = lockError(lockKey);
  if (locked) return locked;
  const row = await db.one('SELECT * FROM email_codes WHERE email = ? AND purpose = ? ORDER BY id DESC LIMIT 1', [email, purpose]);
  if (!row) return '请先获取验证码';
  if (row.expires_at < Date.now()) return '验证码已过期';
  if (row.code !== String(code)) {
    return recordFailure(lockKey) ? '错误次数过多，请稍后再试' : '验证码错误';
  }
  clearFailures(lockKey);
  if (consume) await db.execute('DELETE FROM email_codes WHERE id = ?', [row.id]);
  return null;
}

// 登录：支持「密码」或「邮箱验证码」两种方式
router.post('/login', async (req, res) => {
  const { username, password, code } = req.body;
  const email = normalizeEmail(req.body.email);
  const account = typeof username === 'string' ? username.trim() : '';
  const identifier = email || account.toLowerCase();
  if (!identifier) return res.status(400).json({ error: '请输入账号和密码，或使用邮箱验证码登录' });
  if (!applyRateLimit(req, res, 'login', identifier)) return;

  let user;
  if (email && code) {
    const err = await verifyCode(email, code, 'login');
    if (err) return res.status(401).json({ error: err });
    user = await db.one('SELECT * FROM users WHERE lower(email) = ?', [email]);
    if (!user) return res.status(404).json({ error: '该邮箱未注册' });
  } else {
    if (!account || !password) return res.status(400).json({ error: '请输入账号和密码，或使用邮箱验证码登录' });
    const lockKey = `password:${account.toLowerCase()}`;
    const locked = lockError(lockKey);
    if (locked) return res.status(429).json({ error: locked });
    user = await db.one('SELECT * FROM users WHERE username = ? OR lower(email) = ?', [account, account.toLowerCase()]);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      const nowLocked = recordFailure(lockKey);
      return res.status(nowLocked ? 429 : 401).json({ error: nowLocked ? '错误次数过多，请稍后再试' : '账号或密码错误' });
    }
    clearFailures(lockKey);
  }

  if (user.banned) return res.status(403).json({ error: '账号已被封禁' });

  const nowSec = Math.floor(Date.now() / 1000);
  if (user.ban_until && user.ban_until > nowSec) return res.status(403).json({ error: '账号已被封禁' });

  await db.execute('UPDATE users SET last_seen_at = UNIX_TIMESTAMP() WHERE id = ?', [user.id]);

  if (user.tfa_enabled) {
    const tfaToken = crypto.randomBytes(24).toString('hex');
    const expires = Date.now() + 10 * 60 * 1000;
    pendingTfa.set(tfaToken, { userId: user.id, expires });
    return res.json({ tfa_required: true, tfa_token: tfaToken, tfa_methods: { email: !!user.email, qq: !!user.qq_id } });
  }

  res.json({ token: signToken(user), user: { id: user.id, username: user.username, role: user.role, title: user.title || '', theme: user.theme || 'dark' } });
});

// 注册：必须邮箱 + 验证码
router.post('/register', async (req, res) => {
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const { password, code } = req.body;
  const email = normalizeEmail(req.body.email);
  if (!username || !password) return res.status(400).json({ error: '缺少用户名或密码' });
  if (!email || !emailRe.test(email)) return res.status(400).json({ error: '请输入有效邮箱' });
  if (!code) return res.status(400).json({ error: '请填写邮箱验证码' });
  if (!applyRateLimit(req, res, 'register', [username.toLowerCase(), email])) return;
  if (!usernameRe.test(username)) return res.status(400).json({ error: '用户名仅支持中英文、数字、下划线和连字符，长度 3-20 位' });
  if (password.length < 8) return res.status(400).json({ error: '密码至少 8 位' });

  if (await db.one('SELECT 1 FROM users WHERE username = ?', [username])) {
    return res.status(409).json({ error: '用户名已存在' });
  }
  if (await db.one('SELECT 1 FROM users WHERE lower(email) = ?', [email])) {
    return res.status(409).json({ error: '该邮箱已注册' });
  }

  const err = await verifyCode(email, code, 'register', false);
  if (err) return res.status(400).json({ error: err });

  const hash = await bcrypt.hash(password, 10);
  try {
    const consumed = await db.transaction(async (tx) => {
      await tx.execute('INSERT INTO users (username, password, email, created_at) VALUES (?, ?, ?, UNIX_TIMESTAMP())', [username, hash, email]);
      return tx.execute('DELETE FROM email_codes WHERE id = (SELECT id FROM (SELECT id FROM email_codes WHERE email = ? AND purpose = ? AND code = ? AND expires_at >= ? ORDER BY id DESC LIMIT 1) selected)', [email, 'register', String(code), Date.now()]);
    });
    if (consumed.affectedRows !== 1) throw new Error('验证码已失效');
    res.json({ ok: true, message: '注册成功' });
  } catch (e) {
    if (e.message === '验证码已失效') return res.status(400).json({ error: e.message });
    if (e.code === 'ER_DUP_ENTRY' || String(e.message).includes('UNIQUE constraint failed')) return res.status(409).json({ error: '用户名或邮箱已存在' });
    res.status(500).json({ error: '注册失败' });
  }
});

// 获取当前用户信息
router.get('/me', authMiddleware, async (req, res) => {
  const user = await db.one('SELECT id, username, role, email, title, theme, qq_id, tfa_enabled, last_seen_at, created_at FROM users WHERE id = ?', [req.user.id]);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  res.json(user);
});

// Web 控制台请求签名密钥（不暴露 JWT_SECRET）
router.get('/signing-key', authMiddleware, async (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: '未登录' });
  res.json({ key: crypto.createHash('sha256').update(token + db.getJwtSecret()).digest('hex') });
});

// 客户端显式同步在线状态；注销时仅更新最后活动时间，不暴露额外信息
router.post('/presence', authMiddleware, async (req, res) => {
  const online = req.body.online !== false;
  await db.execute('UPDATE users SET last_seen_at = ? WHERE id = ?', [online ? Math.floor(Date.now() / 1000) : 0, req.user.id]);
  res.json({ ok: true, online });
});

// 修改密码
router.post('/change-password', authMiddleware, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.status(400).json({ error: '参数缺失' });
  if (!applyRateLimit(req, res, 'change-password', String(req.user.id))) return;
  if (newPassword.length < 8) return res.status(400).json({ error: '新密码至少 8 位' });

  const lockKey = `change-password:${req.user.id}`;
  const locked = lockError(lockKey);
  if (locked) return res.status(429).json({ error: locked });
  const user = await db.one('SELECT * FROM users WHERE id = ?', [req.user.id]);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  if (!(await bcrypt.compare(oldPassword, user.password))) {
    const nowLocked = recordFailure(lockKey);
    return res.status(nowLocked ? 429 : 401).json({ error: nowLocked ? '错误次数过多，请稍后再试' : '原密码错误' });
  }

  clearFailures(lockKey);
  const hash = await bcrypt.hash(newPassword, 10);
  await db.execute('UPDATE users SET password = ? WHERE id = ?', [hash, req.user.id]);
  res.json({ ok: true });
});

// 2FA：发送验证码（邮箱）
router.post('/tfa/send', async (req, res) => {
  const { tfa_token, method } = req.body;
  if (!tfa_token) return res.status(400).json({ error: '缺少 tfa_token' });
  const item = pendingTfa.get(tfa_token);
  if (!item || item.expires < Date.now()) return res.status(400).json({ error: '会话已过期，请重新登录' });
  if (method !== 'email') return res.status(400).json({ error: '不支持的验证方式' });

  const user = await db.one('SELECT id, email FROM users WHERE id = ?', [item.userId]);
  if (!user || !user.email) return res.status(400).json({ error: '该账号未绑定邮箱' });

  if (!applyRateLimit(req, res, 'tfa-send', user.email, CODE_RATE_MAX)) return;

  const recent = await db.one('SELECT created_at FROM email_codes WHERE email = ? AND purpose = ? ORDER BY id DESC LIMIT 1', [user.email, 'tfa']);
  if (recent && Date.now() - recent.created_at * 1000 < 60 * 1000) {
    return res.status(429).json({ error: '发送过于频繁，请稍后再试' });
  }

  const code = String(crypto.randomInt(100000, 1000000));
  await db.execute('INSERT INTO email_codes (email, code, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, UNIX_TIMESTAMP())', [user.email, code, 'tfa', Date.now() + CODE_TTL]);
  try {
    await sendCodeMail(user.email, code);
    res.json({ ok: true, message: '验证码已发送' });
  } catch (e) {
    await db.execute('DELETE FROM email_codes WHERE email = ? AND purpose = ? ORDER BY id DESC LIMIT 1', [user.email, 'tfa']);
    res.status(500).json({ error: '邮件发送失败' });
  }
});

// 2FA：完成验证并获取 token
router.post('/tfa/verify', async (req, res) => {
  const { tfa_token, code, method } = req.body;
  if (!tfa_token || !code) return res.status(400).json({ error: '参数缺失' });
  const item = pendingTfa.get(tfa_token);
  if (!item || item.expires < Date.now()) return res.status(400).json({ error: '会话已过期，请重新登录' });
  // 路由级宽松限流（防脚本化滥用）；逐码防爆破由下方 email/qq 各自的失败锁承担
  if (!applyRateLimit(req, res, 'tfa-verify', String(item.userId), 60)) return;

  const user = await db.one('SELECT * FROM users WHERE id = ?', [item.userId]);
  if (!user) return res.status(404).json({ error: '用户不存在' });

  if (method === 'email') {
    const err = await verifyCode(user.email, code, 'tfa');
    if (err) return res.status(401).json({ error: err });
  } else if (method === 'qq') {
    // QQ 验证码与邮箱同级的失败锁定：5 次错误锁 15 分钟，杜绝暴力枚举
    const lockKey = `tfaqq:${item.userId}`;
    const locked = lockError(lockKey);
    if (locked) return res.status(429).json({ error: locked });
    const pending = pendingQqVerify.get(item.userId);
    if (!pending || pending.expires < Date.now() || pending.code !== String(code)) {
      const nowLocked = recordFailure(lockKey);
      return res.status(nowLocked ? 429 : 401).json({ error: nowLocked ? '错误次数过多，请稍后再试' : '验证码错误或已过期' });
    }
    clearFailures(lockKey);
    pendingQqVerify.delete(item.userId);
  } else {
    return res.status(400).json({ error: '不支持的验证方式' });
  }

  pendingTfa.delete(tfa_token);
  await db.execute('UPDATE users SET last_seen_at = UNIX_TIMESTAMP() WHERE id = ?', [user.id]);
  res.json({ token: signToken(user), user: { id: user.id, username: user.username, role: user.role, title: user.title || '', theme: user.theme || 'dark' } });
});

// 2FA 开关
router.post('/tfa/toggle', authMiddleware, async (req, res) => {
  const { enable } = req.body;
  if (!applyRateLimit(req, res, 'tfa-toggle', String(req.user.id), 20)) return;
  const user = await db.one('SELECT id, email, qq_id, tfa_enabled FROM users WHERE id = ?', [req.user.id]);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  if (enable && !user.email && !user.qq_id) {
    return res.status(400).json({ error: '请先绑定邮箱或QQ，再开启两步验证' });
  }
  await db.execute('UPDATE users SET tfa_enabled = ? WHERE id = ?', [enable ? 1 : 0, req.user.id]);
  res.json({ ok: true, tfa_enabled: !!enable });
});

// QQ 绑定：生成5位验证码
router.post('/qq/bind/request', authMiddleware, async (req, res) => {
  if (!applyRateLimit(req, res, 'qq-bind', String(req.user.id), 10)) return;
  const code = String(Math.floor(10000 + Math.random() * 90000));
  const expires = Date.now() + 10 * 60 * 1000;
  pendingQqVerify.set(req.user.id, { code, expires, purpose: 'bind' });
  res.json({ ok: true, code, expiresAt: expires, message: `请在QQ机器人中发送 /verify ${code} 完成绑定` });
});

module.exports = Object.assign(router, { pendingQqVerify });
