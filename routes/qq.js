const router = require('express').Router();
const crypto = require('crypto');
const net = require('net');
const db = require('../db');
const { authMiddleware, adminOnly } = require('../middleware/auth');
const { getLiveRooms, forceCloseRoom } = require('../signaling');
const { getAllSettings } = require('../mailer');
const bcrypt = require('bcryptjs');

const { pendingQqVerify } = require('./auth');

const pendingConfirm = new Map();

function getWebhookSecret() {
  return process.env.ONEBOT_WEBHOOK_SECRET || '';
}

async function isOnebotEnabled() {
  const all = await getAllSettings();
  return all.onebot_enabled === '1';
}

async function getOnebotApiUrl() {
  const all = await getAllSettings();
  return all.onebot_webhook_url || '';
}

async function getOnebotAccessToken() {
  const all = await getAllSettings();
  return all.onebot_access_token || '';
}

async function sendQqMessage(targetId, targetType, text) {
  const apiUrl = await getOnebotApiUrl();
  if (!apiUrl) return false;
  try {
    const endpoint = targetType === 'group'
      ? apiUrl.replace(/\/$/, '') + '/send_group_msg'
      : apiUrl.replace(/\/$/, '') + '/send_private_msg';
    const body = targetType === 'group'
      ? { group_id: Number(targetId), message: text }
      : { user_id: Number(targetId), message: text };
    const headers = { 'Content-Type': 'application/json' };
    const token = await getOnebotAccessToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
    return true;
  } catch {
    return false;
  }
}

function testTcp(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve({ online: ok, latency: ok ? Date.now() - start : null });
    };
    sock.setTimeout(timeout);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    try { sock.connect(port, host); } catch { finish(false); }
  });
}

function escapeMsg(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/\[/g, '&#91;').replace(/\]/g, '&#93;');
}

function qqAt(id) {
  return `[CQ:at,qq=${id}]`;
}

function extractQqFromAt(str) {
  const m = str && str.match(/\[CQ:at,qq=(\d+)\]/);
  return m ? m[1] : null;
}

async function getUserByQqOrUsername(raw) {
  if (!raw) return null;
  const fromAt = extractQqFromAt(raw);
  if (fromAt) return db.one('SELECT * FROM users WHERE qq_id = ?', [fromAt]);
  return db.one('SELECT * FROM users WHERE username = ?', [raw.trim()]);
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function isActiveBan(user) {
  return user.banned && (!user.ban_until || user.ban_until > nowSec());
}

async function handleCommand(senderQq, text, groupId) {
  const targetId = groupId || senderQq;
  const targetType = groupId ? 'group' : 'private';
  const reply = (msg) => sendQqMessage(targetId, targetType, msg);

  const parts = text.trim().split(/\s+/);
  const cmd = parts[0] ? parts[0].toLowerCase() : '';

  const senderUser = await db.one('SELECT * FROM users WHERE qq_id = ?', [String(senderQq)]);

  if (cmd === '/ping') {
    return reply('pong');
  }

  if (cmd === '/help') {
    if (parts[1] === 'admin') {
      return reply(
        '【管理员命令】\n' +
        '/ban [天数] [用户名/@xxx] - 封禁用户\n' +
        '/unban [用户名/@xxx] - 解除封禁\n' +
        '/close [房间号] - 关闭指定房间\n' +
        '/set [用户名/@xxx] [权限组] - 设置权限组\n' +
        '/user [@xxx/用户名] - 查询用户详情\n' +
        '/confirm - 确认执行上一条操作'
      );
    }
    return reply(
      '【BLFP 机器人命令】\n' +
      '/ping - 测试机器人状态\n' +
      '/list - 查看在线房间列表\n' +
      '/frp - 查看 frp 节点状态\n' +
      '/et - 查看 EasyTier 节点状态\n' +
      '/getclient - 获取客户端下载链接\n' +
      '/info - 查看自己绑定账号信息\n' +
      '/verify [验证码] - 绑定QQ或2FA验证\n' +
      '/help admin - 管理员命令列表'
    );
  }

  if (cmd === '/list') {
    const rooms = getLiveRooms();
    if (!rooms.length) return reply('当前没有在线房间。');
    const lines = rooms.map(r => `房间号：${r.code} | 模式：${r.mode} | 人数：${r.memberCount}`);
    return reply('【在线房间列表】\n' + lines.join('\n'));
  }

  if (cmd === '/getclient') {
    const s = await getAllSettings();
    const lines = [];
    if (s.download_url) lines.push('下载地址：' + s.download_url);
    if (s.source_url) lines.push('GitHub：' + s.source_url);
    if (!lines.length) return reply('暂无下载链接，请联系管理员配置。');
    return reply('【客户端下载】\n' + lines.join('\n'));
  }

  if (cmd === '/frp') {
    const nodes = await db.query('SELECT name, host, port, region, bandwidth, enabled FROM frp_nodes ORDER BY id ASC');
    if (!nodes.length) return reply('暂无 frp 节点。');
    const results = await Promise.all(nodes.map(async n => {
      if (!n.enabled) return `${escapeMsg(n.name)} [${escapeMsg(n.region || '?')}] - 已禁用`;
      const r = await testTcp(n.host, n.port || 7000);
      return `${escapeMsg(n.name)} [${escapeMsg(n.region || '?')}] - ${r.online ? `在线 ${r.latency}ms` : '离线'}`;
    }));
    return reply('【frp 节点状态】\n' + results.join('\n'));
  }

  if (cmd === '/et') {
    const nodes = await db.query('SELECT name, peer, enabled FROM easytier_nodes ORDER BY id ASC');
    if (!nodes.length) return reply('暂无 EasyTier 节点。');
    const lines = nodes.map(n => {
      let peerDisplay = escapeMsg(n.peer);
      try {
        const u = new URL(n.peer);
        peerDisplay = `${u.protocol}//*.*.*.*:${u.port}`;
      } catch {}
      return `${escapeMsg(n.name)}: ${peerDisplay} [${n.enabled ? '启用' : '禁用'}]`;
    });
    return reply('【EasyTier 节点】\n' + lines.join('\n'));
  }

  if (cmd === '/info') {
    if (!senderUser) return reply('你尚未绑定 BLFP 账号，请先通过 /verify [验证码] 完成绑定。');
    const roleNames = { user: '普通用户', sponsor: '赞助用户', admin: '管理员' };
    const banStatus = isActiveBan(senderUser)
      ? `已封禁${senderUser.ban_until ? '（到期：' + new Date(senderUser.ban_until * 1000).toLocaleDateString() + '）' : '（永久）'}`
      : '正常';
    return reply(
      '【账号信息】\n' +
      `用户名：${escapeMsg(senderUser.username)}\n` +
      `权限组：${roleNames[senderUser.role] || senderUser.role}\n` +
      `头衔：${escapeMsg(senderUser.title || '无')}\n` +
      `邮箱：${escapeMsg(senderUser.email || '未绑定')}\n` +
      `状态：${banStatus}\n` +
      `两步验证：${senderUser.tfa_enabled ? '已开启' : '未开启'}`
    );
  }

  if (cmd === '/verify') {
    const code = parts[1];
    if (!code) return reply('用法：/verify [验证码]');

    for (const [userId, item] of pendingQqVerify.entries()) {
      if (item.code === code && item.expires > Date.now()) {
        if (item.purpose === 'bind') {
          try {
            await db.execute('UPDATE users SET qq_id = ? WHERE id = ?', [String(senderQq), userId]);
            pendingQqVerify.delete(userId);
            return reply(`✅ QQ绑定成功！已绑定到账号 ID: ${userId}`);
          } catch (e) {
            if (e.code === 'ER_DUP_ENTRY') return reply('❌ 该QQ已绑定其他账号。');
            return reply('❌ 绑定失败，请重试。');
          }
        }
      }
    }

    const pendingTfaModule = require('./auth');
    for (const [tfaToken, item] of (pendingTfaModule.pendingTfa || new Map()).entries()) {
      if (item.userId) {
        const qqItem = pendingQqVerify.get(item.userId);
        if (qqItem && qqItem.code === code && qqItem.expires > Date.now() && String(senderQq) === String((await db.one('SELECT qq_id FROM users WHERE id = ?', [item.userId]))?.qq_id)) {
          pendingQqVerify.delete(item.userId);
          return reply(`✅ 验证成功，请在网页上完成登录。`);
        }
      }
    }

    return reply('❌ 验证码无效或已过期。');
  }

  const isAdmin = senderUser && senderUser.role === 'admin';

  if (cmd === '/user') {
    if (!isAdmin) return reply('❌ 该命令需要管理员权限。');
    const target = await getUserByQqOrUsername(parts[1]);
    if (!target) return reply('❌ 未找到该用户。');
    const roleNames = { user: '普通用户', sponsor: '赞助用户', admin: '管理员' };
    return reply(
      '【用户信息】\n' +
      `用户名：${escapeMsg(target.username)}\n` +
      `权限组：${roleNames[target.role] || target.role}\n` +
      `头衔：${escapeMsg(target.title || '无')}\n` +
      `邮箱：${escapeMsg(target.email || '未绑定')}\n` +
      `QQ：${escapeMsg(target.qq_id || '未绑定')}\n` +
      `状态：${isActiveBan(target) ? '封禁中' : '正常'}`
    );
  }

  if (cmd === '/ban') {
    if (!isAdmin) return reply('❌ 该命令需要管理员权限。');
    const days = parseInt(parts[1]);
    const targetRaw = parts[2];
    if (!days || days <= 0 || !targetRaw) return reply('用法：/ban [天数] [用户名/@xxx]');
    const target = await getUserByQqOrUsername(targetRaw);
    if (!target) return reply('❌ 未找到该用户。');
    if (target.role === 'admin') return reply('❌ 无法封禁管理员。');
    pendingConfirm.set(String(senderQq), {
      action: 'ban', targetId: target.id, targetName: target.username, days,
      expires: Date.now() + 60 * 1000,
    });
    return reply(`⚠️ 确认封禁 ${escapeMsg(target.username)} ${days} 天？发送 /confirm 确认。`);
  }

  if (cmd === '/unban') {
    if (!isAdmin) return reply('❌ 该命令需要管理员权限。');
    const targetRaw = parts[1];
    if (!targetRaw) return reply('用法：/unban [用户名/@xxx]');
    const target = await getUserByQqOrUsername(targetRaw);
    if (!target) return reply('❌ 未找到该用户。');
    pendingConfirm.set(String(senderQq), {
      action: 'unban', targetId: target.id, targetName: target.username,
      expires: Date.now() + 60 * 1000,
    });
    return reply(`⚠️ 确认解封 ${escapeMsg(target.username)}？发送 /confirm 确认。`);
  }

  if (cmd === '/close') {
    if (!isAdmin) return reply('❌ 该命令需要管理员权限。');
    const roomCode = parts[1];
    if (!roomCode) return reply('用法：/close [房间号]');
    pendingConfirm.set(String(senderQq), {
      action: 'close', roomCode,
      expires: Date.now() + 60 * 1000,
    });
    return reply(`⚠️ 确认关闭房间 ${escapeMsg(roomCode)}？发送 /confirm 确认。`);
  }

  if (cmd === '/set') {
    if (!isAdmin) return reply('❌ 该命令需要管理员权限。');
    const targetRaw = parts[1];
    const newRole = parts[2];
    if (!targetRaw || !newRole) return reply('用法：/set [用户名/@xxx] [user/sponsor/admin]');
    if (!['user', 'sponsor', 'admin'].includes(newRole)) return reply('❌ 权限组只能为 user、sponsor、admin。');
    const target = await getUserByQqOrUsername(targetRaw);
    if (!target) return reply('❌ 未找到该用户。');
    pendingConfirm.set(String(senderQq), {
      action: 'set', targetId: target.id, targetName: target.username, newRole,
      expires: Date.now() + 60 * 1000,
    });
    return reply(`⚠️ 确认将 ${escapeMsg(target.username)} 的权限组设为 ${newRole}？发送 /confirm 确认。`);
  }

  if (cmd === '/confirm') {
    if (!isAdmin) return reply('❌ 该命令需要管理员权限。');
    const item = pendingConfirm.get(String(senderQq));
    if (!item || item.expires < Date.now()) return reply('❌ 没有待确认的操作，或操作已超时。');
    pendingConfirm.delete(String(senderQq));

    if (item.action === 'ban') {
      const banUntil = nowSec() + item.days * 86400;
      await db.execute('UPDATE users SET banned = 1, ban_until = ? WHERE id = ?', [banUntil, item.targetId]);
      return reply(`✅ 已封禁 ${escapeMsg(item.targetName)} ${item.days} 天。`);
    }
    if (item.action === 'unban') {
      await db.execute('UPDATE users SET banned = 0, ban_until = NULL WHERE id = ?', [item.targetId]);
      return reply(`✅ 已解封 ${escapeMsg(item.targetName)}。`);
    }
    if (item.action === 'close') {
      const ok = await forceCloseRoom(item.roomCode, '管理员通过QQ机器人关闭了房间');
      return reply(ok ? `✅ 房间 ${escapeMsg(item.roomCode)} 已关闭。` : `❌ 房间 ${escapeMsg(item.roomCode)} 不存在或已关闭。`);
    }
    if (item.action === 'set') {
      await db.execute('UPDATE users SET role = ? WHERE id = ?', [item.newRole, item.targetId]);
      return reply(`✅ 已将 ${escapeMsg(item.targetName)} 的权限组设为 ${item.newRole}。`);
    }
    return reply('❌ 未知操作。');
  }

  return null;
}

// 浏览器访问上报地址时的友好提示（上报本身必须用 POST）
router.get('/webhook', (req, res) => {
  res.json({
    ok: true,
    message: '此地址为 OneBot HTTP 上报接收端，仅接受机器人框架的 POST 请求。请将此 URL 填入 NapCat 的 HTTP 上报地址。',
  });
});

// OneBot HTTP 上报 webhook
router.post('/webhook', async (req, res) => {
  const secret = getWebhookSecret();
  if (secret) {
    const provided = req.headers['x-onebot-secret'] || '';
    const actual = Buffer.from(String(provided));
    const expected = Buffer.from(secret);
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
      return res.status(401).json({ error: '签名无效' });
    }
  }

  res.json({ ok: true });

  const enabled = await isOnebotEnabled();
  if (!enabled) return;

  const body = req.body || {};
  if (body.post_type !== 'message') return;

  const rawText = typeof body.raw_message === 'string' ? body.raw_message.trim() : '';
  if (!rawText.startsWith('/')) return;

  const senderQq = String(body.user_id || '');
  const groupId = body.message_type === 'group' ? String(body.group_id || '') : null;

  if (!senderQq) return;

  handleCommand(senderQq, rawText, groupId).catch(() => {});
});

// QQ 配置查询（管理员）
router.get('/config', authMiddleware, adminOnly, async (req, res) => {
  const s = await getAllSettings();
  res.json({
    enabled: s.onebot_enabled === '1',
    webhookUrl: s.onebot_webhook_url || '',
    accessTokenConfigured: !!s.onebot_access_token,
    webhookSecretConfigured: !!getWebhookSecret(),
  });
});

module.exports = router;
