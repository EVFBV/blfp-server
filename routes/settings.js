const router = require('express').Router();
const { authMiddleware, adminOnly, adminOrDev } = require('../middleware/auth');
const { getAllSettings, setSetting, verifyTransport } = require('../mailer');

// 敏感字段（不回传明文，仅标记是否已设置）
const SECRET_KEYS = ['smtp_pass', 'onebot_access_token'];

// 公开设置（首页/客户端用，无需鉴权）
router.get('/public', async (req, res) => {
  const all = await getAllSettings();
  res.json({
    site_title: all.site_title || 'BLFP 联机',
    site_desc: all.site_desc || '',
    download_url: all.download_url || '',
    downloads: { win: all.download_url || '', linux: all.download_url_linux || '', macos: all.download_url_macos || '' },
    latest_version: all.latest_version || '1.0.0',
    release_notes: all.release_notes || '',
    force_update: all.force_update === '1',
    source_url: all.source_url || '',
    announcement: { title: all.announcement_title || '', content: all.announcement_content || '', enabled: all.announcement_enabled === '1', forceSeconds: Number(all.announcement_force_seconds) || 0, version: all.announcement_version || '1', updatedAt: all.announcement_updated_at || '' },
    client_theme: all.client_theme || 'dark',
    client_accent: all.client_accent || '',
  });
});

router.get('/announcement', async (req, res) => {
  const all = await getAllSettings();
  res.json({ title: all.announcement_title || '', content: all.announcement_content || '', enabled: all.announcement_enabled === '1', forceSeconds: Number(all.announcement_force_seconds) || 0, version: all.announcement_version || '1', updatedAt: all.announcement_updated_at || '' });
});

// 管理员：读取全部设置（脱敏）
router.get('/', authMiddleware, adminOnly, async (req, res) => {
  const all = await getAllSettings();
  const out = {};
  for (const [k, v] of Object.entries(all)) {
    if (SECRET_KEYS.includes(k)) out[k] = v ? '******' : '';
    else out[k] = v;
  }
  res.json(out);
});

// 管理员：保存设置
router.put('/', authMiddleware, adminOnly, async (req, res) => {
  const allowed = [
    'smtp_host', 'smtp_port', 'smtp_secure', 'smtp_user', 'smtp_pass', 'smtp_from',
    'download_url', 'download_url_linux', 'download_url_macos', 'site_title', 'site_desc',
    'latest_version', 'release_notes', 'force_update', 'source_url',
    'announcement_title', 'announcement_content', 'announcement_enabled',
    'announcement_force_seconds', 'announcement_version', 'announcement_updated_at',
    'client_theme', 'client_accent', 'onebot_enabled', 'onebot_webhook_url',
    'onebot_access_token',
  ];
  for (const key of allowed) {
    if (!(key in req.body)) continue;
    let val = req.body[key];
    // 密码字段为脱敏占位符时跳过（表示未修改）
    if (SECRET_KEYS.includes(key) && val === '******') continue;
    await setSetting(key, val);
  }
  res.json({ ok: true });
});

// 发布公告（admin/dev）—— 同时广播到信令服务器（聊天室）
router.post('/announcement', authMiddleware, adminOrDev, async (req, res) => {
  const title = String(req.body.title || '').trim().slice(0, 100);
  const content = String(req.body.content || '').trim().slice(0, 2000);
  if (!title || !content) return res.status(400).json({ error: '公告标题和内容不能为空' });
  await setSetting('announcement_title', title);
  await setSetting('announcement_content', content);
  await setSetting('announcement_enabled', '1');
  await setSetting('announcement_version', String(Date.now()));
  await setSetting('announcement_updated_at', new Date().toISOString());
  let delivered = 0;
  try {
    const { broadcastAnnouncement } = require('../signaling');
    delivered = broadcastAnnouncement(title, content);
  } catch (e) { /* 信令未初始化时忽略 */ }
  res.json({ ok: true, delivered });
});

// 管理员：测试 SMTP 连接
router.post('/test-smtp', authMiddleware, adminOnly, async (req, res) => {
  try {
    await verifyTransport();
    res.json({ ok: true, message: 'SMTP 连接成功' });
  } catch (e) {
    console.error('[SMTP] 测试失败:', e && (e.stack || e.message));
    res.status(500).json({ error: 'SMTP 连接失败，请检查主机 / 端口 / 账号配置，详情见服务器日志' });
  }
});

module.exports = router;
