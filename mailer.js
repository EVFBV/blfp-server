const nodemailer = require('nodemailer');
const db = require('./db');

async function getSetting(key, fallback = '') {
  const row = await db.one('SELECT value FROM settings WHERE setting_key = ?', [key]);
  return row ? row.value : fallback;
}

async function getAllSettings() {
  const rows = await db.query('SELECT setting_key, value FROM settings');
  const obj = {};
  for (const r of rows) obj[r.setting_key] = r.value;
  return obj;
}

async function setSetting(key, value) {
  await db.execute('INSERT INTO settings (setting_key, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)', [key, String(value ?? '')]);
}

async function buildTransport() {
  const host = await getSetting('smtp_host');
  const user = await getSetting('smtp_user');
  const pass = await getSetting('smtp_pass');
  if (!host || !user || !pass) throw new Error('SMTP 未配置，请先在后台完成邮件服务设置');
  return nodemailer.createTransport({ host, port: parseInt(await getSetting('smtp_port', '465')), secure: (await getSetting('smtp_secure', '1')) === '1', auth: { user, pass } });
}

async function sendCodeMail(to, code) {
  const transport = await buildTransport();
  const from = await getSetting('smtp_from') || await getSetting('smtp_user');
  const title = await getSetting('site_title', 'BLFP 联机');
  await transport.sendMail({
    from: `"${title}" <${from}>`,
    to,
    subject: `${title} - 邮箱验证码`,
    html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px;background:#f7f8fa;border-radius:12px"><h2 style="color:#3b6fe0;margin:0 0 16px">${title}</h2><p style="color:#333;font-size:15px">你的验证码是：</p><div style="font-size:32px;font-weight:700;letter-spacing:8px;color:#3b6fe0;background:#fff;padding:16px;text-align:center;border-radius:8px;margin:12px 0">${code}</div><p style="color:#888;font-size:13px">验证码 10 分钟内有效，请勿泄露给他人。若非本人操作请忽略此邮件。</p></div>`,
  });
}

async function verifyTransport() {
  const transport = await buildTransport();
  await transport.verify();
  return true;
}

module.exports = { getSetting, getAllSettings, setSetting, sendCodeMail, verifyTransport };
