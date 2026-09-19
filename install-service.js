const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const db = require('./db');
const { validatePeers } = require('./easytier-peer');

function generateSecret() {
  return crypto.randomBytes(48).toString('base64url');
}

function validateInput(input) {
  const username = String(input.username || '').trim();
  const password = String(input.password || '');
  const mysqlConfig = input.mysql && typeof input.mysql === 'object' ? input.mysql : null;
  const easytierPeers = validatePeers(input.easytierPeers);
  if (username.length < 3 || username.length > 20) throw new Error('用户名长度必须为 3-20 位');
  if (password.length < 12) throw new Error('密码长度必须至少为 12 位');
  if (!mysqlConfig) throw new Error('请提供 MySQL 配置');
  if (!easytierPeers) throw new Error('至少需要 1 个唯一且合法的 EasyTier peer，支持 tcp/udp/ws/wss://host:port');
  return { username, password, email: input.email ? String(input.email).trim().toLowerCase() : null, mysqlConfig, easytierPeers };
}

function writeJsonAtomic(filePath, value) {
  const directory = path.dirname(filePath);
  const temporary = `${filePath}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  fs.chmodSync(temporary, 0o600);
  fs.renameSync(temporary, filePath);
  fs.chmodSync(filePath, 0o600);
}

async function getInstallState() {
  if (!db.hasDatabaseConfig()) return { installed: false, installedAt: null };
  if (!db.isReady()) await db.initSchema();
  const state = await db.one('SELECT installed, installed_at FROM install_state WHERE id = 1');
  return { installed: Boolean(state?.installed), installedAt: state?.installed_at || null };
}

let initializePromise = null;

async function initialize(input) {
  if (initializePromise) return initializePromise;
  initializePromise = initializeOnce(input);
  try {
    return await initializePromise;
  } finally {
    initializePromise = null;
  }
}

async function initializeOnce(input) {
  const account = validateInput(input);
  const wasReady = db.isReady();
  const wasInstalled = db.isInstalled();
  const config = await db.configureMySQL(account.mysqlConfig);
  db.setReady(false);
  db.setInstalled(false);
  const secret = generateSecret();
  const persistedConfig = { mysql: { host: config.host, port: config.port, user: config.user, password: config.password, database: config.database, connectionLimit: config.connectionLimit }, jwtSecret: secret };
  try {
    await db.transaction(async (tx) => {
      const state = await tx.one('SELECT installed FROM install_state WHERE id = 1 FOR UPDATE');
      if (state?.installed) throw new Error('系统已完成初始化');
      const existing = await tx.one('SELECT id FROM users WHERE role = ? LIMIT 1 FOR UPDATE', ['admin']);
      if (existing) throw new Error('管理员账号已存在');
      await tx.execute('INSERT INTO users (username, password, role, email, created_at) VALUES (?, ?, ?, ?, UNIX_TIMESTAMP())', [account.username, bcrypt.hashSync(account.password, 10), 'admin', account.email]);
      if (account.easytierPeers.length) {
        await tx.execute('INSERT INTO easytier_nodes (name, peer, enabled, created_at) VALUES (?, ?, 1, UNIX_TIMESTAMP())', ['安装初始化节点', account.easytierPeers[0]]);
        for (const peer of account.easytierPeers.slice(1)) await tx.execute('INSERT IGNORE INTO easytier_nodes (name, peer, enabled, created_at) VALUES (?, ?, 1, UNIX_TIMESTAMP())', ['安装初始化节点', peer]);
      }
      writeJsonAtomic(db.CONFIG_PATH, persistedConfig);
      await tx.execute('UPDATE install_state SET installed = 1, jwt_secret = ?, installed_at = UNIX_TIMESTAMP() WHERE id = 1', [secret]);
    });
  } catch (error) {
    db.setReady(wasReady);
    db.setInstalled(wasInstalled);
    throw error;
  }
  db.setReady(true);
  db.setInstalled(true);
  return { installed: true, jwtSecret: secret };
}

let upgradePromise = null;

async function upgrade(input) {
  if (upgradePromise) return upgradePromise;
  upgradePromise = upgradeOnce(input);
  try {
    return await upgradePromise;
  } finally {
    upgradePromise = null;
  }
}

async function upgradeOnce(input) {
  const mysqlConfig = input && typeof input.mysql === 'object' ? input.mysql : null;
  if (!mysqlConfig) throw new Error('请提供 MySQL 配置');

  const config = await db.configureMySQL(mysqlConfig);

  const state = await db.one('SELECT installed, jwt_secret FROM install_state WHERE id = 1');
  if (!state || !state.installed) throw new Error('该数据库尚未完成初始化，请使用全新安装模式');

  const jwtSecret = state.jwt_secret;
  if (!jwtSecret) throw new Error('数据库中未找到 JWT 密钥，无法完成更新，请联系管理员');

  const persistedConfig = {
    mysql: {
      host: config.host,
      port: config.port,
      user: config.user,
      password: config.password,
      database: config.database,
      connectionLimit: config.connectionLimit,
    },
    jwtSecret,
  };

  writeJsonAtomic(db.CONFIG_PATH, persistedConfig);
  db.setReady(true);
  db.setInstalled(true);

  return { upgraded: true };
}

module.exports = { generateSecret, getInstallState, initialize, writeJsonAtomic, upgrade };
