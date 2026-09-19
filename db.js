const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CONFIG_PATH = process.env.CONFIG_PATH || path.join(__dirname, 'config.json');
const defaultSettings = {
  smtp_host: '', smtp_port: '465', smtp_secure: '1', smtp_user: '', smtp_pass: '', smtp_from: '',
  download_url: '', download_url_linux: '', download_url_macos: '', latest_version: '1.0.0', release_notes: '', force_update: '0', source_url: '',
  announcement_title: '', announcement_content: '', announcement_enabled: '0', announcement_force_seconds: '0',
  announcement_version: '1', announcement_updated_at: '', client_theme: 'dark', client_accent: '',
  onebot_enabled: '0', onebot_webhook_url: '', site_title: 'BLFP 联机',
  site_desc: 'BLFP 是一款我的世界 Java 版联机工具。EasyTier 自动尝试 P2P 直连，受限网络自动经已配置的共享节点中继，无需公网 IP。',
};

function readConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function hasDatabaseConfig() {
  const mysqlConfig = readConfig().mysql;
  const hasEnvironmentConfig = Boolean(process.env.MYSQL_HOST && process.env.MYSQL_USER && process.env.MYSQL_DATABASE);
  const hasFileConfig = Boolean(mysqlConfig && mysqlConfig.host && mysqlConfig.user && mysqlConfig.database);
  return hasEnvironmentConfig || hasFileConfig;
}

function getConfig() {
  const file = readConfig();
  const mysqlConfig = file.mysql || {};
  return {
    host: process.env.MYSQL_HOST || mysqlConfig.host || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || mysqlConfig.port || 3306),
    user: process.env.MYSQL_USER || mysqlConfig.user || 'root',
    password: process.env.MYSQL_PASSWORD ?? mysqlConfig.password ?? '',
    database: process.env.MYSQL_DATABASE || mysqlConfig.database || 'mclink',
    waitForConnections: true,
    connectionLimit: Number(process.env.MYSQL_CONNECTION_LIMIT || mysqlConfig.connectionLimit || 10),
    queueLimit: 0,
    timezone: 'Z',
  };
}

// 非生产环境兜底密钥：进程内随机生成，不再使用源码中的固定字符串
let devJwtSecret = null;

function getJwtSecret() {
  const secret = process.env.JWT_SECRET || readConfig().jwtSecret;
  if (secret) return secret;
  if (process.env.NODE_ENV === 'production') throw new Error('生产环境必须设置 JWT_SECRET 或完成系统初始化');
  if (!devJwtSecret) devJwtSecret = crypto.randomBytes(32).toString('base64url');
  return devJwtSecret;
}

function poolConfig() {
  return normalizeMySQLConfig(getConfig());
}

let pool = hasDatabaseConfig() ? mysql.createPool(poolConfig()) : null;
let ready = false;
let installed = false;
let schemaInitPromise = null;

function isReady() {
  return ready;
}

function setReady(value) {
  ready = Boolean(value);
}

function isInstalled() {
  return installed;
}

function setInstalled(value) {
  installed = Boolean(value);
}

const schema = [
  `CREATE TABLE IF NOT EXISTS users (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, username VARCHAR(64) NOT NULL, password VARCHAR(255) NOT NULL, role VARCHAR(20) NOT NULL DEFAULT 'user', email VARCHAR(255), banned TINYINT(1) NOT NULL DEFAULT 0, title VARCHAR(80) NOT NULL DEFAULT '', theme VARCHAR(20) NOT NULL DEFAULT 'dark', last_seen_at BIGINT, qq_id VARCHAR(128), created_at BIGINT NOT NULL, PRIMARY KEY (id), UNIQUE KEY uq_users_username (username), UNIQUE KEY uq_users_qq_id (qq_id)) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS frp_nodes (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, name VARCHAR(128) NOT NULL, host VARCHAR(255) NOT NULL, port INT NOT NULL DEFAULT 7000, token VARCHAR(512), region VARCHAR(64) DEFAULT '未知', bandwidth VARCHAR(64) DEFAULT '未知', enabled TINYINT(1) NOT NULL DEFAULT 1, tls_enabled TINYINT(1) NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS easytier_nodes (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, name VARCHAR(128) NOT NULL, peer VARCHAR(512) NOT NULL, enabled TINYINT(1) NOT NULL DEFAULT 1, created_at BIGINT NOT NULL, PRIMARY KEY (id), UNIQUE KEY uq_easytier_nodes_peer (peer)) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS frp_sessions (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, user_id BIGINT UNSIGNED NOT NULL, username VARCHAR(64) NOT NULL DEFAULT '', room_code VARCHAR(16) DEFAULT NULL, node_id BIGINT UNSIGNED DEFAULT NULL, tunnel_name VARCHAR(64) NOT NULL, remote_port INT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (id), KEY idx_frp_user (user_id), KEY idx_frp_tunnel (tunnel_name)) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS rooms (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, room_code VARCHAR(64) NOT NULL, host_id BIGINT UNSIGNED, mode VARCHAR(20) NOT NULL DEFAULT 'p2p', frp_node_id BIGINT UNSIGNED, mc_port INT NOT NULL DEFAULT 25565, is_public TINYINT(1) NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, PRIMARY KEY (id), UNIQUE KEY uq_rooms_code (room_code), CONSTRAINT fk_rooms_node FOREIGN KEY (frp_node_id) REFERENCES frp_nodes(id) ON DELETE SET NULL) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS friendships (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, user_id BIGINT UNSIGNED NOT NULL, friend_id BIGINT UNSIGNED NOT NULL, status VARCHAR(20) NOT NULL DEFAULT 'accepted', created_at BIGINT NOT NULL, PRIMARY KEY (id), UNIQUE KEY uq_friendship (user_id, friend_id), CONSTRAINT fk_friend_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, CONSTRAINT fk_friend_friend FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS settings (setting_key VARCHAR(128) NOT NULL, value TEXT, PRIMARY KEY (setting_key)) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS email_codes (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, email VARCHAR(255) NOT NULL, code VARCHAR(32) NOT NULL, purpose VARCHAR(32) NOT NULL DEFAULT 'register', expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY (id), KEY idx_email_codes_lookup (email, purpose, id)) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS install_state (id TINYINT UNSIGNED NOT NULL, installed TINYINT(1) NOT NULL DEFAULT 0, jwt_secret VARCHAR(255), installed_at BIGINT, PRIMARY KEY (id)) ENGINE=InnoDB`,
];

async function configureMySQL(config) {
  const nextConfig = normalizeMySQLConfig(config);
  const nextPool = mysql.createPool(nextConfig);
  const previousPool = pool;
  const previousReady = ready;
  const previousInstalled = installed;
  try {
    const connection = await nextPool.getConnection();
    connection.release();
    pool = nextPool;
    await initSchema();
    if (previousPool) await previousPool.end();
    return nextConfig;
  } catch (error) {
    ready = previousReady;
    installed = previousInstalled;
    pool = previousPool;
    await nextPool.end();
    throw error;
  }
}

function normalizeMySQLConfig(config = {}) {
  const host = String(config.host || '').trim();
  const user = String(config.user || '').trim();
  const database = String(config.database || '').trim();
  const port = Number(config.port || 3306);
  const connectionLimit = Number(config.connectionLimit || 10);
  if (!host || !user || !database || !Number.isInteger(port) || port < 1 || port > 65535 || !Number.isInteger(connectionLimit) || connectionLimit < 1) {
    throw new Error('MySQL 配置无效');
  }
  if (user.toLowerCase() === 'root' && !['localhost', '127.0.0.1', '::1'].includes(host.toLowerCase())) {
    throw new Error('禁止使用 root 账号连接远程 MySQL，请使用专用数据库账号');
  }
  return { host, port, user, password: String(config.password ?? ''), database, waitForConnections: true, connectionLimit, queueLimit: 0, timezone: 'Z' };
}

async function initSchema() {
  if (!pool) throw new Error('数据库尚未配置');
  if (schemaInitPromise) return schemaInitPromise;
  schemaInitPromise = (async () => {
    ready = false;
    for (const statement of schema) await pool.query(statement);
    await migrateSchema();
    await pool.query('INSERT IGNORE INTO install_state (id, installed) VALUES (1, 0)');
    const [installRows] = await pool.query('SELECT installed FROM install_state WHERE id = 1');
    installed = Boolean(installRows[0]?.installed);
    for (const [key, value] of Object.entries(defaultSettings)) {
      await pool.query('INSERT IGNORE INTO settings (setting_key, value) VALUES (?, ?)', [key, value]);
    }
    ready = true;
  })();
  try {
    await schemaInitPromise;
  } finally {
    schemaInitPromise = null;
  }
}

async function migrateSchema() {
  const migrations = [
    ['users', 'email', 'ALTER TABLE users ADD COLUMN email VARCHAR(255) NULL'],
    ['users', 'banned', 'ALTER TABLE users ADD COLUMN banned TINYINT(1) NOT NULL DEFAULT 0'],
    ['users', 'title', "ALTER TABLE users ADD COLUMN title VARCHAR(80) NOT NULL DEFAULT ''"],
    ['users', 'theme', "ALTER TABLE users ADD COLUMN theme VARCHAR(20) NOT NULL DEFAULT 'dark'"],
    ['users', 'last_seen_at', 'ALTER TABLE users ADD COLUMN last_seen_at BIGINT NULL'],
    ['users', 'qq_id', 'ALTER TABLE users ADD COLUMN qq_id VARCHAR(128) NULL'],
    ['users', 'ban_until', 'ALTER TABLE users ADD COLUMN ban_until BIGINT NULL'],
    ['users', 'tfa_enabled', 'ALTER TABLE users ADD COLUMN tfa_enabled TINYINT(1) NOT NULL DEFAULT 0'],
    ['frp_nodes', 'tls_enabled', 'ALTER TABLE frp_nodes ADD COLUMN tls_enabled TINYINT(1) NOT NULL DEFAULT 0'],
    ['rooms', 'is_public', 'ALTER TABLE rooms ADD COLUMN is_public TINYINT(1) NOT NULL DEFAULT 0'],
    ['easytier_nodes', 'kind', "ALTER TABLE easytier_nodes ADD COLUMN kind VARCHAR(16) NOT NULL DEFAULT 'relay'"],
  ];
  for (const [table, column, statement] of migrations) {
    const [rows] = await pool.query('SELECT COUNT(*) AS count FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?', [table, column]);
    if (!Number(rows[0].count)) await pool.query(statement);
  }
  const [settingsColumns] = await pool.query('SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = \'settings\'');
  const columnNames = new Set(settingsColumns.map((row) => row.COLUMN_NAME || row.column_name));
  if (columnNames.has('key') && !columnNames.has('setting_key')) {
    await pool.query('ALTER TABLE settings CHANGE COLUMN `key` setting_key VARCHAR(128) NOT NULL');
  } else if (columnNames.has('key') && columnNames.has('setting_key')) {
    await pool.query('INSERT IGNORE INTO settings (setting_key, value) SELECT `key`, value FROM settings WHERE `key` IS NOT NULL');
    await pool.query('ALTER TABLE settings DROP COLUMN `key`');
  }
  const [indexes] = await pool.query('SELECT DISTINCT index_name FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = \'settings\' AND index_name <> \'PRIMARY\'');
  for (const index of indexes) {
    if (index.index_name === 'uq_settings_key') await pool.query('ALTER TABLE settings DROP INDEX uq_settings_key');
  }
  const [settingKeyIndex] = await pool.query('SELECT COUNT(*) AS count FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = \'settings\' AND index_name = \'PRIMARY\' AND column_name = \'setting_key\'');
  if (!Number(settingKeyIndex[0].count)) await pool.query('ALTER TABLE settings ADD PRIMARY KEY (setting_key)');
}

async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

async function one(sql, params = []) {
  const rows = await query(sql, params);
  return rows[0] || null;
}

async function execute(sql, params = []) {
  const [result] = await pool.execute(sql, params);
  return result;
}

async function transaction(callback) {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const tx = {
      query: async (sql, params = []) => (await connection.execute(sql, params))[0],
      one: async (sql, params = []) => {
        const rows = (await connection.execute(sql, params))[0];
        return rows[0] || null;
      },
      execute: async (sql, params = []) => (await connection.execute(sql, params))[0],
    };
    const result = await callback(tx);
    await connection.commit();
    return result;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

function getPool() {
  return pool;
}

module.exports = { get pool() { return pool; }, query, one, execute, transaction, initSchema, configureMySQL, getConfig, getJwtSecret, getPool, hasDatabaseConfig, isReady, setReady, isInstalled, setInstalled, defaultSettings, CONFIG_PATH };
