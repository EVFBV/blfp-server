// ============ BLFP Web 前端逻辑 ============
let TOKEN = localStorage.getItem('mclink_token') || null;
let ME = null;
let signingKeyCache = { token: null, key: null };

async function sha256Hex(value) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('');
}

async function getSigningKey() {
  if (signingKeyCache.token === TOKEN && signingKeyCache.key) return signingKeyCache.key;
  const res = await fetch('/api/auth/signing-key', {
    headers: { Authorization: 'Bearer ' + TOKEN },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.key) throw new Error(data.error || '获取签名密钥失败');
  signingKeyCache = { token: TOKEN, key: data.key };
  return data.key;
}

// ---------- 通用请求封装 ----------
async function api(path, opts = {}) {
  opts.headers = opts.headers || {};
  opts.headers['Content-Type'] = 'application/json';
  if (TOKEN) opts.headers['Authorization'] = 'Bearer ' + TOKEN;
  if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);

  const method = (opts.method || 'GET').toUpperCase();
  if (TOKEN && method !== 'GET' && method !== 'HEAD') {
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyHash = await sha256Hex(opts.body || '{}');
    const keyHex = await getSigningKey();
    const keyBytes = new Uint8Array(keyHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const payload = [method, '/api' + path.split('?')[0], timestamp, nonce, bodyHash].join('\n');
    const signatureBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
    opts.headers['X-Timestamp'] = timestamp;
    opts.headers['X-Nonce'] = nonce;
    opts.headers['X-Signature'] = Array.from(new Uint8Array(signatureBuffer), byte => byte.toString(16).padStart(2, '0')).join('');
  }

  const res = await fetch('/api' + path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || '请求失败');
  return data;
}

// ---------- Toast ----------
function toast(msg, type = 'success') {
  const wrap = document.getElementById('toast-wrap');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

function titleThemeClass(theme, role) {
  if (theme === 'role' || !theme) return `theme-role role-${role || 'user'}`;
  const map = { violet: 'purple', emerald: 'green' };
  const t = map[theme] || theme;
  return `theme-${t} role-${role || 'user'}`;
}

// ---------- 防抖 ----------
let debounceTimers = {};
function debounce(fn, delay) {
  return function (...args) {
    const key = fn.name;
    clearTimeout(debounceTimers[key]);
    debounceTimers[key] = setTimeout(() => fn.apply(this, args), delay);
  };
}

// ---------- 登录/注册切换 ----------
function showAuthTab(tab) {
  document.getElementById('tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('tab-reg').classList.toggle('active', tab === 'reg');
  document.getElementById('form-login').classList.toggle('hidden', tab !== 'login');
  document.getElementById('form-reg').classList.toggle('hidden', tab !== 'reg');
}

// 登录方式切换（密码 / 验证码）
let loginMethod = 'pass';
function switchLoginMethod(m) {
  loginMethod = m;
  document.getElementById('lm-pass').classList.toggle('active', m === 'pass');
  document.getElementById('lm-code').classList.toggle('active', m === 'code');
  document.getElementById('login-by-pass').classList.toggle('hidden', m !== 'pass');
  document.getElementById('login-by-code').classList.toggle('hidden', m !== 'code');
}

// 发送邮箱验证码（scene: 'register' | 'login'）
const codeCooldown = {};
async function sendCode(scene) {
  const btnId = scene === 'login' ? 'l-send-code' : 'r-send-code';
  const emailId = scene === 'login' ? 'l-email' : 'r-email';
  const email = document.getElementById(emailId).value.trim();
  if (!email) return toast('请先填写邮箱', 'error');
  const btn = document.getElementById(btnId);
  if (btn.disabled) return;
  try {
    await api('/auth/send-code', { method: 'POST', body: { email, purpose: scene } });
    toast('验证码已发送，请查收邮件');
    let left = 60;
    btn.disabled = true;
    const orig = '获取验证码';
    btn.textContent = left + 's';
    codeCooldown[btnId] = setInterval(() => {
      left--;
      if (left <= 0) {
        clearInterval(codeCooldown[btnId]);
        btn.disabled = false;
        btn.textContent = orig;
      } else {
        btn.textContent = left + 's';
      }
    }, 1000);
  } catch (e) { toast(e.message, 'error'); }
}

let tfaSession = null;

async function doLogin() {
  let body;
  if (loginMethod === 'code') {
    const email = document.getElementById('l-email').value.trim();
    const code = document.getElementById('l-code').value.trim();
    if (!email || !code) return toast('请输入邮箱和验证码', 'error');
    body = { email, code };
  } else {
    const username = document.getElementById('l-user').value.trim();
    const password = document.getElementById('l-pass').value;
    if (!username || !password) return toast('请输入账号和密码', 'error');
    body = { username, password };
  }
  try {
    const data = await api('/auth/login', { method: 'POST', body });
    if (data.tfa_required) {
      tfaSession = { tfaToken: data.tfa_token, methods: data.tfa_methods || {} };
      document.getElementById('form-login').classList.add('hidden');
      document.getElementById('form-reg').classList.add('hidden');
      document.getElementById('form-2fa').classList.remove('hidden');
      document.getElementById('tab-login').parentElement.classList.add('hidden');
      document.getElementById('tfa-btn-email').classList.toggle('hidden', !tfaSession.methods.email);
      document.getElementById('tfa-btn-qq').classList.toggle('hidden', !tfaSession.methods.qq);
      return;
    }
    TOKEN = data.token;
    localStorage.setItem('mclink_token', TOKEN);
    ME = data.user;
    enterApp();
  } catch (e) { toast(e.message, 'error'); }
}

async function requestTfaCode(method) {
  if (!tfaSession) return;
  try {
    await api('/auth/tfa/send', { method: 'POST', body: { tfa_token: tfaSession.tfaToken, method } });
    document.getElementById('tfa-method').value = method;
    toast('验证码已发送');
  } catch (e) { toast(e.message, 'error'); }
}

function showTfaQq() {
  document.getElementById('tfa-method').value = 'qq';
  toast('请在QQ机器人中发送 /verify [验证码]，再将验证码填入上方输入框', 'info');
}

async function submitTfa() {
  if (!tfaSession) return;
  const code = document.getElementById('tfa-code').value.trim();
  const method = document.getElementById('tfa-method').value;
  if (!code) return toast('请输入验证码', 'error');
  try {
    const data = await api('/auth/tfa/verify', { method: 'POST', body: { tfa_token: tfaSession.tfaToken, code, method } });
    tfaSession = null;
    TOKEN = data.token;
    localStorage.setItem('mclink_token', TOKEN);
    ME = data.user;
    cancelTfa(true);
    enterApp();
  } catch (e) { toast(e.message, 'error'); }
}

function cancelTfa(silent) {
  tfaSession = null;
  document.getElementById('form-2fa').classList.add('hidden');
  document.getElementById('tfa-code').value = '';
  document.getElementById('tab-login').parentElement.classList.remove('hidden');
  if (!silent) showAuthTab('login');
}

async function doRegister() {
  const username = document.getElementById('r-user').value.trim();
  const password = document.getElementById('r-pass').value;
  const email = document.getElementById('r-email').value.trim();
  const code = document.getElementById('r-code').value.trim();
  if (!username || !password) return toast('请填写用户名和密码', 'error');
  if (!email) return toast('请填写邮箱', 'error');
  if (!code) return toast('请填写邮箱验证码', 'error');
  try {
    await api('/auth/register', { method: 'POST', body: { username, password, email, code } });
    toast('注册成功，请登录');
    showAuthTab('login');
    switchLoginMethod('pass');
    document.getElementById('l-user').value = username;
  } catch (e) { toast(e.message, 'error'); }
}

// 退出登录：弹出二次确认框
function doLogout() {
  openModal('logout-modal');
}

// 用户确认后真正执行退出
function confirmLogout() {
  closeModal('logout-modal');
  TOKEN = null; ME = null;
  signingKeyCache = { token: null, key: null };
  localStorage.removeItem('mclink_token');
  document.getElementById('main-app').classList.add('hidden');
  document.getElementById('landing-page').classList.add('hidden');
  showAuth();
}

// ---------- 安装页 / 宣传页 / 登录页切换 ----------
function showSetup() {
  document.getElementById('landing-page').classList.add('hidden');
  document.getElementById('auth-page').classList.add('hidden');
  document.getElementById('main-app').classList.add('hidden');
  document.getElementById('setup-page').classList.remove('hidden');
}

async function checkInstallState() {
  try {
    const res = await fetch('/api/install/state');
    const state = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(state.error || '无法读取安装状态');
    return state;
  } catch (e) {
    toast(e.message, 'error');
    return null;
  }
}

async function submitSetup(event) {
  event.preventDefault();
  const password = document.getElementById('setup-password').value;
  const easytierPeers = document.getElementById('setup-easytier-peers').value.trim();
  if (password.length < 12) return toast('管理员密码至少需要 12 位', 'error');
  if (!easytierPeers) return toast('至少需要填写 1 个 EasyTier peer 地址', 'error');
  const submit = document.getElementById('setup-submit');
  submit.disabled = true;
  submit.textContent = '初始化中...';
  const body = {
    mysql: {
      host: document.getElementById('setup-mysql-host').value.trim(),
      port: Number(document.getElementById('setup-mysql-port').value),
      user: document.getElementById('setup-mysql-user').value.trim(),
      password: document.getElementById('setup-mysql-password').value,
      database: document.getElementById('setup-mysql-database').value.trim(),
      connectionLimit: Number(document.getElementById('setup-mysql-limit').value) || 10,
    },
    username: document.getElementById('setup-username').value.trim(),
    password,
    email: document.getElementById('setup-email').value.trim(),
    easytierPeers,
  };
  try {
    await fetch('/api/install', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(async res => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || '初始化失败');
      return data;
    });
    toast('初始化成功，请刷新页面进入登录');
    submit.textContent = '初始化成功，请刷新页面';
    submit.disabled = true;
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    if (submit.textContent === '初始化中...') {
      submit.disabled = false;
      submit.textContent = '完成初始化';
    }
  }
}

// ---------- 安装向导模式切换 ----------
function switchSetupMode(mode) {
  const isFresh = mode === 'fresh';
  document.getElementById('smode-fresh').className = isFresh ? 'btn btn-primary btn-sm' : 'btn btn-outline btn-sm';
  document.getElementById('smode-upgrade').className = isFresh ? 'btn btn-outline btn-sm' : 'btn btn-primary btn-sm';
  document.getElementById('setup-form').classList.toggle('hidden', !isFresh);
  document.getElementById('upgrade-form').classList.toggle('hidden', isFresh);
  document.getElementById('setup-title').textContent = isFresh ? '首次初始化' : '更新模式';
  document.getElementById('setup-subtitle').textContent = isFresh
    ? '完成服务端配置后，即可进入管理控制台'
    : '连接已有数据库，保留所有数据，仅补全新字段和配置项';
}

async function submitUpgrade(event) {
  event.preventDefault();
  const submit = document.getElementById('upgrade-submit');
  submit.disabled = true;
  submit.textContent = '更新中...';
  const body = {
    mysql: {
      host: document.getElementById('upg-mysql-host').value.trim(),
      port: Number(document.getElementById('upg-mysql-port').value),
      user: document.getElementById('upg-mysql-user').value.trim(),
      password: document.getElementById('upg-mysql-password').value,
      database: document.getElementById('upg-mysql-database').value.trim(),
      connectionLimit: Number(document.getElementById('upg-mysql-limit').value) || 10,
    },
  };
  try {
    const res = await fetch('/api/install/upgrade', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || '更新失败');
    submit.textContent = '更新成功，正在跳转...';
    toast('更新成功！数据库已连接，正在进入系统...');
    setTimeout(() => window.location.reload(), 1500);
  } catch (e) {
    toast(e.message, 'error');
    submit.disabled = false;
    submit.textContent = '执行更新';
  }
}

function showLanding() {
  document.getElementById('setup-page').classList.add('hidden');
  document.getElementById('auth-page').classList.add('hidden');
  document.getElementById('main-app').classList.add('hidden');
  document.getElementById('landing-page').classList.remove('hidden');
  loadLandingInfo();
}

// 从宣传页进入登录/注册页
function showAuth() {
  document.getElementById('setup-page').classList.add('hidden');
  document.getElementById('landing-page').classList.add('hidden');
  document.getElementById('auth-page').classList.remove('hidden');
}

// 拉取公开站点信息（标题、介绍、下载链接）填充宣传页
async function loadLandingInfo() {
  try {
    const pub = await api('/settings/public');
    if (pub.site_title) document.getElementById('landing-title').textContent = pub.site_title;
    if (pub.site_desc) document.getElementById('landing-desc').textContent = pub.site_desc;
    fillDownloadOverlay(pub);
  } catch {}
}

// ---------- 进入主应用 ----------
async function enterApp() {
  try {
    ME = await api('/auth/me');
  } catch {
    // token 失效：直接清理并返回宣传页（不弹确认框）
    TOKEN = null; ME = null;
    signingKeyCache = { token: null, key: null };
    localStorage.removeItem('mclink_token');
    document.getElementById('main-app').classList.add('hidden');
    return showAuth();
  }

  document.getElementById('landing-page').classList.add('hidden');
  document.getElementById('auth-page').classList.add('hidden');
  document.getElementById('main-app').classList.remove('hidden');

  const roleNames = { user: '普通用户', sponsor: '赞助用户', admin: '管理员' };
  const roleName = roleNames[ME.role] || '普通用户';
  document.getElementById('nav-username').textContent = ME.username;
  document.getElementById('welcome-text').textContent = `欢迎回来，${roleName} ${ME.username}`;
  const badge = document.getElementById('nav-badge');
  badge.textContent = roleName;
  badge.className = 'badge' + (ME.role === 'admin' ? ' admin' : ME.role === 'sponsor' ? ' sponsor' : '');

  // 用户中心信息
  document.getElementById('p-username').textContent = ME.username;
  document.getElementById('p-role').textContent = roleName;
  document.getElementById('p-email').textContent = ME.email || '未设置';
  document.getElementById('p-created').textContent = ME.created_at ? new Date(ME.created_at * 1000).toLocaleString() : '-';

  const tfaBtn = document.getElementById('btn-tfa-toggle');
  if (tfaBtn) {
    tfaBtn.textContent = ME.tfa_enabled ? '关闭两步验证' : '开启两步验证';
  }
  const qqStatus = document.getElementById('p-qq-status');
  if (qqStatus) qqStatus.textContent = ME.qq_id ? `已绑定：${ME.qq_id}` : '未绑定';

  document.getElementById('nav-admin').classList.toggle('hidden', ME.role !== 'admin');

  loadDashboardStats();
}

// ---------- 页面导航 ----------
function navTo(page, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
  if (el) el.classList.add('active');

  if (page === 'admin') adminTab('overview');
  if (page === 'square') loadSquare();
  if (page === 'friends') { loadSrvFriends(); loadSrvFriendRequests(); }
}

// ---------- Dashboard 统计 ----------
async function loadDashboardStats() {
  try {
    const s = await api('/stats');
    document.getElementById('stat-rooms').textContent = s.liveRooms;
    document.getElementById('stat-users').textContent = s.users;
    document.getElementById('stat-nodes').textContent = s.easytierNodes;
  } catch {}
}

// ---------- 修改密码 ----------
async function doChangePassword() {
  const oldPassword = document.getElementById('cp-old').value;
  const newPassword = document.getElementById('cp-new').value;
  const confirm = document.getElementById('cp-confirm').value;
  if (!oldPassword || !newPassword) return toast('请填写完整', 'error');
  if (newPassword !== confirm) return toast('两次密码不一致', 'error');
  try {
    await api('/auth/change-password', { method: 'POST', body: { oldPassword, newPassword } });
    toast('密码修改成功');
    document.getElementById('cp-old').value = '';
    document.getElementById('cp-new').value = '';
    document.getElementById('cp-confirm').value = '';
  } catch (e) { toast(e.message, 'error'); }
}

async function toggleTfa() {
  if (!ME) return;
  const enable = !ME.tfa_enabled;
  if (enable && !ME.email && !ME.qq_id) return toast('请先绑定邮箱或QQ，再开启两步验证', 'error');
  try {
    const data = await api('/auth/tfa/toggle', { method: 'POST', body: { enable } });
    ME.tfa_enabled = data.tfa_enabled;
    document.getElementById('btn-tfa-toggle').textContent = data.tfa_enabled ? '关闭两步验证' : '开启两步验证';
    toast(data.tfa_enabled ? '两步验证已开启' : '两步验证已关闭');
  } catch (e) { toast(e.message, 'error'); }
}

async function requestQqBind() {
  try {
    const data = await api('/auth/qq/bind/request', { method: 'POST', body: {} });
    document.getElementById('qq-bind-code-text').textContent = `/verify ${data.code}`;
    document.getElementById('qq-bind-code-box').classList.remove('hidden');
    toast('验证码已生成，10分钟内有效');
  } catch (e) { toast(e.message, 'error'); }
}

// ============ 管理后台 ============
function adminTab(tab) {
  ['overview', 'users', 'nodes', 'easytier-nodes', 'rooms', 'settings', 'qq-bot'].forEach(t => {
    document.getElementById('at-' + t).classList.toggle('hidden', t !== tab);
  });
  if (tab === 'overview') loadAdminOverview();
  if (tab === 'users') loadAdminUsers();
  if (tab === 'nodes') loadNodes();
  if (tab === 'easytier-nodes') loadEasyTierNodes();
  if (tab === 'rooms') { loadLiveRooms(); loadFrpSessions(); }
  if (tab === 'settings') loadSettings();
  if (tab === 'qq-bot') loadQqBotConfig();
}

// ---------- 系统设置 ----------
async function loadSettings() {
  try {
    const s = await api('/settings');
    document.getElementById('set-site-title').value = s.site_title || '';
    document.getElementById('set-site-desc').value = s.site_desc || '';
    document.getElementById('set-download-url').value = s.download_url || '';
    document.getElementById('set-download-url-linux').value = s.download_url_linux || '';
    document.getElementById('set-download-url-macos').value = s.download_url_macos || '';
    document.getElementById('set-latest-version').value = s.latest_version || '1.0.0';
    document.getElementById('set-source-url').value = s.source_url || '';
    document.getElementById('set-release-notes').value = s.release_notes || '';
    document.getElementById('set-force-update').checked = s.force_update === '1' || s.force_update === true;
    document.getElementById('set-ann-title').value = s.announcement_title || '';
    document.getElementById('set-ann-seconds').value = s.announcement_force_seconds || 0;
    document.getElementById('set-ann-version').value = s.announcement_version || '1';
    document.getElementById('set-ann-content').value = s.announcement_content || '';
    document.getElementById('set-ann-enabled').checked = s.announcement_enabled === '1';
    document.getElementById('set-client-theme').value = s.client_theme || 'dark';
    document.getElementById('set-smtp-host').value = s.smtp_host || '';
    document.getElementById('set-smtp-port').value = s.smtp_port || '';
    document.getElementById('set-smtp-secure').value = s.smtp_secure === '0' ? '0' : '1';
    document.getElementById('set-smtp-user').value = s.smtp_user || '';
    document.getElementById('set-smtp-pass').value = '';
    document.getElementById('set-smtp-from').value = s.smtp_from || '';
  } catch (e) { toast(e.message, 'error'); }
}

async function saveSettings() {
  const body = {
    site_title: document.getElementById('set-site-title').value.trim(),
    site_desc: document.getElementById('set-site-desc').value.trim(),
    download_url: document.getElementById('set-download-url').value.trim(),
    download_url_linux: document.getElementById('set-download-url-linux').value.trim(),
    download_url_macos: document.getElementById('set-download-url-macos').value.trim(),
    latest_version: document.getElementById('set-latest-version').value.trim() || '1.0.0',
    source_url: document.getElementById('set-source-url').value.trim(),
    release_notes: document.getElementById('set-release-notes').value.trim(),
    force_update: document.getElementById('set-force-update').checked ? '1' : '0',
    announcement_title: document.getElementById('set-ann-title').value.trim(),
    announcement_content: document.getElementById('set-ann-content').value.trim(),
    announcement_enabled: document.getElementById('set-ann-enabled').checked ? '1' : '0',
    announcement_force_seconds: String(Math.max(0, parseInt(document.getElementById('set-ann-seconds').value) || 0)),
    announcement_version: document.getElementById('set-ann-version').value.trim() || '1',
    announcement_updated_at: String(Date.now()),
    smtp_host: document.getElementById('set-smtp-host').value.trim(),
    smtp_port: document.getElementById('set-smtp-port').value.trim(),
    smtp_secure: document.getElementById('set-smtp-secure').value,
    smtp_user: document.getElementById('set-smtp-user').value.trim(),
    smtp_from: document.getElementById('set-smtp-from').value.trim(),
  };
  const pass = document.getElementById('set-smtp-pass').value;
  if (pass) body.smtp_pass = pass;
  try {
    await api('/settings', { method: 'PUT', body });
    toast('设置已保存');
    loadSettings();
  } catch (e) { toast(e.message, 'error'); }
}

async function testSmtp() {
  try {
    const r = await api('/settings/test-smtp', { method: 'POST' });
    toast(r.message || 'SMTP 连接成功');
  } catch (e) { toast(e.message, 'error'); }
}

// ============ 广场 ============
async function loadSquare() {
  try {
    const rooms = await api('/rooms/public');
    const el = document.getElementById('square-list');
    if (!rooms || !rooms.length) { el.innerHTML = '<div class="empty-state">暂无公开房间</div>'; return; }
    el.innerHTML = rooms.map(r => `
      <div class="friend-item">
        <div class="fi-info" style="flex:1">
          <div class="fi-name">房间号：<strong>${escapeHtml(r.room_code)}</strong></div>
          <div class="fi-status">模式：${escapeHtml(r.mode || '-')} · 在线：${r.member_count || 0} 人</div>
        </div>
        <button class="btn btn-primary btn-sm" onclick="copyAndToast('${escapeHtml(r.room_code)}')">加入（复制房间号）</button>
      </div>`).join('');
  } catch (e) { toast(e.message, 'error'); }
}

function copyAndToast(text) {
  navigator.clipboard.writeText(text).then(() => toast(`已复制房间号：${text}`)).catch(() => toast('复制失败，请手动复制：' + text, 'error'));
}

// ============ 服务端好友 ============
function switchSrvFriendTab(tab) {
  ['list', 'requests', 'history'].forEach(t => {
    document.getElementById('sftab-' + t).classList.toggle('active', t === tab);
    document.getElementById('srv-friends-panel-' + t).classList.toggle('hidden', t !== tab);
  });
  if (tab === 'requests') loadSrvFriendRequests();
  if (tab === 'history') loadSrvFriendHistory();
}

async function searchSrvFriends() {
  const q = document.getElementById('srv-friend-search').value.trim();
  if (!q) return;
  try {
    const users = await api('/friends/search?q=' + encodeURIComponent(q));
    const el = document.getElementById('srv-friend-search-results');
    if (!users.length) { el.innerHTML = '<div class="empty-state">未找到用户</div>'; return; }
    el.innerHTML = users.map(u => `
      <div class="friend-item">
        <div class="fi-avatar">${escapeHtml(u.username.charAt(0).toUpperCase())}</div>
        <div class="fi-info" style="flex:1">
          <div class="fi-name">${escapeHtml(u.username)}${u.title ? ` <span class="user-title ${titleThemeClass(u.theme, u.role)}">${escapeHtml(u.title)}</span>` : ''}</div>
          <div class="fi-status ${u.online ? 'online' : ''}">${u.online ? '在线' : '离线'}</div>
        </div>
        <button class="btn btn-primary btn-sm" onclick="sendSrvFriendReq(${u.id})">添加好友</button>
      </div>`).join('');
  } catch (e) { toast(e.message, 'error'); }
}

async function sendSrvFriendReq(id) {
  try { const r = await api(`/friends/${id}`, { method: 'POST' }); toast(r.message || '申请已发送'); } catch (e) { toast(e.message, 'error'); }
}

async function loadSrvFriends() {
  try {
    const friends = await api('/friends');
    const el = document.getElementById('srv-friends-list');
    if (!friends.length) { el.innerHTML = '<div class="empty-state">暂无好友</div>'; return; }
    el.innerHTML = friends.map(f => `
      <div class="friend-item">
        <div class="fi-avatar">${escapeHtml(f.username.charAt(0).toUpperCase())}</div>
        <div class="fi-info" style="flex:1">
          <div class="fi-name">${escapeHtml(f.username)}${f.title ? ` <span class="user-title ${titleThemeClass(f.theme, f.role)}">${escapeHtml(f.title)}</span>` : ''}</div>
          <div class="fi-status ${f.online ? 'online' : ''}">${f.online ? '在线' : '离线'}${f.room ? ` · <span class="copy-link" onclick="copyAndToast('${escapeHtml(f.room.code)}')" style="cursor:pointer;color:var(--accent)">房间 ${escapeHtml(f.room.code)}</span>` : ''}</div>
        </div>
        <button class="btn btn-danger btn-sm" onclick="removeSrvFriend(${f.id})">删除</button>
      </div>`).join('');
  } catch (e) { toast(e.message, 'error'); }
}

async function loadSrvFriendRequests() {
  try {
    const reqs = await api('/friends/requests');
    const el = document.getElementById('srv-friends-requests-list');
    const badge = document.getElementById('sftab-requests-badge');
    if (badge) { if (reqs.length) { badge.textContent = reqs.length; badge.classList.remove('hidden'); } else badge.classList.add('hidden'); }
    if (!reqs.length) { el.innerHTML = '<div class="empty-state">暂无待处理申请</div>'; return; }
    el.innerHTML = reqs.map(r => `
      <div class="friend-item">
        <div class="fi-avatar">${escapeHtml(r.username.charAt(0).toUpperCase())}</div>
        <div class="fi-info" style="flex:1">
          <div class="fi-name">${escapeHtml(r.username)}${r.title ? ` <span class="user-title ${titleThemeClass(r.theme, r.role)}">${escapeHtml(r.title)}</span>` : ''}</div>
          <div class="fi-status" style="font-size:.75rem;color:var(--text2)">${new Date(r.requested_at*1000).toLocaleString()}</div>
        </div>
        <div style="display:flex;gap:6px">
          <button class="btn btn-primary btn-sm" onclick="acceptSrvFriend(${r.id})">接受</button>
          <button class="btn btn-danger btn-sm" onclick="rejectSrvFriend(${r.id})">拒绝</button>
        </div>
      </div>`).join('');
  } catch (e) { toast(e.message, 'error'); }
}

async function loadSrvFriendHistory() {
  try {
    const rows = await api('/friends/history');
    const el = document.getElementById('srv-friends-history-list');
    if (!rows.length) { el.innerHTML = '<div class="empty-state">暂无记录</div>'; return; }
    const statusLabel = { pending: '等待确认', rejected: '已被拒绝' };
    el.innerHTML = rows.map(r => `
      <div class="friend-item">
        <div class="fi-avatar">${escapeHtml(r.username.charAt(0).toUpperCase())}</div>
        <div class="fi-info">
          <div class="fi-name">${escapeHtml(r.username)}</div>
          <div class="fi-status">${statusLabel[r.status] || r.status} · ${new Date(r.sent_at*1000).toLocaleDateString()}</div>
        </div>
      </div>`).join('');
  } catch (e) { toast(e.message, 'error'); }
}

async function acceptSrvFriend(id) {
  try { await api(`/friends/${id}/accept`, { method: 'POST' }); toast('已接受好友申请'); loadSrvFriendRequests(); loadSrvFriends(); } catch (e) { toast(e.message, 'error'); }
}
async function rejectSrvFriend(id) {
  try { await api(`/friends/${id}/reject`, { method: 'POST' }); toast('已拒绝'); loadSrvFriendRequests(); } catch (e) { toast(e.message, 'error'); }
}
async function removeSrvFriend(id) {
  if (!confirm('确认删除好友？')) return;
  try { await api(`/friends/${id}`, { method: 'DELETE' }); toast('已删除'); loadSrvFriends(); } catch (e) { toast(e.message, 'error'); }
}

async function loadQqBotConfig() {
  document.getElementById('qqb-webhook-url').textContent = window.location.origin + '/api/qq/webhook';
  try {
    const s = await api('/settings');
    document.getElementById('qqb-enabled').checked = s.onebot_enabled === '1';
    document.getElementById('qqb-api-url').value = s.onebot_webhook_url || '';
    document.getElementById('qqb-access-token').value = s.onebot_access_token === '******' ? '******' : '';
  } catch (e) { toast(e.message, 'error'); }
}

async function saveQqBotConfig() {
  const body = {
    onebot_enabled: document.getElementById('qqb-enabled').checked ? '1' : '0',
    onebot_webhook_url: document.getElementById('qqb-api-url').value.trim(),
  };
  const token = document.getElementById('qqb-access-token').value;
  if (token !== '******') body.onebot_access_token = token.trim();
  try {
    await api('/settings', { method: 'PUT', body });
    toast('QQ 机器人配置已保存');
  } catch (e) { toast(e.message, 'error'); }
}

async function loadAdminOverview() {
  try {
    const s = await api('/stats');
    document.getElementById('ad-stat-users').textContent = s.users;
    document.getElementById('ad-stat-nodes').textContent = s.easytierNodesTotal;
    document.getElementById('ad-stat-rooms').textContent = s.liveRooms;
  } catch (e) { toast(e.message, 'error'); }
}

// ---------- 用户管理 ----------
let userPage = 1;
const adminUserCache = new Map();
async function loadAdminUsers(page = 1) {
  userPage = page;
  const keyword = document.getElementById('user-search').value.trim();
  try {
    const data = await api(`/admin/users?page=${page}&keyword=${encodeURIComponent(keyword)}`);
    adminUserCache.clear();
    data.users.forEach(u => adminUserCache.set(u.id, u));
    const tbody = document.getElementById('users-tbody');
    tbody.innerHTML = data.users.map(u => {
      const banLabel = u.active_ban
        ? (u.ban_until ? `<span class="tag tag-banned">封禁至${new Date(u.ban_until * 1000).toLocaleDateString()}</span>` : '<span class="tag tag-banned">永久封禁</span>')
        : '<span class="tag tag-on">正常</span>';
      const titleHtml = u.title
        ? `<span class="user-title ${titleThemeClass(u.theme, u.role)}">${escapeHtml(u.title)}</span>`
        : '<span style="color:var(--text2)">-</span>';
      return `<tr>
        <td>${u.id}</td>
        <td>${escapeHtml(u.username)}</td>
        <td>${titleHtml}</td>
        <td><span class="tag tag-${escapeHtml(u.role)}">${u.role}</span></td>
        <td>${escapeHtml(u.email || '-')}</td>
        <td>${escapeHtml(u.qq_id || '-')}</td>
        <td>${banLabel}</td>
        <td>${new Date(u.created_at * 1000).toLocaleDateString()}</td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="openEditUserModal(${u.id})">编辑</button>
          <button class="btn btn-danger btn-sm" onclick="deleteUser(${u.id})">删除</button>
        </td>
      </tr>`;
    }).join('');

    // 分页
    const totalPages = Math.ceil(data.total / 20) || 1;
    const pg = document.getElementById('users-pagination');
    pg.innerHTML = '';
    for (let i = 1; i <= totalPages; i++) {
      const b = document.createElement('button');
      b.textContent = i;
      if (i === page) b.classList.add('active');
      b.onclick = () => loadAdminUsers(i);
      pg.appendChild(b);
    }
  } catch (e) { toast(e.message, 'error'); }
}

function openCreateUserModal() {
  document.getElementById('user-modal-title').textContent = '新建用户';
  document.getElementById('um-id').value = '';
  document.getElementById('um-user').value = '';
  document.getElementById('um-user').disabled = false;
  document.getElementById('um-pass').value = '';
  document.getElementById('um-pass-hint').textContent = '(必填)';
  document.getElementById('um-role').value = 'user';
  document.getElementById('um-email').value = '';
  document.getElementById('um-title').value = '';
  document.getElementById('um-theme').value = 'dark';
  document.getElementById('um-banned').value = '0';
  document.getElementById('um-ban-days').value = '';
  document.getElementById('um-ban-days-row').classList.add('hidden');
  openModal('user-modal');
}

function openEditUserModal(id) {
  const u = adminUserCache.get(id);
  if (!u) return;
  document.getElementById('user-modal-title').textContent = '编辑用户';
  document.getElementById('um-id').value = u.id;
  document.getElementById('um-user').value = u.username;
  document.getElementById('um-user').disabled = true;
  document.getElementById('um-pass').value = '';
  document.getElementById('um-pass-hint').textContent = '(留空不修改)';
  document.getElementById('um-role').value = u.role;
  document.getElementById('um-email').value = u.email || '';
  document.getElementById('um-title').value = u.title || '';
  document.getElementById('um-theme').value = u.theme || 'dark';
  document.getElementById('um-banned').value = u.active_ban ? '1' : '0';
  document.getElementById('um-ban-days').value = '';
  document.getElementById('um-ban-days-row').classList.toggle('hidden', !u.active_ban);
  openModal('user-modal');
}

function onBannedChange(val) {
  document.getElementById('um-ban-days-row').classList.toggle('hidden', val !== '1');
}

function onRoleChange(val) {
  const themeEl = document.getElementById('um-theme');
  if (themeEl.value === 'role') return;
  if (val === 'sponsor' && themeEl.value === 'dark') themeEl.value = 'gold';
}

async function saveUser() {
  const id = document.getElementById('um-id').value;
  const username = document.getElementById('um-user').value.trim();
  const password = document.getElementById('um-pass').value;
  const role = document.getElementById('um-role').value;
  const email = document.getElementById('um-email').value.trim();
  const title = document.getElementById('um-title').value.trim();
  const theme = document.getElementById('um-theme').value;
  const banned = parseInt(document.getElementById('um-banned').value);
  const banDays = parseInt(document.getElementById('um-ban-days').value) || 0;

  try {
    if (id) {
      const body = { role, email, title, theme, banned };
      if (banned && banDays > 0) body.ban_days = banDays;
      if (password) body.password = password;
      await api('/admin/users/' + id, { method: 'PUT', body });
      toast('用户已更新');
    } else {
      if (!username || !password) return toast('用户名和密码必填', 'error');
      await api('/admin/users', { method: 'POST', body: { username, password, role, email, title, theme } });
      toast('用户已创建');
    }
    closeModal('user-modal');
    loadAdminUsers(userPage);
  } catch (e) { toast(e.message, 'error'); }
}

async function deleteUser(id) {
  if (!confirm('确定删除该用户？')) return;
  try {
    await api('/admin/users/' + id, { method: 'DELETE' });
    toast('已删除');
    loadAdminUsers(userPage);
  } catch (e) { toast(e.message, 'error'); }
}

// ---------- frp 节点管理 ----------
const frpNodeCache = new Map();
async function loadNodes() {
  try {
    const nodes = await api('/nodes/all');
    frpNodeCache.clear();
    nodes.forEach(n => frpNodeCache.set(n.id, n));
    document.getElementById('nodes-tbody').innerHTML = nodes.map(n => `
      <tr>
        <td>${n.id}</td>
        <td>${escapeHtml(n.name)}</td>
        <td>${escapeHtml(n.host)}</td>
        <td>${n.port}</td>
        <td>${escapeHtml(n.region || '-')}</td>
        <td>${escapeHtml(n.bandwidth || '-')}</td>
        <td>${n.enabled ? '<span class="tag tag-on">启用</span>' : '<span class="tag tag-off">禁用</span>'}</td>
        <td id="node-status-${n.id}"><span class="tag tag-off">未检测</span></td>
        <td>
          <button class="btn btn-outline btn-sm" id="node-test-btn-${n.id}" onclick="testNode(${n.id})">测试</button>
          <button class="btn btn-outline btn-sm" onclick="openNodeModal(${n.id})">编辑</button>
          <button class="btn btn-danger btn-sm" onclick="deleteNode(${n.id})">删除</button>
        </td>
      </tr>`).join('');
  } catch (e) { toast(e.message, 'error'); }
}

// 渲染单个节点的状态监控单元格
function renderNodeStatus(id, online, latency) {
  const cell = document.getElementById('node-status-' + id);
  if (!cell) return;
  if (online) {
    cell.innerHTML = `<span class="tag tag-on">在线</span> <span style="color:var(--text2);font-size:.8rem">${latency}ms</span>`;
  } else {
    cell.innerHTML = '<span class="tag tag-banned">离线</span>';
  }
}

// 测试单个节点连通性
async function testNode(id) {
  const btn = document.getElementById('node-test-btn-' + id);
  const orig = btn ? btn.textContent : '测试';
  if (btn) { btn.disabled = true; btn.textContent = '测试中...'; }
  try {
    const r = await api('/nodes/' + id + '/test', { method: 'POST' });
    renderNodeStatus(id, r.online, r.latency);
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = orig; }
  }
}

// 一键测试全部节点连通性
async function testAllNodes() {
  const btn = document.getElementById('btn-test-all');
  const orig = btn ? btn.textContent : '一键测试全部';
  if (btn) { btn.disabled = true; btn.textContent = '测试中...'; }
  try {
    const data = await api('/nodes/status-all');
    (data.results || []).forEach(r => renderNodeStatus(r.id, r.online, r.latency));
    toast('全部节点测试完成');
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = orig; }
  }
}

function openNodeModal(id) {
  const n = id ? frpNodeCache.get(id) : null;
  const isEdit = n && n.id;
  document.getElementById('node-modal-title').textContent = isEdit ? '编辑 frp 节点' : '添加 frp 节点';
  document.getElementById('nm-id').value = isEdit ? n.id : '';
  document.getElementById('nm-name').value = isEdit ? n.name : '';
  document.getElementById('nm-host').value = isEdit ? n.host : '';
  document.getElementById('nm-port').value = isEdit ? n.port : 7000;
  document.getElementById('nm-token').value = isEdit ? (n.token || '') : '';
  document.getElementById('nm-region').value = isEdit ? (n.region || '') : '';
  document.getElementById('nm-bandwidth').value = isEdit ? (n.bandwidth || '') : '';
  document.getElementById('nm-enabled').value = isEdit ? String(n.enabled) : '1';
  openModal('node-modal');
}

async function saveNode() {
  const id = document.getElementById('nm-id').value;
  const body = {
    name: document.getElementById('nm-name').value.trim(),
    host: document.getElementById('nm-host').value.trim(),
    port: parseInt(document.getElementById('nm-port').value) || 7000,
    token: document.getElementById('nm-token').value.trim(),
    tls_enabled: Number(document.getElementById('nm-tls').value) === 1,
    region: document.getElementById('nm-region').value.trim(),
    bandwidth: document.getElementById('nm-bandwidth').value.trim(),
    enabled: parseInt(document.getElementById('nm-enabled').value),
  };
  if (!body.name || !body.host) return toast('名称和地址必填', 'error');
  try {
    if (id) {
      await api('/nodes/' + id, { method: 'PUT', body });
      toast('节点已更新');
    } else {
      await api('/nodes', { method: 'POST', body });
      toast('节点已添加');
    }
    closeModal('node-modal');
    loadNodes();
  } catch (e) { toast(e.message, 'error'); }
}

async function deleteNode(id) {
  if (!confirm('确定删除该节点？')) return;
  try {
    await api('/nodes/' + id, { method: 'DELETE' });
    toast('已删除');
    loadNodes();
  } catch (e) { toast(e.message, 'error'); }
}

const easyTierNodeCache = new Map();
const etTestResults = new Map();

async function loadEasyTierNodes() {
  try {
    const nodes = await api('/easytier-nodes');
    easyTierNodeCache.clear();
    nodes.forEach((node) => easyTierNodeCache.set(String(node.id), node));
    document.getElementById('easytier-nodes-tbody').innerHTML = nodes.map(n => {
      const t = etTestResults.get(String(n.id));
      const testHtml = t ? (t.ok ? `<span class="tag tag-on">✓ ${t.ms}ms</span>` : `<span class="tag tag-off">✗ ${escapeHtml(t.error || '失败')}</span>`) : '<span class="tag">未测试</span>';
      const kindHtml = n.kind === 'signaling' ? '<span class="tag tag-signaling">信令</span>' : '<span class="tag tag-relay">中继</span>';
      return `<tr><td>${n.id}</td><td>${escapeHtml(n.name)}</td><td>${kindHtml}</td><td>${escapeHtml(n.peer)}</td><td>${n.enabled ? '<span class="tag tag-on">启用</span>' : '<span class="tag tag-off">禁用</span>'}</td><td>${testHtml}</td><td>${new Date(n.created_at * 1000).toLocaleString()}</td><td><button class="btn btn-outline btn-sm" onclick="testEasyTierNode(${n.id})">测试</button> <button class="btn btn-outline btn-sm" onclick="openEasyTierNodeModalById(${n.id})">编辑</button> <button class="btn btn-danger btn-sm" onclick="deleteEasyTierNode(${n.id})">删除</button></td></tr>`;
    }).join('');
  } catch (e) { toast(e.message, 'error'); }
}

async function testEasyTierNode(id) {
  try {
    const r = await api('/easytier-nodes/' + id + '/test', { method: 'POST' });
    etTestResults.set(String(id), r);
    loadEasyTierNodes();
    toast(r.ok ? `节点「${r.name}」连接成功（${r.ms}ms）` : `节点「${r.name}」连接失败：${r.error || '未知错误'}`, r.ok ? 'success' : 'error');
  } catch (e) { toast(e.message, 'error'); }
}

async function testAllEasyTierNodes() {
  const btn = document.getElementById('et-test-all-btn');
  if (btn) { btn.disabled = true; btn.textContent = '测试中…'; }
  try {
    const list = await api('/easytier-nodes/test-all');
    list.forEach((r) => etTestResults.set(String(r.id), r));
    loadEasyTierNodes();
    const okCount = list.filter(r => r.ok).length;
    toast(`一键测试完成：${okCount}/${list.length} 个节点可用`, okCount ? 'success' : 'error');
  } catch (e) { toast(e.message, 'error'); }
  if (btn) { btn.disabled = false; btn.textContent = '一键测试全部'; }
}

function openEasyTierNodeModalById(id) {
  openEasyTierNodeModal(easyTierNodeCache.get(String(id)) || null);
}

function openEasyTierNodeModal(n) {
  document.getElementById('easytier-node-modal-title').textContent = n ? '编辑 EasyTier 节点' : '添加 EasyTier 节点';
  document.getElementById('enm-id').value = n ? n.id : '';
  document.getElementById('enm-name').value = n ? n.name : '';
  document.getElementById('enm-peer').value = n ? n.peer : '';
  document.getElementById('enm-kind').value = n ? (n.kind === 'signaling' ? 'signaling' : 'relay') : 'relay';
  document.getElementById('enm-enabled').value = n ? String(n.enabled) : '1';
  openModal('easytier-node-modal');
}

async function saveEasyTierNode() {
  const id = document.getElementById('enm-id').value;
  const body = { name: document.getElementById('enm-name').value.trim(), peer: document.getElementById('enm-peer').value.trim(), kind: document.getElementById('enm-kind').value, enabled: document.getElementById('enm-enabled').value === '1' };
  if (!body.name || !body.peer) return toast('名称和 peer 地址必填', 'error');
  try { await api(id ? '/easytier-nodes/' + id : '/easytier-nodes', { method: id ? 'PUT' : 'POST', body }); closeModal('easytier-node-modal'); toast(id ? '节点已更新' : '节点已添加'); loadEasyTierNodes(); } catch (e) { toast(e.message, 'error'); }
}

async function deleteEasyTierNode(id) {
  if (!confirm('确定删除该 EasyTier 节点？')) return;
  try { await api('/easytier-nodes/' + id, { method: 'DELETE' }); toast('节点已删除'); loadEasyTierNodes(); } catch (e) { toast(e.message, 'error'); }
}

// ---------- 在线房间管理 ----------
async function loadLiveRooms() {
  try {
    const rooms = await api('/admin/live-rooms');
    const tbody = document.getElementById('live-rooms-tbody');
    if (!rooms.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text2)">暂无在线房间</td></tr>';
      return;
    }
    tbody.innerHTML = rooms.map(r => `
      <tr>
        <td><strong style="color:var(--accent2)">${r.room_code}</strong></td>
        <td>${escapeHtml(r.host)}</td>
        <td>
          <span class="tag tag-${r.mode}">${r.mode.toUpperCase()}</span>
          ${r.frp_endpoint ? `<div style="color:var(--text2);font-size:.78rem;margin-top:4px">${escapeHtml(r.frp_endpoint)}</div>` : ''}
        </td>
        <td>${r.total}/${r.max_members}</td>
        <td>${new Date(r.created_at).toLocaleString()}</td>
        <td><button class="btn btn-danger btn-sm" onclick="closeRoom('${r.room_code}')">强制关闭</button></td>
      </tr>`).join('');
  } catch (e) { toast(e.message, 'error'); }
}

async function closeRoom(code) {
  if (!confirm('确定强制关闭房间 ' + code + '？')) return;
  try {
    await api('/admin/live-rooms/' + code + '/close', { method: 'POST' });
    toast('房间已关闭');
    loadLiveRooms();
    loadFrpSessions();
  } catch (e) { toast(e.message, 'error'); }
}

// ---------- frp 会话（客户端启动上报） ----------
async function loadFrpSessions() {
  try {
    const list = await api('/frp/sessions');
    const tbody = document.getElementById('frp-sessions-tbody');
    if (!tbody) return;
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text2)">暂无 frp 上报记录</td></tr>';
      return;
    }
    tbody.innerHTML = list.map(s => `
      <tr>
        <td><code>${escapeHtml(s.tunnelName)}</code></td>
        <td>${escapeHtml(s.username)}</td>
        <td>${s.roomCode ? `<strong style="color:var(--accent2)">${s.roomCode}</strong>` : '<span style="color:var(--text3)">未绑定</span>'}</td>
        <td>${escapeHtml(s.nodeName)}</td>
        <td>${s.endpoint ? `<code>${escapeHtml(s.endpoint)}</code>` : '<span style="color:var(--text3)">-</span>'}</td>
        <td>${s.remotePort}</td>
        <td>${new Date(s.updatedAt * 1000).toLocaleString()}</td>
      </tr>`).join('');
  } catch (e) { toast(e.message, 'error'); }
}

// ---------- 工具 ----------
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------- 下载叠加层 ----------
let dlOverlayLoaded = false;

function fillDownloadOverlay(settings) {
  if (!settings) return;
  if (settings.site_title) document.getElementById('dl-title').textContent = settings.site_title;
  if (settings.latest_version) {
    document.getElementById('dl-ver').textContent = '最新版本 v' + settings.latest_version + ' · 全平台客户端下载';
  }
  const map = {
    'dl-win': settings.downloads && settings.downloads.win,
    'dl-linux': settings.downloads && settings.downloads.linux,
    'dl-macos': settings.downloads && settings.downloads.macos,
  };
  for (const [id, url] of Object.entries(map)) {
    const el = document.getElementById(id);
    if (el) { if (url) el.href = url; else el.classList.add('disabled'); }
  }
  dlOverlayLoaded = true;
}

function openDownloadOverlay() {
  if (!dlOverlayLoaded) {
    api('/settings/public').then(fillDownloadOverlay).catch(() => {});
  }
  document.getElementById('dl-overlay').classList.add('open');
}

function closeDownloadOverlay() {
  document.getElementById('dl-overlay').classList.remove('open');
}

// ---------- 按钮涟漪动画 ----------
document.addEventListener('click', (e) => {
  // 动画关闭时不生成涟漪
  if (getAnimLevel() === 'off' || !isAnimEnabled()) return;
  const btn = e.target.closest('.btn');
  if (!btn) return;
  const rect = btn.getBoundingClientRect();
  const size = Math.max(rect.width, rect.height);
  const ripple = document.createElement('span');
  ripple.className = 'ripple';
  ripple.style.width = ripple.style.height = size + 'px';
  ripple.style.left = (e.clientX - rect.left - size / 2) + 'px';
  ripple.style.top = (e.clientY - rect.top - size / 2) + 'px';
  btn.appendChild(ripple);
  setTimeout(() => ripple.remove(), 600);
});

// ============ 外观 & 动画设置（localStorage 持久化）============
const PREF_KEYS = { theme: 'blfp_theme', animEnabled: 'blfp_anim_enabled', animLevel: 'blfp_anim_level' };

function getTheme() { return localStorage.getItem(PREF_KEYS.theme) || 'dark'; }
function isAnimEnabled() { return localStorage.getItem(PREF_KEYS.animEnabled) !== '0'; }
// 动画性能档位：high / medium / low / off
function getAnimLevel() { return localStorage.getItem(PREF_KEYS.animLevel) || 'high'; }

// 应用主题：切换 [data-theme]，写入 localStorage
function applyThemeSetting(theme) {
  const t = theme === 'light' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem(PREF_KEYS.theme, t);
}

// 应用动画开关
function applyAnimEnabled(val) {
  const on = String(val) === '1' || val === true;
  localStorage.setItem(PREF_KEYS.animEnabled, on ? '1' : '0');
  syncAnimClasses();
}

// 应用动画性能档位：high / medium / low / off
function applyAnimLevel(level) {
  const allowed = ['high', 'medium', 'low', 'off'];
  const lv = allowed.includes(level) ? level : 'high';
  localStorage.setItem(PREF_KEYS.animLevel, lv);
  syncAnimClasses();
}

// 根据当前开关与档位，同步 <html> 上的 class（供 CSS 控制）
function syncAnimClasses() {
  const root = document.documentElement;
  const level = isAnimEnabled() ? getAnimLevel() : 'off';
  root.classList.remove('anim-high', 'anim-medium', 'anim-low', 'anim-off');
  root.classList.add('anim-' + level);
}

// 页面加载时应用已保存偏好，并回填设置控件
function initPreferences() {
  applyThemeSetting(getTheme());
  syncAnimClasses();
  const themeSel = document.getElementById('set-theme');
  const enabledSel = document.getElementById('set-anim-enabled');
  const levelSel = document.getElementById('set-anim-level');
  if (themeSel) themeSel.value = getTheme();
  if (enabledSel) enabledSel.value = isAnimEnabled() ? '1' : '0';
  if (levelSel) levelSel.value = getAnimLevel();
}

// ---------- 启动 ----------
async function startConsole() {
  initPreferences();
  const installState = await checkInstallState();
  if (!installState || !installState.installed) return showSetup();
  if (TOKEN) return enterApp();
  showAuth();
}

startConsole();
