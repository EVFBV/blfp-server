const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { WebSocketServer, WebSocket } = require('ws');
const db = require('./db');
const { validateMessage } = require('./security-logic');

const rooms = new Map();
const onlineUsers = new Map();
const MEMBER_BROADCAST_INTERVAL = 1000;
const MESSAGE_RATE_WINDOW_MS = 10000;
const MESSAGE_RATE_LIMIT = 100;
function genRoomCode() {
  let code;
  do code = String(Math.floor(100000 + Math.random() * 900000));
  while (rooms.has(code));
  return code;
}

async function getEasyTierPeers() {
  const rows = await db.query('SELECT peer FROM easytier_nodes WHERE enabled = 1 ORDER BY id ASC');
  return rows.map((row) => row.peer).filter(Boolean);
}

function createEasyTierConfig(code, mcPort, peers, etPort) {
  const preferredSubnet = (Number(code) % 250) + 1;
  const usedSubnets = new Set();
  rooms.forEach((room) => {
    if (room.mode !== 'easytier' || !room.easytier?.hostVirtualIp) return;
    const subnet = Number(room.easytier.hostVirtualIp.split('.')[2]);
    if (Number.isInteger(subnet) && subnet >= 1 && subnet <= 250) usedSubnets.add(subnet);
  });
  let subnet = null;
  for (let offset = 0; offset < 250; offset += 1) {
    const candidate = ((preferredSubnet - 1 + offset) % 250) + 1;
    if (!usedSubnets.has(candidate)) {
      subnet = candidate;
      break;
    }
  }
  if (subnet === null) return null;
  return {
    networkName: `blfp-${code}`,
    networkSecret: crypto.randomBytes(32).toString('hex'),
    peers,
    hostVirtualIp: `10.200.${subnet}.1`,
    port: etPort || 25565,
    mcPort: mcPort || 25565,
    guestVirtualIps: new Map(),
  };
}

function allocateGuestVirtualIp(room, memberId) {
  const prefix = room.easytier.hostVirtualIp.slice(0, room.easytier.hostVirtualIp.lastIndexOf('.'));
  const used = new Set(room.easytier.guestVirtualIps.values());
  let host = 2;
  while (used.has(`${prefix}.${host}`)) host += 1;
  const virtualIp = `${prefix}.${host}`;
  room.easytier.guestVirtualIps.set(memberId, virtualIp);
  return virtualIp;
}

function easyTierClientConfig(easytier, virtualIp) {
  return {
    virtualIp,
    hostVirtualIp: easytier.hostVirtualIp,
    port: easytier.port,
    networkName: easytier.networkName,
    networkSecret: easytier.networkSecret,
    peers: easytier.peers,
  };
}

function logSignalingError(scope, error, ws) {
  const rawMessage = error instanceof Error ? error.message : String(error);
  const message = rawMessage
    .replace(/(bearer\s+)[^\s]+/gi, '$1[REDACTED]')
    .replace(/([?&](?:token|secret|key)=)[^&\s]+/gi, '$1[REDACTED]')
    .replace(/\b[a-f\d]{32,}\b/gi, '[REDACTED]')
    .slice(0, 300);
  console.error('[Signaling]', {
    scope,
    error: {
      name: error instanceof Error ? error.name : 'Error',
      message,
      ...(error && typeof error === 'object' && typeof error.code === 'string' ? { code: error.code } : {}),
    },
    ...(ws?.memberId ? { memberId: ws.memberId } : {}),
    ...(ws?.user?.id ? { userId: ws.user.id } : {}),
    ...(ws?.roomCode ? { roomCode: ws.roomCode } : {}),
  });
}

function send(ws, obj) {
  const task = async () => {
    if (ws.readyState !== WebSocket.OPEN) return;
    const payload = JSON.stringify(obj);
    await new Promise((resolve) => {
      try {
        ws.send(payload, (error) => {
          if (error) logSignalingError('send', error, ws);
          resolve();
        });
      } catch (error) {
        logSignalingError('send', error, ws);
        resolve();
      }
    });
  };
  ws.sendQueue = ws.sendQueue.then(task, task);
  return ws.sendQueue;
}

function exceedsMessageRate(ws, now = Date.now()) {
  const cutoff = now - MESSAGE_RATE_WINDOW_MS;
  while (ws.messageTimestamps.length && ws.messageTimestamps[0] <= cutoff) ws.messageTimestamps.shift();
  if (ws.messageTimestamps.length >= MESSAGE_RATE_LIMIT) return true;
  ws.messageTimestamps.push(now);
  return false;
}

function clientIp(request) {
  let ip = request.socket.remoteAddress || '';
  if (process.env.TRUST_PROXY === '1') {
    const forwarded = request.headers['x-forwarded-for'];
    if (forwarded) ip = forwarded.split(',')[0].trim();
  }
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function memberInfo(ws, includeIp, isHost) {
  return {
    memberId: ws.memberId,
    username: ws.user.username,
    title: ws.user.title || '',
    theme: ws.user.theme || 'dark',
    ...(includeIp ? { ip: ws.ip } : {}),
    ping: ws.pingMs,
    isHost,
  };
}

function roomMembers(room, includeIp) {
  return [
    memberInfo(room.host, includeIp, true),
    ...[...room.guests.values()].map((guest) => memberInfo(guest, includeIp, false)),
  ];
}

function broadcastMembers(room) {
  room.lastMemberBroadcastAt = Date.now();
  const total = room.guests.size + 1;
  send(room.host, { type: 'members', members: roomMembers(room, true), total, maxMembers: room.maxMembers });
  const guestMessage = { type: 'members', members: roomMembers(room, false), total, maxMembers: room.maxMembers };
  room.guests.forEach((guest) => send(guest, guestMessage));
}

function scheduleMembersBroadcast(room) {
  if (room.memberBroadcastTimer) return;
  const delay = Math.max(0, MEMBER_BROADCAST_INTERVAL - (Date.now() - (room.lastMemberBroadcastAt || 0)));
  room.memberBroadcastTimer = setTimeout(() => {
    room.memberBroadcastTimer = null;
    try {
      if (rooms.get(room.host.roomCode) === room) broadcastMembers(room);
    } catch (error) {
      logSignalingError('member-broadcast-timer', error, room.host);
    }
  }, delay);
}

function getLiveRooms() {
  return [...rooms.entries()].map(([code, room]) => ({
    room_code: code,
    host_id: room.host.user.id,
    host: room.host.user.username,
    host_title: room.host.user.title || '',
    host_theme: room.host.user.theme || 'dark',
    is_public: room.isPublic,
    mode: room.mode,
    guests: room.guests.size,
    total: room.guests.size + 1,
    max_members: room.maxMembers,
    members: roomMembers(room, true),
    created_at: room.createdAt,
    frp_endpoint: room.mode === 'frp' && room.frp ? `${room.frp.host}:${room.frp.port}` : null,
  }));
}

function getRoomInfo(code) {
  const room = rooms.get(String(code));
  if (!room) return null;
  return {
    room_code: String(code),
    mode: room.mode,
    mc_port: room.mcPort,
    is_public: room.isPublic,
    created_at: room.createdAt,
    host_name: room.host.user.username,
    total: room.guests.size + 1,
    max_members: room.maxMembers,
    frp_host: room.mode === 'frp' && room.frp ? room.frp.host : null,
    frp_port: room.mode === 'frp' && room.frp ? room.frp.port : null,
  };
}

function getPublicRooms() {
  return getLiveRooms().filter((room) => room.is_public === true).map((room) => ({
    room_code: room.room_code,
    host: room.host,
    host_title: room.host_title,
    host_theme: room.host_theme,
    mode: room.mode,
    total: room.total,
    max_members: room.max_members,
    created_at: room.created_at,
    is_public: true,
  }));
}

function setUserPresence(userId, online) {
  const state = onlineUsers.get(userId) || { sockets: 0, explicit: false };
  state.explicit = online;
  if (state.sockets || state.explicit) onlineUsers.set(userId, state);
  else onlineUsers.delete(userId);
}

function isUserOnline(userId) {
  const state = onlineUsers.get(userId);
  return !!state && (state.sockets > 0 || state.explicit);
}

async function deleteRoom(code) {
  const roomCode = String(code);
  const room = rooms.get(roomCode);
  if (room?.memberBroadcastTimer) clearTimeout(room.memberBroadcastTimer);
  rooms.delete(roomCode);
  try {
    await db.execute('DELETE FROM rooms WHERE room_code = ?', [roomCode]);
  } catch (error) {
    logSignalingError('delete-room-projection', error, room?.host);
  }
}

async function forceCloseRoom(code, reason = '管理员关闭了房间') {
  const roomCode = String(code);
  const room = rooms.get(roomCode);
  if (!room) return false;
  if (room.closePromise) return room.closePromise;
  room.closePromise = (async () => {
    const sends = [send(room.host, { type: 'closed', reason }), ...[...room.guests.values()].map((guest) => send(guest, { type: 'closed', reason }))];
    room.host.roomCode = null;
    room.host.roomRole = null;
    room.guests.forEach((guest) => {
      guest.roomCode = null;
      guest.roomRole = null;
    });
    await deleteRoom(roomCode);
    await Promise.all(sends);
    return true;
  })();
  return room.closePromise;
}

async function closeRoomsByHost(hostId, reason) {
  let closed = 0;
  for (const [code, room] of rooms) {
    if (room.host.user.id === hostId && await forceCloseRoom(code, reason)) closed += 1;
  }
  return closed;
}

function initSignaling(server) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

  server.on('upgrade', async (request, socket, head) => {
    let url;
    try { url = new URL(request.url, 'http://localhost'); } catch { return socket.destroy(); }
    if (url.pathname !== '/ws') return socket.destroy();
    if (!db.isReady() || !db.isInstalled()) {
      socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
      return socket.destroy();
    }

    try {
      const token = url.searchParams.get('token');
      if (!token) throw new Error('missing token');
      const payload = jwt.verify(token, db.getJwtSecret(), { algorithms: ['HS256'] });
      const user = await db.one('SELECT id, username, role, title, theme, banned FROM users WHERE id = ?', [payload.id]);
      if (!user || user.banned) throw new Error('invalid user');
      request.authUser = { id: user.id, username: user.username, role: user.role, title: user.title, theme: user.theme };
      wss.handleUpgrade(request, socket, head, (ws) => wss.emit('connection', ws, request));
    } catch {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
    }
  });

  const heartbeat = setInterval(() => {
    wss.clients.forEach((ws) => {
      try {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        ws.pingStartedAt = Date.now();
        ws.ping();
      } catch (error) {
        logSignalingError('heartbeat-timer', error, ws);
      }
    });
  }, 30000);
  wss.on('close', () => clearInterval(heartbeat));

  wss.on('connection', async (ws, request) => {
    ws.memberId = crypto.randomUUID();
    ws.user = request.authUser;
    ws.ip = clientIp(request);
    ws.pingMs = null;
    ws.roomCode = null;
    ws.roomRole = null;
    ws.isAlive = true;
    ws.messageTimestamps = [];
    ws.messageQueue = Promise.resolve();
    ws.sendQueue = Promise.resolve();
    ws.closePromise = null;
    ws.disconnectPromise = null;
    ws.cleanupPromise = null;
    ws.cleanupCode = null;
    const onlineState = onlineUsers.get(ws.user.id) || { sockets: 0, explicit: false };
    onlineState.sockets += 1;
    onlineUsers.set(ws.user.id, onlineState);

    /* 连接时推送最新公告（公告系统集成到信令服务器） */
    try {
      const { getAllSettings } = require('./mailer');
      const all = await getAllSettings();
      const annTitle = all.announcement_title || '';
      const annContent = all.announcement_content || '';
      if (annContent && all.announcement_enabled !== '0') {
        send(ws, {
          type: 'chat',
          system: true,
          text: ('📢 ' + (annTitle ? annTitle + '：' : '') + annContent).slice(0, 800),
          at: Date.now(),
        });
      }
    } catch (e) { /* 公告推送失败不影响连接 */ }


    ws.on('pong', async () => {
      try {
        ws.isAlive = true;
        if (ws.pingStartedAt) ws.pingMs = Date.now() - ws.pingStartedAt;
        await db.execute('UPDATE users SET last_seen_at = UNIX_TIMESTAMP() WHERE id = ?', [ws.user.id]);
        const room = rooms.get(ws.roomCode);
        if (room) scheduleMembersBroadcast(room);
      } catch (error) {
        logSignalingError('pong', error, ws);
      }
    });

    ws.on('message', (raw, isBinary) => {
      const processMessage = async () => {
        try {
          if (exceedsMessageRate(ws)) {
            send(ws, { type: 'error', error: '消息过于频繁' });
            return ws.close(1008, '消息过于频繁');
          }
          if (isBinary) return send(ws, { type: 'error', error: '非法消息格式' });
          let msg;
        try {
          msg = JSON.parse(raw.toString());
        } catch (error) {
          logSignalingError('message-parse', error, ws);
          return send(ws, { type: 'error', error: '非法消息格式' });
        }
        if (!validateMessage(msg)) {
          logSignalingError('message-validation', new TypeError('消息字段不合法'), ws);
          return send(ws, { type: 'error', error: '非法消息格式' });
        }

        switch (msg.type) {
      case 'chat': {
        // 全局聊天：广播给所有在线客户端
        const chatMsg = {
          type: 'chat',
          text: String(msg.text || '').slice(0, 500),
          username: (ws.user && ws.user.username) || 'Unknown',
          userId: ws.user ? ws.user.id : 0,
          at: Date.now(),
        };
        wss.clients.forEach((client) => {
          if (client.readyState === WebSocket.OPEN && client.user) send(client, chatMsg);
        });
        break;
      }

        case 'create': {
          if (msg.userId !== undefined && msg.userId !== ws.user.id) {
            return send(ws, { type: 'error', error: '非法消息格式' });
          }
          if (msg.username !== undefined && msg.username !== ws.user.username) {
            return send(ws, { type: 'error', error: '非法消息格式' });
          }
          const mode = msg.mode;
          let frp = null;
          if (mode === 'frp') {
            const node = await db.one('SELECT id, host FROM frp_nodes WHERE id = ? AND enabled = 1', [msg.frp.node]);
            if (!node || typeof node.host !== 'string' || !node.host.length) {
              return send(ws, { type: 'error', error: 'frp 节点不存在或已停用' });
            }
            frp = { host: node.host, port: msg.frp.port, node: node.id };
          }
          if (ws.roomCode) await cleanup(ws);
          ws.cleanupPromise = null;
          ws.cleanupCode = null;
          const code = genRoomCode();
          let easytier = null;
          if (mode === 'easytier') {
            const peers = await getEasyTierPeers();
            if (!peers.length) return send(ws, { type: 'error', error: '暂无可用的 EasyTier 节点，请联系管理员配置' });
            easytier = createEasyTierConfig(code, msg.mcPort, peers, msg.etPort);
            if (!easytier) return send(ws, { type: 'error', error: 'EasyTier 虚拟网段已全部占用' });
          }
          const isPublic = msg.isPublic === true;
          const elevated = ws.user.role === 'sponsor' || ws.user.role === 'admin';
          const maxMembers = elevated ? (isPublic ? 20 : 12) : (isPublic ? 12 : 8);
          const room = {
            host: ws,
            guests: new Map(),
            mode,
            frp,
            easytier,
            mcPort: msg.mcPort || 25565,
            isPublic,
            maxMembers,
            createdAt: Date.now(),
          };
          try {
                await db.execute('INSERT INTO rooms (room_code, host_id, mode, mc_port, is_public, created_at) VALUES (?, ?, ?, ?, ?, UNIX_TIMESTAMP())', [code, ws.user.id, mode, room.mcPort, isPublic ? 1 : 0]);
          } catch (error) {
            logSignalingError('create-room-projection', error, ws);
            return send(ws, { type: 'error', error: '房间创建失败' });
          }
          rooms.set(code, room);
          ws.roomCode = code;
          ws.roomRole = 'host';
          const created = {
            type: 'created', room: code, hostUser: ws.user.username, hostId: ws.user.id,
            isPublic, total: 1, maxMembers,
          };
          if (mode === 'frp') {
            created.mode = 'frp';
            created.frp = frp ? { host: frp.host, port: frp.port } : null;
          } else {
            created.mode = mode;
            created.easytier = {
              ...easyTierClientConfig(easytier, easytier.hostVirtualIp),
              mcPort: easytier.mcPort,
            };
          }
          send(ws, created);
          broadcastMembers(room);
          break;
        }

        case 'join': {
          if (ws.roomCode) await cleanup(ws);
          ws.cleanupPromise = null;
          ws.cleanupCode = null;
          const room = rooms.get(msg.room);
          if (!room) return send(ws, { type: 'error', error: '房间不存在或已关闭' });
          if (room.guests.size + 1 >= room.maxMembers) {
            return send(ws, { type: 'error', error: 'ROOM_FULL', code: 'ROOM_FULL' });
          }
          ws.roomCode = msg.room;
          ws.roomRole = 'guest';
          room.guests.set(ws.memberId, ws);
          const joined = {
            type: 'joined', room: ws.roomCode, mode: room.mode,
            hostUser: room.host.user.username, hostId: room.host.user.id,
            guests: room.guests.size, total: room.guests.size + 1, maxMembers: room.maxMembers,
          };
          if (room.mode === 'frp' && room.frp) joined.frp = { host: room.frp.host, port: room.frp.port };
          if (room.mode === 'easytier' && room.easytier) {
            const virtualIp = allocateGuestVirtualIp(room, ws.memberId);
            joined.easytier = easyTierClientConfig(room.easytier, virtualIp);
          }
          send(ws, joined);
          broadcastMembers(room);
          ws.pingStartedAt = Date.now();
          try {
            ws.ping();
          } catch (error) {
            logSignalingError('join-ping', error, ws);
          }
          break;
        }

        case 'close':
          if (msg.room !== undefined && msg.room !== ws.roomCode) {
            return send(ws, { type: 'error', error: '房间号不匹配' });
          }
          if (ws.roomRole === 'host' && ws.roomCode) await forceCloseRoom(ws.roomCode, '房主已关闭房间');
          break;

        case 'signal': {
          const room = rooms.get(ws.roomCode);
          if (!room) return send(ws, { type: 'error', error: '当前不在房间中' });
          if (room.mode === 'easytier') {
            return send(ws, { type: 'error', error: 'EasyTier 模式不支持 signal' });
          }
          if (ws.roomRole === 'host') {
            if (!msg.to) return send(ws, { type: 'error', error: 'signal 缺少目标成员' });
            const guest = room.guests.get(msg.to);
            if (!guest) return send(ws, { type: 'error', error: 'signal 目标成员不存在' });
            send(guest, { type: 'signal', data: msg.data });
          } else if (ws.roomRole === 'guest' && msg.to === undefined) {
            send(room.host, { type: 'signal', data: msg.data, from: ws.memberId });
          } else {
            return send(ws, { type: 'error', error: '非法 signal 目标' });
          }
          break;
        }

        case 'leave':
          if (msg.room !== undefined && msg.room !== ws.roomCode) {
            return send(ws, { type: 'error', error: '房间号不匹配' });
          }
          await cleanup(ws);
          break;

        case 'et-port-update': {
          const room = rooms.get(ws.roomCode);
          if (!room || ws.roomRole !== 'host') return send(ws, { type: 'error', error: '无权操作' });
          const port = Number(msg.port);
          if (!Number.isInteger(port) || port < 1 || port > 65535) return send(ws, { type: 'error', error: '端口无效' });
          room.easytier.port = port;
          // 广播给房内所有成员
          broadcastToRoom(ws.roomCode, { type: 'et-port', port });
          break;
        }
        }
        } catch (error) {
          logSignalingError('message', error, ws);
          await send(ws, { type: 'error', error: '消息处理失败' });
        }
      };
      ws.messageQueue = ws.messageQueue.then(processMessage, processMessage);
    });

    const close = () => {
      if (ws.closePromise) return ws.closePromise;
      ws.closePromise = ws.messageQueue.then(() => disconnect(ws), () => disconnect(ws));
      return ws.closePromise;
    };

    ws.on('close', () => {
      close().catch((error) => logSignalingError('close', error, ws));
    });
    ws.on('error', (socketError) => {
      if (socketError) logSignalingError('error', socketError, ws);
      close().catch((error) => logSignalingError('error', error, ws));
    });
  });

  function disconnect(ws) {
    if (ws.disconnectPromise) return ws.disconnectPromise;
    ws.disconnectPromise = (async () => {
      if (!ws.presenceRemoved) {
        ws.presenceRemoved = true;
        const state = onlineUsers.get(ws.user.id);
        if (state) {
          state.sockets = Math.max(0, state.sockets - 1);
          if (state.sockets || state.explicit) onlineUsers.set(ws.user.id, state);
          else onlineUsers.delete(ws.user.id);
        }
      }
      await cleanup(ws);
    })();
    return ws.disconnectPromise;
  }

  function cleanup(ws) {
    const code = ws.roomCode;
    if (!code) return Promise.resolve();
    if (ws.cleanupPromise && ws.cleanupCode === code) return ws.cleanupPromise;
    ws.cleanupCode = code;
    ws.cleanupPromise = (async () => {
      const role = ws.roomRole;
      ws.roomCode = null;
      ws.roomRole = null;
      const room = rooms.get(code);
      if (!room) return;

      if (role === 'host') {
        await forceCloseRoom(code, '房主已断开');
      } else if (room.guests.delete(ws.memberId)) {
        if (room.mode === 'easytier' && room.easytier) {
          room.easytier.guestVirtualIps.delete(ws.memberId);
        } else {
          await send(room.host, { type: 'peer-left', memberId: ws.memberId, guestId: ws.memberId, guests: room.guests.size });
        }
        broadcastMembers(room);
      }
    })();
    return ws.cleanupPromise;
  }

  console.log('[Signaling] 已鉴权的信令服务已挂载于 /ws');
  return wss;
}

function applyFrpReport(userId, roomCode, remotePort) {
  const room = rooms.get(String(roomCode));
  if (!room || room.mode !== 'frp') return false;
  if (!room.host || !room.host.user || Number(room.host.user.id) !== Number(userId)) return false;
  if (!room.frp) room.frp = { host: null, port: null, node: null };
  room.frp.port = Number(remotePort);
  return true;
}

function broadcastAnnouncement(title, content) {
  const text = ('📢 ' + (title ? title + '：' : '') + String(content || '')).slice(0, 800);
  let delivered = 0;
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && client.user) {
      send(client, { type: 'chat', system: true, text, at: Date.now() });
      delivered += 1;
    }
  });
  return delivered;
}

module.exports = { initSignaling, getLiveRooms, getRoomInfo, getPublicRooms, forceCloseRoom, closeRoomsByHost, applyFrpReport, broadcastAnnouncement };
