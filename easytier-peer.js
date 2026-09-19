const PROTOCOLS = new Set(['tcp:', 'udp:', 'ws:', 'wss:']);

function normalizePeer(value) {
  const text = String(value || '').trim();
  if (!text || text.length > 512) return null;
  const match = text.match(/^([a-z]+):\/\/(\[[^\]]+\]|[^/:?#]+):(\d+)$/i);
  if (!match) return null;
  let url;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  if (!PROTOCOLS.has(url.protocol) || !url.hostname || url.username || url.password) return null;
  const port = Number(match[3]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return `${url.protocol}//${url.hostname.toLowerCase()}:${port}`;
}

function parsePeers(value) {
  const values = Array.isArray(value) ? value : String(value || '').split(/\r?\n|,/);
  const peers = [];
  const seen = new Set();
  for (const item of values) {
    const peer = normalizePeer(item);
    if (!peer || seen.has(peer)) continue;
    seen.add(peer);
    peers.push(peer);
  }
  return peers;
}

function validatePeers(value) {
  const values = Array.isArray(value) ? value : String(value || '').split(/\r?\n|,/).filter((item) => String(item).trim());
  const peers = parsePeers(value);
  return peers.length > 0 && peers.length === values.length ? peers : null;
}

module.exports = { normalizePeer, parsePeers, validatePeers };
