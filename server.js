const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── MeshCore Key Derivation ─────────────────────────────────────────────────
// Channel name is always prefixed with #
// key    = SHA256("#" + channelName)[0:16]   (first 16 bytes)
// prefix = SHA256(key)[0]                    (first byte)

function deriveChannelKey(channelName) {
  const name = channelName.startsWith('#') ? channelName : '#' + channelName;
  const hash = crypto.createHash('sha256').update(name).digest();
  return hash.subarray(0, 16); // first 16 bytes
}

function derivePrefix(keyBuffer) {
  const hash = crypto.createHash('sha256').update(keyBuffer).digest();
  return hash[0]; // first byte
}

function deriveAll(channelName) {
  const key = deriveChannelKey(channelName);
  const prefix = derivePrefix(key);
  return {
    channelName: channelName.startsWith('#') ? channelName : '#' + channelName,
    key: key.toString('hex'),
    prefix: prefix.toString(16).padStart(2, '0'),
  };
}

// Extract prefix byte from raw packet data (first byte of the packet)
function extractPrefixFromPacket(rawData) {
  const cleaned = rawData.trim();
  // If it looks like hex data, parse the first byte
  const hexMatch = cleaned.match(/^([0-9a-fA-F]{2})/);
  if (hexMatch) return parseInt(hexMatch[1], 16);
  // If raw binary provided as decimal bytes
  const byteMatch = cleaned.match(/^(\d{1,3})/);
  if (byteMatch) return parseInt(byteMatch[1], 10) & 0xFF;
  return null;
}

// ── Database Setup ──────────────────────────────────────────────────────────
const db = new Database('keygen.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_data TEXT NOT NULL,
    prefix INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    cracked_key TEXT,
    channel_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    cracked_at DATETIME
  );

  CREATE TABLE IF NOT EXISTS known_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_name TEXT NOT NULL UNIQUE,
    key TEXT NOT NULL,
    prefix TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS work_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER NOT NULL,
    target_prefix INTEGER NOT NULL,
    range_start INTEGER NOT NULL,
    range_end INTEGER NOT NULL,
    charset TEXT NOT NULL DEFAULT 'alnum',
    status TEXT DEFAULT 'pending',
    assigned_to TEXT,
    assigned_at DATETIME,
    completed_at DATETIME,
    FOREIGN KEY (packet_id) REFERENCES packets(id)
  );

  CREATE TABLE IF NOT EXISTS candidate_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER NOT NULL,
    channel_name TEXT NOT NULL,
    key TEXT NOT NULL,
    prefix TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    decode_success INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (packet_id) REFERENCES packets(id)
  );
`);

// ── Prepared Statements ─────────────────────────────────────────────────────
const stmts = {
  insertPacket: db.prepare('INSERT INTO packets (raw_data, prefix) VALUES (?, ?)'),
  getPackets: db.prepare('SELECT * FROM packets ORDER BY created_at DESC'),
  getPacketById: db.prepare('SELECT * FROM packets WHERE id = ?'),
  updatePacketStatus: db.prepare('UPDATE packets SET status = ?, cracked_key = ?, channel_name = ?, cracked_at = CURRENT_TIMESTAMP WHERE id = ?'),
  getKnownChannels: db.prepare('SELECT * FROM known_channels ORDER BY channel_name'),
  insertKnownChannel: db.prepare('INSERT OR REPLACE INTO known_channels (channel_name, key, prefix) VALUES (?, ?, ?)'),
  deleteKnownChannel: db.prepare('DELETE FROM known_channels WHERE id = ?'),
  findByPrefix: db.prepare('SELECT * FROM known_channels WHERE prefix = ?'),
  insertChunk: db.prepare('INSERT INTO work_chunks (packet_id, target_prefix, range_start, range_end, charset) VALUES (?, ?, ?, ?, ?)'),
  getPendingChunks: db.prepare("SELECT * FROM work_chunks WHERE status = 'pending' LIMIT ?"),
  assignChunk: db.prepare("UPDATE work_chunks SET status = 'assigned', assigned_to = ?, assigned_at = CURRENT_TIMESTAMP WHERE id = ?"),
  completeChunk: db.prepare("UPDATE work_chunks SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?"),
  getChunksByPacket: db.prepare('SELECT * FROM work_chunks WHERE packet_id = ?'),
  getQueueStats: db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM work_chunks WHERE status = 'pending') as pending,
      (SELECT COUNT(*) FROM work_chunks WHERE status = 'assigned') as assigned,
      (SELECT COUNT(*) FROM work_chunks WHERE status = 'completed') as completed,
      (SELECT COUNT(*) FROM work_chunks) as total
  `),
  expireStaleChunks: db.prepare(`
    UPDATE work_chunks SET status = 'pending', assigned_to = NULL, assigned_at = NULL
    WHERE status = 'assigned' AND assigned_at < datetime('now', '-5 minutes')
  `),
  insertCandidate: db.prepare('INSERT INTO candidate_keys (packet_id, channel_name, key, prefix) VALUES (?, ?, ?, ?)'),
  getCandidates: db.prepare('SELECT * FROM candidate_keys WHERE packet_id = ? ORDER BY created_at DESC'),
  getAllCandidates: db.prepare('SELECT * FROM candidate_keys ORDER BY created_at DESC LIMIT 100'),
};

// ── Work Chunk Generation ───────────────────────────────────────────────────
// We brute-force channel names. The charset is alphanumeric + common chars.
// Chunks represent ranges of a numeric index that maps to candidate strings.
const CHUNK_SIZE = 500_000;

// Character sets for name generation
const CHARSETS = {
  // a-z, 0-9 (lowercase only, most common for channel names)
  alnum: 'abcdefghijklmnopqrstuvwxyz0123456789',
  // Include uppercase and common special chars
  full: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.',
};

// Generate candidate strings by length tier
// 1 char: 36 candidates (alnum)
// 2 char: 36^2 = 1,296
// 3 char: 36^3 = 46,656
// 4 char: 36^4 = 1,679,616
// 5 char: 36^5 = 60,466,176
// 6 char: 36^6 = 2,176,782,336
// Total through 5 chars: ~62M candidates
// Total through 6 chars: ~2.2B candidates

function createWorkChunks(packetId, targetPrefix) {
  // Start with names up to 6 chars long using alnum charset
  const charset = CHARSETS.alnum;
  const base = charset.length; // 36
  let totalCandidates = 0;
  for (let len = 1; len <= 6; len++) {
    totalCandidates += Math.pow(base, len);
  }

  const insert = db.transaction(() => {
    for (let start = 0; start < totalCandidates; start += CHUNK_SIZE) {
      const end = Math.min(start + CHUNK_SIZE, totalCandidates);
      stmts.insertChunk.run(packetId, targetPrefix, start, end, 'alnum');
    }
  });
  insert();
}

// ── Connected Workers ───────────────────────────────────────────────────────
const workers = new Map();

function broadcast(data) {
  const msg = JSON.stringify(data);
  for (const ws of wss.clients) {
    if (ws.readyState === 1) ws.send(msg);
  }
}

// ── WebSocket Handler ───────────────────────────────────────────────────────
wss.on('connection', (ws) => {
  const workerId = crypto.randomUUID();
  workers.set(workerId, { ws, chunksCompleted: 0, hashRate: 0 });
  broadcast({ type: 'worker_count', count: workers.size });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {
      case 'request_work': {
        stmts.expireStaleChunks.run();
        const chunks = stmts.getPendingChunks.all(msg.count || 1);
        for (const chunk of chunks) {
          stmts.assignChunk.run(workerId, chunk.id);
        }
        ws.send(JSON.stringify({
          type: 'work',
          chunks,
          charset: CHARSETS.alnum,
        }));
        broadcast({ type: 'stats', ...stmts.getQueueStats.get() });
        break;
      }

      case 'chunk_complete': {
        stmts.completeChunk.run(msg.chunkId);
        const worker = workers.get(workerId);
        if (worker) {
          worker.chunksCompleted++;
          worker.hashRate = msg.hashRate || 0;
        }
        broadcast({ type: 'stats', ...stmts.getQueueStats.get() });
        broadcast({ type: 'worker_update', workerId, hashRate: msg.hashRate || 0 });
        break;
      }

      case 'prefix_match': {
        // Worker found a channel name whose derived prefix matches the target
        // Store it as a candidate key for verification with meshcore-decoder
        const { packetId, channelName, key, prefix } = msg;
        stmts.insertCandidate.run(packetId, channelName, key, prefix);
        broadcast({
          type: 'candidate_found',
          packetId,
          channelName,
          key,
          prefix,
        });
        broadcast({ type: 'candidates', candidates: stmts.getAllCandidates.all() });
        break;
      }

      case 'key_found': {
        // Confirmed working key (verified via meshcore-decoder)
        stmts.updatePacketStatus.run('cracked', msg.key, msg.channelName || null, msg.packetId);
        db.prepare("UPDATE work_chunks SET status = 'completed' WHERE packet_id = ? AND status != 'completed'")
          .run(msg.packetId);
        broadcast({ type: 'key_found', packetId: msg.packetId, key: msg.key, channelName: msg.channelName });
        broadcast({ type: 'stats', ...stmts.getQueueStats.get() });
        broadcast({ type: 'packets', packets: stmts.getPackets.all() });
        break;
      }

      case 'hashrate_update': {
        const w = workers.get(workerId);
        if (w) w.hashRate = msg.hashRate || 0;
        broadcast({ type: 'worker_update', workerId, hashRate: msg.hashRate || 0 });
        break;
      }
    }
  });

  ws.on('close', () => {
    workers.delete(workerId);
    broadcast({ type: 'worker_count', count: workers.size });
  });
});

// ── REST API ────────────────────────────────────────────────────────────────

app.get('/api/packets', (req, res) => {
  res.json(stmts.getPackets.all());
});

app.post('/api/packets', (req, res) => {
  const { rawData } = req.body;
  if (!rawData) return res.status(400).json({ error: 'rawData required' });

  const prefix = extractPrefixFromPacket(rawData);
  if (prefix === null) return res.status(400).json({ error: 'Could not extract prefix byte from packet' });

  const prefixHex = prefix.toString(16).padStart(2, '0');

  // Check against known channels with matching prefix
  const known = stmts.findByPrefix.all(prefixHex);
  if (known.length > 0) {
    // Try each known key — for now just report the first match
    const match = known[0];
    const result = stmts.insertPacket.run(rawData, prefix);
    stmts.updatePacketStatus.run('cracked', match.key, match.channel_name, result.lastInsertRowid);
    const packet = stmts.getPacketById.get(result.lastInsertRowid);
    broadcast({ type: 'packets', packets: stmts.getPackets.all() });
    return res.json({ packet, alreadyKnown: true, knownChannel: match });
  }

  const result = stmts.insertPacket.run(rawData, prefix);
  createWorkChunks(result.lastInsertRowid, prefix);
  const packet = stmts.getPacketById.get(result.lastInsertRowid);

  broadcast({ type: 'packets', packets: stmts.getPackets.all() });
  broadcast({ type: 'stats', ...stmts.getQueueStats.get() });

  res.json({ packet, alreadyKnown: false, prefixByte: prefixHex });
});

app.delete('/api/packets/:id', (req, res) => {
  db.prepare('DELETE FROM work_chunks WHERE packet_id = ?').run(req.params.id);
  db.prepare('DELETE FROM candidate_keys WHERE packet_id = ?').run(req.params.id);
  db.prepare('DELETE FROM packets WHERE id = ?').run(req.params.id);
  broadcast({ type: 'packets', packets: stmts.getPackets.all() });
  broadcast({ type: 'stats', ...stmts.getQueueStats.get() });
  res.json({ ok: true });
});

app.get('/api/channels', (req, res) => {
  res.json(stmts.getKnownChannels.all());
});

app.post('/api/channels', (req, res) => {
  let { channelName } = req.body;
  if (!channelName) return res.status(400).json({ error: 'channelName required' });

  // Derive key and prefix from channel name using MeshCore algorithm
  const derived = deriveAll(channelName);

  stmts.insertKnownChannel.run(derived.channelName, derived.key, derived.prefix);
  broadcast({ type: 'channels', channels: stmts.getKnownChannels.all() });
  res.json({ ok: true, ...derived });
});

app.delete('/api/channels/:id', (req, res) => {
  stmts.deleteKnownChannel.run(req.params.id);
  broadcast({ type: 'channels', channels: stmts.getKnownChannels.all() });
  res.json({ ok: true });
});

app.get('/api/candidates/:packetId', (req, res) => {
  res.json(stmts.getCandidates.all(req.params.packetId));
});

app.get('/api/candidates', (req, res) => {
  res.json(stmts.getAllCandidates.all());
});

app.get('/api/stats', (req, res) => {
  stmts.expireStaleChunks.run();
  const stats = stmts.getQueueStats.get();
  const workerList = [];
  for (const [id, w] of workers) {
    workerList.push({ id: id.substring(0, 8), hashRate: w.hashRate, chunksCompleted: w.chunksCompleted });
  }
  res.json({ ...stats, workers: workerList, workerCount: workers.size });
});

// ── Derive endpoint (for frontend auto-populate) ────────────────────────────
app.post('/api/derive', (req, res) => {
  const { channelName } = req.body;
  if (!channelName) return res.status(400).json({ error: 'channelName required' });
  res.json(deriveAll(channelName));
});

// ── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`MC-Keygen 2.0 running on http://localhost:${PORT}`);
});
