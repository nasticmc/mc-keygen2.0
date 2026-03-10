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

// ── Database Setup ──────────────────────────────────────────────────────────
const db = new Database('keygen.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_data TEXT NOT NULL,
    hash TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    cracked_key TEXT,
    channel_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    cracked_at DATETIME
  );

  CREATE TABLE IF NOT EXISTS known_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_name TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    key TEXT NOT NULL,
    prefix TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS work_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER NOT NULL,
    hash TEXT NOT NULL,
    range_start INTEGER NOT NULL,
    range_end INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    assigned_to TEXT,
    assigned_at DATETIME,
    completed_at DATETIME,
    FOREIGN KEY (packet_id) REFERENCES packets(id)
  );
`);

// ── Prepared Statements ─────────────────────────────────────────────────────
const stmts = {
  insertPacket: db.prepare('INSERT INTO packets (raw_data, hash) VALUES (?, ?)'),
  getPackets: db.prepare('SELECT * FROM packets ORDER BY created_at DESC'),
  getPacketById: db.prepare('SELECT * FROM packets WHERE id = ?'),
  updatePacketStatus: db.prepare('UPDATE packets SET status = ?, cracked_key = ?, channel_name = ?, cracked_at = CURRENT_TIMESTAMP WHERE id = ?'),
  getKnownChannels: db.prepare('SELECT * FROM known_channels ORDER BY channel_name'),
  insertKnownChannel: db.prepare('INSERT OR REPLACE INTO known_channels (channel_name, hash, key, prefix) VALUES (?, ?, ?, ?)'),
  deleteKnownChannel: db.prepare('DELETE FROM known_channels WHERE id = ?'),
  findByHash: db.prepare('SELECT * FROM known_channels WHERE hash = ?'),
  insertChunk: db.prepare('INSERT INTO work_chunks (packet_id, hash, range_start, range_end) VALUES (?, ?, ?, ?)'),
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
};

// ── Utility Functions ───────────────────────────────────────────────────────

function extractHash(rawData) {
  const cleaned = rawData.trim();
  // Try to extract hash from raw packet data
  // Supports hex-encoded packet data or raw hash strings
  const hexMatch = cleaned.match(/[0-9a-fA-F]{32,64}/);
  if (hexMatch) return hexMatch[0].toLowerCase();
  // If no hex hash found, hash the entire input as the target
  return crypto.createHash('md5').update(cleaned).digest('hex');
}

function generatePrefix(channelName) {
  return crypto.createHash('md5').update(channelName).digest('hex').substring(0, 8);
}

function generateKey(channelName) {
  return crypto.createHash('sha256').update(channelName).digest('hex');
}

const CHUNK_SIZE = 1_000_000; // 1M keys per chunk
const TOTAL_KEYSPACE = 256_000_000; // ~256M total keyspace to search

function createWorkChunks(packetId, hash) {
  const insert = db.transaction(() => {
    for (let start = 0; start < TOTAL_KEYSPACE; start += CHUNK_SIZE) {
      const end = Math.min(start + CHUNK_SIZE, TOTAL_KEYSPACE);
      stmts.insertChunk.run(packetId, hash, start, end);
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
        ws.send(JSON.stringify({ type: 'work', chunks }));
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

      case 'key_found': {
        stmts.updatePacketStatus.run('cracked', msg.key, msg.channelName || null, msg.packetId);
        // Mark remaining chunks as completed
        db.prepare("UPDATE work_chunks SET status = 'completed' WHERE packet_id = ? AND status != 'completed'")
          .run(msg.packetId);
        broadcast({ type: 'key_found', packetId: msg.packetId, key: msg.key });
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

// Get all packets
app.get('/api/packets', (req, res) => {
  res.json(stmts.getPackets.all());
});

// Upload a new packet
app.post('/api/packets', (req, res) => {
  const { rawData } = req.body;
  if (!rawData) return res.status(400).json({ error: 'rawData required' });

  const hash = extractHash(rawData);

  // Check against known keys first
  const known = stmts.findByHash.get(hash);
  if (known) {
    const result = stmts.insertPacket.run(rawData, hash);
    stmts.updatePacketStatus.run('cracked', known.key, known.channel_name, result.lastInsertRowid);
    const packet = stmts.getPacketById.get(result.lastInsertRowid);
    broadcast({ type: 'packets', packets: stmts.getPackets.all() });
    return res.json({ packet, alreadyKnown: true, knownChannel: known });
  }

  const result = stmts.insertPacket.run(rawData, hash);
  createWorkChunks(result.lastInsertRowid, hash);
  const packet = stmts.getPacketById.get(result.lastInsertRowid);

  broadcast({ type: 'packets', packets: stmts.getPackets.all() });
  broadcast({ type: 'stats', ...stmts.getQueueStats.get() });

  res.json({ packet, alreadyKnown: false });
});

// Delete a packet
app.delete('/api/packets/:id', (req, res) => {
  db.prepare('DELETE FROM work_chunks WHERE packet_id = ?').run(req.params.id);
  db.prepare('DELETE FROM packets WHERE id = ?').run(req.params.id);
  broadcast({ type: 'packets', packets: stmts.getPackets.all() });
  broadcast({ type: 'stats', ...stmts.getQueueStats.get() });
  res.json({ ok: true });
});

// Get all known channels
app.get('/api/channels', (req, res) => {
  res.json(stmts.getKnownChannels.all());
});

// Add a known channel
app.post('/api/channels', (req, res) => {
  const { channelName, hash, key, prefix } = req.body;
  if (!channelName) return res.status(400).json({ error: 'channelName required' });

  const finalHash = hash || generatePrefix(channelName);
  const finalKey = key || generateKey(channelName);
  const finalPrefix = prefix || generatePrefix(channelName);

  stmts.insertKnownChannel.run(channelName, finalHash, finalKey, finalPrefix);
  broadcast({ type: 'channels', channels: stmts.getKnownChannels.all() });
  res.json({ ok: true });
});

// Delete a known channel
app.delete('/api/channels/:id', (req, res) => {
  stmts.deleteKnownChannel.run(req.params.id);
  broadcast({ type: 'channels', channels: stmts.getKnownChannels.all() });
  res.json({ ok: true });
});

// Get queue stats
app.get('/api/stats', (req, res) => {
  stmts.expireStaleChunks.run();
  const stats = stmts.getQueueStats.get();
  const workerList = [];
  for (const [id, w] of workers) {
    workerList.push({ id: id.substring(0, 8), hashRate: w.hashRate, chunksCompleted: w.chunksCompleted });
  }
  res.json({ ...stats, workers: workerList, workerCount: workers.size });
});

// ── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`MC-Keygen 2.0 running on http://localhost:${PORT}`);
});
