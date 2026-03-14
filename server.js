const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const { MeshCorePacketDecoder } = require('@michaelhart/meshcore-decoder');

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
  return hash.subarray(0, 16);
}

function derivePrefix(keyBuffer) {
  const hash = crypto.createHash('sha256').update(keyBuffer).digest();
  return hash[0];
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

// ── MeshCore Decoder (Node.js) ───────────────────────────────────────────────

function decodePacket(hexData, channelKey) {
  let options;
  if (channelKey) {
    const keyStore = MeshCorePacketDecoder.createKeyStore({ channelSecrets: [channelKey.trim()] });
    options = { keyStore, attemptDecryption: true };
  }
  try {
    return MeshCorePacketDecoder.decode(hexData, options);
  } catch (err) {
    return { error: err.message };
  }
}

function extractChannelHash(hexData) {
  try {
    const decoded = MeshCorePacketDecoder.decode(hexData);
    const channelHash = decoded.payload?.decoded?.channelHash ?? null;
    return {
      channelHash,
      payloadType: decoded.payloadType,
      isValid: decoded.isValid,
      decoded,
    };
  } catch (err) {
    return { error: err.message };
  }
}

function tryDecrypt(hexData, channelKey) {
  const keyStore = MeshCorePacketDecoder.createKeyStore({ channelSecrets: [channelKey.trim()] });
  const options = { keyStore, attemptDecryption: true };
  try {
    const decoded = MeshCorePacketDecoder.decode(hexData, options);
    const payloadDecoded = decoded.payload?.decoded;
    const decrypted = payloadDecoded?.decrypted ?? payloadDecoded?.message ?? null;
    return {
      success: decrypted !== null,
      decoded,
      channelKey,
    };
  } catch (err) {
    return { error: err.message, success: false };
  }
}

// Auto-decrypt: try all candidate keys for a packet
function autoDecryptCandidates(packetId) {
  const packet = stmts.getPacketById.get(packetId);
  if (!packet || packet.status === 'cracked') return;

  const candidates = stmts.getCandidates.all(packetId);
  for (const candidate of candidates) {
    if (candidate.verified) continue;

    try {
      const result = tryDecrypt(packet.raw_data, candidate.key);
      db.prepare('UPDATE candidate_keys SET verified = 1, decode_success = ? WHERE id = ?')
        .run(result.success ? 1 : 0, candidate.id);

      if (result.success) {
        stmts.updatePacketStatus.run('cracked', candidate.key, candidate.channel_name, packetId);
        if (result.decoded) stmts.updatePacketDecrypted.run(JSON.stringify(result.decoded), packetId);
        db.prepare("UPDATE work_chunks SET status = 'completed' WHERE packet_id = ? AND status != 'completed'")
          .run(packetId);
        broadcast({ type: 'key_found', packetId, key: candidate.key, channelName: candidate.channel_name, decoded: result.decoded });
        broadcast({ type: 'stats', ...stmts.getQueueStats.get() });
        broadcast({ type: 'packets', packets: stmts.getPackets.all() });
        return result;
      }
    } catch (err) {
      console.error(`Decrypt failed for candidate ${candidate.id}:`, err.message);
    }
  }
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
    channel_hash TEXT,
    decoded_json TEXT,
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

// Migration: add decrypted_json column for storing decoded message content
try { db.exec('ALTER TABLE packets ADD COLUMN decrypted_json TEXT'); } catch {}

// ── Prepared Statements ─────────────────────────────────────────────────────
const stmts = {
  insertPacket: db.prepare('INSERT INTO packets (raw_data, prefix, channel_hash, decoded_json) VALUES (?, ?, ?, ?)'),
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
  updatePacketDecrypted: db.prepare('UPDATE packets SET decrypted_json = ? WHERE id = ?'),
  getDecodedPackets: db.prepare("SELECT * FROM packets WHERE status = 'cracked' ORDER BY cracked_at DESC"),
  unassignWorkerChunks: db.prepare(`
    UPDATE work_chunks
    SET status = 'pending', assigned_to = NULL, assigned_at = NULL
    WHERE status = 'assigned' AND assigned_to = ?
  `),
  tryAssignChunk: db.prepare(`
    UPDATE work_chunks
    SET status = 'assigned', assigned_to = ?, assigned_at = CURRENT_TIMESTAMP
    WHERE id = ? AND status = 'pending'
  `),
};

const assignPendingChunks = db.transaction((workerId, count) => {
  const available = stmts.getPendingChunks.all(count);
  const assigned = [];
  for (const chunk of available) {
    const result = stmts.tryAssignChunk.run(workerId, chunk.id);
    if (result.changes > 0) assigned.push(chunk);
  }
  return assigned;
});

// ── Work Chunk Generation ───────────────────────────────────────────────────
const CHUNK_SIZE = 500_000;

const CHARSETS = {
  alnum: 'abcdefghijklmnopqrstuvwxyz0123456789',
  full: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.',
};

function createWorkChunks(packetId, targetPrefix) {
  const charset = CHARSETS.alnum;
  const base = charset.length;
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
        const chunks = assignPendingChunks(workerId, msg.count || 1);
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
        const { packetId, channelName, key, prefix } = msg;
        const exists = db.prepare('SELECT 1 FROM candidate_keys WHERE packet_id = ? AND key = ? LIMIT 1')
          .get(packetId, key);
        if (!exists) {
          stmts.insertCandidate.run(packetId, channelName, key, prefix);
        }
        broadcast({
          type: 'candidate_found',
          packetId,
          channelName,
          key,
          prefix,
        });
        broadcast({ type: 'candidates', candidates: stmts.getAllCandidates.all() });

        // Auto-try decryption with this candidate
        const packet = stmts.getPacketById.get(packetId);
        if (packet && packet.status !== 'cracked') {
          try {
            const result = tryDecrypt(packet.raw_data, key);
            const candidateRow = db.prepare('SELECT id FROM candidate_keys WHERE packet_id = ? AND key = ? ORDER BY id DESC LIMIT 1')
              .get(packetId, key);
            if (candidateRow) {
              db.prepare('UPDATE candidate_keys SET verified = 1, decode_success = ? WHERE id = ?')
                .run(result.success ? 1 : 0, candidateRow.id);
            }

            if (result.success) {
              stmts.updatePacketStatus.run('cracked', key, channelName, packetId);
              if (result.decoded) stmts.updatePacketDecrypted.run(JSON.stringify(result.decoded), packetId);
              db.prepare("UPDATE work_chunks SET status = 'completed' WHERE packet_id = ? AND status != 'completed'")
                .run(packetId);
              broadcast({ type: 'key_found', packetId, key, channelName, decoded: result.decoded });
              broadcast({ type: 'stats', ...stmts.getQueueStats.get() });
              broadcast({ type: 'packets', packets: stmts.getPackets.all() });
            }
            broadcast({ type: 'candidates', candidates: stmts.getAllCandidates.all() });
          } catch (err) {
            console.error('Auto-decrypt error:', err.message);
          }
        }
        break;
      }

      case 'key_found': {
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
    stmts.unassignWorkerChunks.run(workerId);
    workers.delete(workerId);
    broadcast({ type: 'worker_count', count: workers.size });
    broadcast({ type: 'stats', ...stmts.getQueueStats.get() });
  });
});

// ── REST API ────────────────────────────────────────────────────────────────

app.get('/api/packets', (req, res) => {
  res.json(stmts.getPackets.all());
});

app.get('/api/packets/decoded', (req, res) => {
  res.json(stmts.getDecodedPackets.all());
});

// Re-run decoder on an already-cracked packet and store the result
app.post('/api/packets/:id/decode', async (req, res) => {
  const packet = stmts.getPacketById.get(parseInt(req.params.id));
  if (!packet) return res.status(404).json({ error: 'Packet not found' });
  if (!packet.cracked_key) return res.status(400).json({ error: 'Packet not yet cracked' });

  try {
    const result = await tryDecrypt(packet.raw_data, packet.cracked_key);
    if (result.decoded) stmts.updatePacketDecrypted.run(JSON.stringify(result.decoded), packet.id);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Upload a packet — decode it with meshcoredecoder to extract channelHash
app.post('/api/packets', (req, res) => {
  const { rawData } = req.body;
  if (!rawData) return res.status(400).json({ error: 'rawData required' });

  const hexData = rawData.trim().replace(/\s+/g, '');

  // Decode the packet to extract channelHash
  let decoded = null;
  let channelHash = null;
  let prefix = null;

  try {
    decoded = extractChannelHash(hexData);
    channelHash = decoded.channelHash;
    if (channelHash !== null && channelHash !== undefined) {
      prefix = parseInt(channelHash, 16);
    }
  } catch (err) {
    console.error('Decoder error:', err.message);
  }

  // If decoder couldn't extract channelHash, fall back to raw first byte
  if (prefix === null) {
    const hexMatch = hexData.match(/^([0-9a-fA-F]{2})/);
    if (hexMatch) {
      prefix = parseInt(hexMatch[1], 16);
    }
  }

  if (prefix === null) {
    return res.status(400).json({ error: 'Could not extract channel hash from packet' });
  }

  const prefixHex = prefix.toString(16).padStart(2, '0');

  // Check against known channels with matching prefix
  const known = stmts.findByPrefix.all(prefixHex);
  if (known.length > 0) {
    // Try to actually decrypt with each known key
    for (const match of known) {
      try {
        const decryptResult = tryDecrypt(hexData, match.key);
        if (decryptResult.success) {
          const result = stmts.insertPacket.run(hexData, prefix, channelHash, JSON.stringify(decoded));
          stmts.updatePacketStatus.run('cracked', match.key, match.channel_name, result.lastInsertRowid);
          if (decryptResult.decoded) stmts.updatePacketDecrypted.run(JSON.stringify(decryptResult.decoded), result.lastInsertRowid);
          const packet = stmts.getPacketById.get(result.lastInsertRowid);
          broadcast({ type: 'packets', packets: stmts.getPackets.all() });
          return res.json({ packet, alreadyKnown: true, knownChannel: match, decoded: decryptResult.decoded });
        }
      } catch (err) {
        console.error('Known key decrypt failed:', err.message);
      }
    }
  }

  const result = stmts.insertPacket.run(hexData, prefix, channelHash, decoded ? JSON.stringify(decoded) : null);
  createWorkChunks(result.lastInsertRowid, prefix);
  const packet = stmts.getPacketById.get(result.lastInsertRowid);

  broadcast({ type: 'packets', packets: stmts.getPackets.all() });
  broadcast({ type: 'stats', ...stmts.getQueueStats.get() });

  res.json({ packet, alreadyKnown: false, prefixByte: prefixHex, decoded });
});

app.delete('/api/packets/:id', (req, res) => {
  db.prepare('DELETE FROM work_chunks WHERE packet_id = ?').run(req.params.id);
  db.prepare('DELETE FROM candidate_keys WHERE packet_id = ?').run(req.params.id);
  db.prepare('DELETE FROM packets WHERE id = ?').run(req.params.id);
  broadcast({ type: 'packets', packets: stmts.getPackets.all() });
  broadcast({ type: 'stats', ...stmts.getQueueStats.get() });
  res.json({ ok: true });
});

// Decode a packet (without saving)
app.post('/api/decode', (req, res) => {
  const { hexData, channelKey } = req.body;
  if (!hexData) return res.status(400).json({ error: 'hexData required' });

  const result = decodePacket(hexData.trim().replace(/\s+/g, ''), channelKey);
  res.json(result);
});

// Try to decrypt a packet with a specific key
app.post('/api/decrypt', (req, res) => {
  const { hexData, channelKey } = req.body;
  if (!hexData || !channelKey) return res.status(400).json({ error: 'hexData and channelKey required' });

  const result = tryDecrypt(hexData.trim().replace(/\s+/g, ''), channelKey);
  res.json(result);
});

// Auto-decrypt all candidates for a packet
app.post('/api/packets/:id/auto-decrypt', (req, res) => {
  try {
    const result = autoDecryptCandidates(parseInt(req.params.id));
    res.json({ success: !!result, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/channels', (req, res) => {
  res.json(stmts.getKnownChannels.all());
});

app.post('/api/channels', (req, res) => {
  let { channelName } = req.body;
  if (!channelName) return res.status(400).json({ error: 'channelName required' });

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

app.post('/api/derive', (req, res) => {
  const { channelName } = req.body;
  if (!channelName) return res.status(400).json({ error: 'channelName required' });
  res.json(deriveAll(channelName));
});

// Decoder health check
app.get('/api/decoder-status', (req, res) => {
  res.json({ available: true, version: require('@michaelhart/meshcore-decoder/package.json').version });
});

// ── Start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`MC-Keygen 2.0 running on http://localhost:${PORT}`);
  const decoderVersion = require('@michaelhart/meshcore-decoder/package.json').version;
  console.log(`meshcoredecoder: available (v${decoderVersion})`);
});
