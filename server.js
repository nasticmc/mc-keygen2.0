const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { Worker } = require('worker_threads');
const os = require('os');
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
    const validation = validateDecryptedContent(decoded);
    return {
      success: decrypted !== null && validation.valid,
      decoded,
      channelKey,
      validation,
    };
  } catch (err) {
    return { error: err.message, success: false };
  }
}

function validateDecryptedContent(decodedPacket) {
  const payload = decodedPacket?.payload?.decoded;
  if (!payload) return { valid: false, reason: 'missing_payload' };

  const interestingPaths = ['decrypted', 'message', 'text', 'msg', 'content', 'payload'];
  const strings = [];

  function visit(value, path = '', depth = 0) {
    if (depth > 4 || strings.length > 20 || value === null || value === undefined) return;
    if (typeof value === 'string') {
      strings.push({ value, path });
      return;
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) visit(value[i], `${path}[${i}]`, depth + 1);
      return;
    }
    if (typeof value === 'object') {
      for (const [key, inner] of Object.entries(value)) {
        const nextPath = path ? `${path}.${key}` : key;
        visit(inner, nextPath, depth + 1);
      }
    }
  }

  for (const key of interestingPaths) {
    if (payload[key] !== undefined) visit(payload[key], key);
  }

  if (strings.length === 0) return { valid: false, reason: 'missing_text' };

  const best = strings.find(({ value }) => isReadableMessage(value));
  if (!best) return { valid: false, reason: 'non_readable_text' };
  return { valid: true, reason: 'ok', path: best.path };
}

function isReadableMessage(input) {
  if (typeof input !== 'string') return false;
  const value = input.trim();
  if (value.length < 2) return false;

  const allowedChars = /^[\x09\x0A\x0D\x20-\x7E\p{Extended_Pictographic}\uFE0F\u200D]+$/u;
  if (!allowedChars.test(value)) return false;

  const hasAsciiWord = /[A-Za-z0-9]/.test(value);
  const hasEmoji = /\p{Extended_Pictographic}/u.test(value);
  return hasAsciiWord || hasEmoji;
}

// Auto-decrypt: try all candidate keys for a packet
function autoDecryptCandidates(packetId) {
  const packet = stmts.getPacketById.get(packetId);
  if (!packet || packet.status === 'cracked') return;

  const candidates = stmts.getCandidates.all(packetId);
  for (const candidate of candidates) {
    if (candidate.verified || candidate.ignored) continue;

    try {
      const result = tryDecrypt(packet.raw_data, candidate.key);
      db.prepare('UPDATE candidate_keys SET verified = 1, decode_success = ? WHERE id = ?')
        .run(result.success ? 1 : 0, candidate.id);

      if (result.success) {
        stmts.updatePacketStatus.run('cracked', candidate.key, candidate.channel_name, packetId);
        if (result.decoded) stmts.updatePacketDecrypted.run(JSON.stringify(result.decoded), packetId);
        db.prepare('UPDATE packets SET chunk_gen_offset = keyspace_end WHERE id = ?').run(packetId);
        stmts.deletePacketAssigned.run(packetId);
        broadcast({ type: 'key_found', packetId, key: candidate.key, channelName: candidate.channel_name, decoded: result.decoded });
        broadcast({ type: 'stats', ...getQueueStats(), activeStats: getActiveJobStats() });
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
    charset TEXT DEFAULT 'lower',
    min_len INTEGER DEFAULT 1,
    max_len INTEGER DEFAULT 5,
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
    ignored INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (packet_id) REFERENCES packets(id)
  );
`);

// Indexes to avoid full table scans on hot-path queries
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_wc_status          ON work_chunks(status);
  CREATE INDEX IF NOT EXISTS idx_wc_packet_status   ON work_chunks(packet_id, status);
  CREATE INDEX IF NOT EXISTS idx_wc_expire          ON work_chunks(status, assigned_at);
  CREATE INDEX IF NOT EXISTS idx_wc_assigned_to     ON work_chunks(status, assigned_to);
`);

// Migration: add decrypted_json column for storing decoded message content
try { db.exec('ALTER TABLE packets ADD COLUMN decrypted_json TEXT'); } catch {}
try { db.exec("ALTER TABLE packets ADD COLUMN charset TEXT DEFAULT 'alnum'"); } catch {}
try { db.exec('ALTER TABLE packets ADD COLUMN min_len INTEGER DEFAULT 1'); } catch {}
try { db.exec('ALTER TABLE packets ADD COLUMN max_len INTEGER DEFAULT 5'); } catch {}
// Fix rows that got the wrong default (6) from the old migration — only if user never explicitly set a higher value
try { db.exec('UPDATE packets SET max_len = 5 WHERE max_len = 6 AND status = \'pending\''); } catch {}
try { db.exec('ALTER TABLE candidate_keys ADD COLUMN ignored INTEGER DEFAULT 0'); } catch {}
// Virtual chunk generation: chunk_gen_offset tracks the next unassigned index,
// keyspace_end tracks the total keyspace size. No pending rows are pre-generated.
try { db.exec('ALTER TABLE packets ADD COLUMN chunk_gen_offset INTEGER'); } catch {}
try { db.exec('ALTER TABLE packets ADD COLUMN keyspace_end INTEGER'); } catch {}

// Migration: delete old "pending" rows (virtual chunk system no longer uses them)
// and reset assigned rows on startup (workers are not connected yet).
// Also rewind packet cursors so orphaned keyspace ranges get re-assigned.
{
  const deleted = db.prepare("DELETE FROM work_chunks WHERE status = 'pending'").run().changes;
  // Rewind cursors for any assigned chunks before deleting them
  const orphanedAssigned = db.prepare(
    "SELECT packet_id, MIN(range_start) as min_start FROM work_chunks WHERE status = 'assigned' GROUP BY packet_id"
  ).all();
  for (const { packet_id, min_start } of orphanedAssigned) {
    const pkt = db.prepare('SELECT chunk_gen_offset FROM packets WHERE id = ?').get(packet_id);
    if (pkt && pkt.chunk_gen_offset > min_start) {
      db.prepare('UPDATE packets SET chunk_gen_offset = ? WHERE id = ?').run(min_start, packet_id);
      console.log(`[startup] rewound packet ${packet_id} cursor from ${pkt.chunk_gen_offset} to ${min_start}`);
    }
  }
  const reset = db.prepare("DELETE FROM work_chunks WHERE status = 'assigned'").run().changes;
  if (deleted + reset > 0) console.log(`[startup] cleaned up ${deleted} pending + ${reset} assigned chunk rows`);
  // Ensure all active packets have keyspace_end set
  const needInit = db.prepare("SELECT * FROM packets WHERE status != 'cracked' AND keyspace_end IS NULL").all();
  for (const p of needInit) {
    const cfg = { charset: p.charset || 'lower', minLen: p.min_len || 1, maxLen: p.max_len || 5 };
    const charsetKey = cfg.charset;
    const base = (charsetKey === 'alnum' ? 36 : charsetKey === 'lower' ? 26 : charsetKey === 'numeric' ? 10 : charsetKey === 'full' ? 65 : 26);
    let start = 0;
    for (let len = 1; len < cfg.minLen; len++) start += Math.pow(base, len);
    let end = start;
    for (let len = cfg.minLen; len <= cfg.maxLen; len++) end += Math.pow(base, len);
    // Start past completed work
    const completedMax = db.prepare("SELECT MAX(range_end) as max_end FROM work_chunks WHERE packet_id = ? AND status = 'completed'").get(p.id);
    const offset = (completedMax?.max_end != null) ? Math.max(start, completedMax.max_end) : start;
    db.prepare('UPDATE packets SET chunk_gen_offset = ?, keyspace_end = ? WHERE id = ?').run(offset, end, p.id);
    console.log(`[migration] initialized packet ${p.id} keyspace: offset=${offset} end=${end}`);
  }
}

// Candidate dedupe + uniqueness guard so high-volume prefix-match batches don't
// spend most of their time doing per-row existence checks.
try {
  db.exec(`
    DELETE FROM candidate_keys
    WHERE id IN (
      SELECT c1.id
      FROM candidate_keys c1
      JOIN candidate_keys c2
        ON c1.packet_id = c2.packet_id
       AND c1.key = c2.key
       AND c1.id > c2.id
    )
  `);
} catch {}
try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_ck_packet_key ON candidate_keys(packet_id, key)'); } catch {}

// ── Prepared Statements ─────────────────────────────────────────────────────
const stmts = {
  insertPacket: db.prepare('INSERT INTO packets (raw_data, prefix, channel_hash, decoded_json, charset, min_len, max_len) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  getPackets: db.prepare('SELECT * FROM packets ORDER BY created_at DESC'),
  getPacketById: db.prepare('SELECT * FROM packets WHERE id = ?'),
  updatePacketStatus: db.prepare('UPDATE packets SET status = ?, cracked_key = ?, channel_name = ?, cracked_at = CURRENT_TIMESTAMP WHERE id = ?'),
  getKnownChannels: db.prepare('SELECT * FROM known_channels ORDER BY channel_name'),
  insertKnownChannel: db.prepare('INSERT OR REPLACE INTO known_channels (channel_name, key, prefix) VALUES (?, ?, ?)'),
  deleteKnownChannel: db.prepare('DELETE FROM known_channels WHERE id = ?'),
  findByPrefix: db.prepare('SELECT * FROM known_channels WHERE prefix = ?'),
  insertAssignedChunk: db.prepare('INSERT INTO work_chunks (packet_id, target_prefix, range_start, range_end, charset, status, assigned_to, assigned_at) VALUES (?, ?, ?, ?, ?, \'assigned\', ?, CURRENT_TIMESTAMP)'),
  completeChunkByWorker: db.prepare("UPDATE work_chunks SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'assigned' AND assigned_to = ?"),
  getChunksByPacket: db.prepare('SELECT * FROM work_chunks WHERE packet_id = ?'),
  // Stats now compute pending virtually from packet keyspace offsets
  getAssignedCount: db.prepare("SELECT COUNT(*) as assigned FROM work_chunks WHERE status = 'assigned'"),
  getCompletedCount: db.prepare("SELECT COUNT(*) as completed FROM work_chunks WHERE status = 'completed'"),
  getActiveAssigned: db.prepare(`
    SELECT COUNT(*) as assigned FROM work_chunks w
    JOIN packets p ON p.id = w.packet_id
    WHERE w.status = 'assigned' AND p.status != 'cracked'
  `),
  getActiveCompleted: db.prepare(`
    SELECT COUNT(*) as completed FROM work_chunks w
    JOIN packets p ON p.id = w.packet_id
    WHERE w.status = 'completed' AND p.status != 'cracked'
  `),
  // Stale chunks: find them for recycling back into the virtual pool
  getStaleChunks: db.prepare(`
    SELECT id, packet_id, range_start FROM work_chunks
    WHERE status = 'assigned' AND assigned_at < datetime('now', '-10 minutes')
  `),
  deleteChunkById: db.prepare('DELETE FROM work_chunks WHERE id = ?'),
  insertCandidate: db.prepare('INSERT OR IGNORE INTO candidate_keys (packet_id, channel_name, key, prefix, verified, decode_success) VALUES (?, ?, ?, ?, 1, 1)'),
  getCandidates: db.prepare('SELECT * FROM candidate_keys WHERE packet_id = ? ORDER BY created_at DESC'),
  getAllCandidates: db.prepare('SELECT * FROM candidate_keys ORDER BY created_at DESC LIMIT 100'),
  updatePacketDecrypted: db.prepare('UPDATE packets SET decrypted_json = ? WHERE id = ?'),
  getDecodedPackets: db.prepare("SELECT * FROM packets WHERE status = 'cracked' ORDER BY cracked_at DESC"),
  // When a worker disconnects, delete its assigned chunks (virtual system will reassign the ranges)
  unassignWorkerChunks: db.prepare(`
    DELETE FROM work_chunks
    WHERE status = 'assigned' AND assigned_to = ?
  `),
  deletePacketAssigned: db.prepare("DELETE FROM work_chunks WHERE packet_id = ? AND status = 'assigned'"),
  countAssignedToWorker: db.prepare("SELECT COUNT(*) AS cnt FROM work_chunks WHERE status = 'assigned' AND assigned_to = ?"),
  getActivePackets: db.prepare("SELECT * FROM packets WHERE status != 'cracked' AND chunk_gen_offset IS NOT NULL AND keyspace_end IS NOT NULL"),
};

// ── Virtual Stats ────────────────────────────────────────────────────────────
// Pending chunks are computed from keyspace math, not DB rows.
function getQueueStats() {
  const assigned = stmts.getAssignedCount.get().assigned;
  const completed = stmts.getCompletedCount.get().completed;
  // Count virtual pending across all active packets
  let virtualPending = 0;
  for (const p of stmts.getActivePackets.all()) {
    virtualPending += Math.ceil(Math.max(0, p.keyspace_end - p.chunk_gen_offset) / CHUNK_SIZE);
  }
  const total = virtualPending + assigned + completed;
  return { pending: virtualPending, assigned, completed, total };
}

function getActiveJobStats() {
  const assigned = stmts.getActiveAssigned.get().assigned;
  const completed = stmts.getActiveCompleted.get().completed;
  let virtualPending = 0;
  for (const p of stmts.getActivePackets.all()) {
    virtualPending += Math.ceil(Math.max(0, p.keyspace_end - p.chunk_gen_offset) / CHUNK_SIZE);
  }
  const total = virtualPending + assigned + completed;
  return { pending: virtualPending, assigned, completed, total };
}

function persistWinningCandidate(packetId, channelName, key, prefix) {
  stmts.insertCandidate.run(packetId, channelName, key, prefix);
}

function markPacketCracked(packetId, channelName, key, decoded) {
  const current = stmts.getPacketById.get(packetId);
  if (!current || current.status === 'cracked') return false;

  console.log(`[FOUND] packet ${packetId} cracked — channel="${channelName}" key=${key.substring(0, 8)}...`);
  stmts.updatePacketStatus.run('cracked', key, channelName, packetId);
  if (decoded) stmts.updatePacketDecrypted.run(JSON.stringify(decoded), packetId);
  // Stop virtual generation and clean up assigned chunks for this packet
  db.prepare('UPDATE packets SET chunk_gen_offset = keyspace_end WHERE id = ?').run(packetId);
  stmts.deletePacketAssigned.run(packetId);
  broadcast({ type: 'key_found', packetId, key, channelName, decoded });
  broadcast({ type: 'stats', ...getQueueStats(), activeStats: getActiveJobStats() });
  broadcast({ type: 'packets', packets: stmts.getPackets.all() });
  broadcast({ type: 'candidates', candidates: stmts.getAllCandidates.all() });
  return true;
}

function findWinningCandidate(packet, matches, onDone) {
  const MAX_IN_FLIGHT = Math.max(1, DECODER_POOL_SIZE * 2);
  let index = 0;
  let inFlight = 0;
  let done = false;

  const finish = (winner) => {
    if (done) return;
    done = true;
    onDone(winner);
  };

  const schedule = () => {
    while (!done && inFlight < MAX_IN_FLIGHT && index < matches.length) {
      const match = matches[index++];
      inFlight++;
      decodeAsync(packet.raw_data, match.keyHex, (result) => {
        inFlight--;
        if (done) return;
        if (result.success) {
          finish({ match, result });
          return;
        }
        if (index >= matches.length && inFlight === 0) {
          finish(null);
          return;
        }
        schedule();
      });
    }
  };

  if (matches.length === 0) return finish(null);
  schedule();
}

// Recycle stale assigned chunks: delete the rows and rewind the packet's
// virtual cursor so those ranges will be reassigned to other workers.
// Release all assigned chunks for a worker back to the virtual pool.
function releaseWorkerChunks(workerId) {
  // Find the minimum range_start per packet to rewind cursors
  const rows = db.prepare(
    "SELECT packet_id, MIN(range_start) as min_start FROM work_chunks WHERE status = 'assigned' AND assigned_to = ? GROUP BY packet_id"
  ).all(workerId);

  // Delete the assigned rows — virtual system will regenerate the ranges
  stmts.unassignWorkerChunks.run(workerId);

  for (const { packet_id, min_start } of rows) {
    const packet = stmts.getPacketById.get(packet_id);
    if (packet && packet.chunk_gen_offset > min_start) {
      db.prepare('UPDATE packets SET chunk_gen_offset = ? WHERE id = ?').run(min_start, packet_id);
    }
  }
}

const completeChunksForWorker = db.transaction((workerId, chunkIds) => {
  let completedNow = 0;
  let alreadyCompletedOrMissing = 0;

  for (const chunkId of chunkIds) {
    const result = stmts.completeChunkByWorker.run(chunkId, workerId);
    if (result.changes > 0) completedNow += 1;
    else alreadyCompletedOrMissing += 1;
  }

  return { completedNow, alreadyCompletedOrMissing };
});

function recycleStaleChunks() {
  const stale = stmts.getStaleChunks.all();
  if (stale.length === 0) return 0;

  // Group by packet and find the minimum range_start per packet
  const rewindTo = new Map();
  for (const row of stale) {
    const current = rewindTo.get(row.packet_id);
    if (current === undefined || row.range_start < current) {
      rewindTo.set(row.packet_id, row.range_start);
    }
    stmts.deleteChunkById.run(row.id);
  }

  // Rewind each affected packet's cursor so the ranges get regenerated
  for (const [packetId, minStart] of rewindTo) {
    const packet = stmts.getPacketById.get(packetId);
    if (packet && packet.chunk_gen_offset > minStart) {
      db.prepare('UPDATE packets SET chunk_gen_offset = ? WHERE id = ?').run(minStart, packetId);
      console.log(`[stale] rewound packet ${packetId} cursor from ${packet.chunk_gen_offset} to ${minStart}`);
    }
  }

  return stale.length;
}

// Assign virtual chunks: compute ranges from packet keyspace on-the-fly,
// insert directly as "assigned" rows. No "pending" rows ever exist.
const assignVirtualChunks = db.transaction((workerId, count) => {
  const alreadyAssigned = stmts.countAssignedToWorker.get(workerId)?.cnt || 0;
  const capacity = Math.max(0, count - alreadyAssigned);
  if (capacity === 0) return [];

  const packets = stmts.getActivePackets.all();
  const assigned = [];

  for (const packet of packets) {
    if (assigned.length >= capacity) break;
    let offset = packet.chunk_gen_offset;
    const end = packet.keyspace_end;
    if (offset >= end) continue;

    while (assigned.length < capacity && offset < end) {
      const rangeEnd = Math.min(offset + CHUNK_SIZE, end);
      const result = stmts.insertAssignedChunk.run(
        packet.id, packet.prefix, offset, rangeEnd, packet.charset || 'lower', workerId
      );
      assigned.push({
        id: Number(result.lastInsertRowid),
        packet_id: packet.id,
        target_prefix: packet.prefix,
        range_start: offset,
        range_end: rangeEnd,
        charset: packet.charset || 'lower',
        status: 'assigned',
        assigned_to: workerId,
      });
      offset = rangeEnd;
    }
    // Advance the packet's cursor
    db.prepare('UPDATE packets SET chunk_gen_offset = ? WHERE id = ?').run(offset, packet.id);
  }

  return assigned;
});

// Assign exactly N chunks without checking alreadyAssigned.
// Used by request_work so the client always gets what it asked for.
const assignExactChunks = db.transaction((workerId, count) => {
  const packets = stmts.getActivePackets.all();
  const assigned = [];

  for (const packet of packets) {
    if (assigned.length >= count) break;
    let offset = packet.chunk_gen_offset;
    const end = packet.keyspace_end;
    if (offset >= end) continue;

    while (assigned.length < count && offset < end) {
      const rangeEnd = Math.min(offset + CHUNK_SIZE, end);
      const result = stmts.insertAssignedChunk.run(
        packet.id, packet.prefix, offset, rangeEnd, packet.charset || 'lower', workerId
      );
      assigned.push({
        id: Number(result.lastInsertRowid),
        packet_id: packet.id,
        target_prefix: packet.prefix,
        range_start: offset,
        range_end: rangeEnd,
        charset: packet.charset || 'lower',
        status: 'assigned',
        assigned_to: workerId,
      });
      offset = rangeEnd;
    }
    db.prepare('UPDATE packets SET chunk_gen_offset = ? WHERE id = ?').run(offset, packet.id);
  }

  return assigned;
});

// ── Decoder Worker Pool ──────────────────────────────────────────────────────
// Runs MeshCorePacketDecoder in worker threads so the main event loop is never
// blocked while verifying prefix-match candidates.  Pool size = min(cpus-1, 4).
const DECODER_POOL_SIZE = Math.max(1, os.cpus().length - 1);
const _decoderPool = [];
const _decoderQueue = [];
let _decoderTaskId = 0;
const _decoderCallbacks = new Map();

function _spawnDecoderWorker() {
  const w = new Worker(path.join(__dirname, 'decoder-worker.js'));
  w.busy = false;
  w.currentTaskId = null;
  w.on('message', ({ id, ...result }) => {
    w.busy = false;
    w.currentTaskId = null;
    const cb = _decoderCallbacks.get(id);
    if (cb) { _decoderCallbacks.delete(id); cb(result); }
    _drainDecoderPool(w);
  });
  const _failInFlight = (reason) => {
    if (w.currentTaskId != null) {
      const cb = _decoderCallbacks.get(w.currentTaskId);
      if (cb) { _decoderCallbacks.delete(w.currentTaskId); cb({ success: false, error: reason }); }
      w.currentTaskId = null;
    }
    w.busy = false;
  };
  w.on('error', (err) => {
    console.error('[decoder-pool] worker error:', err.message);
    _failInFlight(err.message);
    const idx = _decoderPool.indexOf(w);
    if (idx >= 0) _decoderPool.splice(idx, 1);
    const replacement = _spawnDecoderWorker();
    _decoderPool.push(replacement);
    _drainDecoderPool(replacement);
  });
  w.on('exit', (code) => {
    if (code === 0) return;
    console.error(`[decoder-pool] worker exited with code ${code}, restarting`);
    _failInFlight(`worker exited with code ${code}`);
    const idx = _decoderPool.indexOf(w);
    if (idx >= 0) { _decoderPool.splice(idx, 1); _decoderPool.push(_spawnDecoderWorker()); }
  });
  return w;
}

function _drainDecoderPool(worker) {
  if (!worker.busy && _decoderQueue.length > 0) {
    const task = _decoderQueue.shift();
    worker.busy = true;
    worker.currentTaskId = task.id;
    worker.postMessage(task);
  }
}

function decodeAsync(hexData, channelKey, cb) {
  const id = _decoderTaskId++;
  _decoderCallbacks.set(id, cb);
  const free = _decoderPool.find(w => !w.busy);
  if (free) {
    free.busy = true;
    free.currentTaskId = id;
    free.postMessage({ id, hexData, channelKey });
  } else {
    _decoderQueue.push({ id, hexData, channelKey });
  }
}

for (let i = 0; i < DECODER_POOL_SIZE; i++) _decoderPool.push(_spawnDecoderWorker());

// ── Work Chunk Generation ───────────────────────────────────────────────────
const CHUNK_SIZE = 64_000_000;

const CHARSETS = {
  alnum: 'abcdefghijklmnopqrstuvwxyz0123456789',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  numeric: '0123456789',
  full: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.',
};

function clampInt(value, min, max, fallback) {
  const parsed = parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

function normalizeCrackConfig(input = {}) {
  const charsetKey = CHARSETS[input.charset] ? input.charset : 'lower';
  const minLen = clampInt(input.minLen, 1, 10, 1);
  const maxLen = clampInt(input.maxLen, minLen, 10, 5);
  return {
    charset: charsetKey,
    minLen,
    maxLen,
  };
}

function indexRangeForLengths(base, minLen, maxLen) {
  let start = 0;
  for (let len = 1; len < minLen; len++) start += Math.pow(base, len);
  let span = 0;
  for (let len = minLen; len <= maxLen; len++) span += Math.pow(base, len);
  return { start, end: start + span };
}

// ── Virtual Chunk System ────────────────────────────────────────────────────
// Instead of pre-inserting thousands of "pending" rows, we store
// chunk_gen_offset (next unassigned index) and keyspace_end on each packet.
// Chunks are computed on-the-fly and inserted directly as "assigned".

function initWorkForPacket(packetId, targetPrefix, crackConfig = {}) {
  const cfg = normalizeCrackConfig(crackConfig);
  const base = CHARSETS[cfg.charset].length;
  const { start: totalStart, end: totalEnd } = indexRangeForLengths(base, cfg.minLen, cfg.maxLen);

  // Start past any already-completed work for this charset (handles retries)
  const completedMaxRow = db.prepare(
    "SELECT MAX(range_end) as max_end FROM work_chunks WHERE packet_id = ? AND status = 'completed' AND charset = ?"
  ).get(packetId, cfg.charset);
  const genStart = (completedMaxRow?.max_end != null)
    ? Math.max(totalStart, completedMaxRow.max_end)
    : totalStart;

  const totalChunks = Math.ceil((totalEnd - genStart) / CHUNK_SIZE);
  db.prepare('UPDATE packets SET chunk_gen_offset = ?, keyspace_end = ? WHERE id = ?')
    .run(genStart, totalEnd, packetId);

  console.log(`[chunks] packet ${packetId}: keyspace ready — ${totalChunks} virtual chunks (${genStart}→${totalEnd})`);
  return cfg;
}

// ── Connected Workers ───────────────────────────────────────────────────────
const workers = new Map();
const PREFETCH_LOW_WATERMARK = 0.25;

// ── Human-Readable Worker Names ─────────────────────────────────────────────
// Mirrors the client-side workerIdToName() so server logs show the same names.
const _workerNameAnimals = [
  'Bear', 'Cat', 'Crow', 'Deer', 'Duck', 'Fox', 'Frog', 'Goat', 'Hawk',
  'Hare', 'Lynx', 'Lion', 'Mole', 'Moose', 'Newt', 'Orca', 'Owl', 'Puma',
  'Slug', 'Swan', 'Toad', 'Vole', 'Wolf', 'Wren', 'Yak',
];
const _workerNameEmotions = [
  'Bold', 'Brave', 'Bright', 'Calm', 'Cozy', 'Dark', 'Eager', 'Faint',
  'Fuzzy', 'Glad', 'Giddy', 'Happy', 'Jolly', 'Keen', 'Merry', 'Proud',
  'Sharp', 'Snug', 'Sunny', 'Swift', 'Tense', 'Warm', 'Wild', 'Zesty', 'Cool',
];

function workerIdToName(id) {
  let h = 5381;
  for (let i = 0; i < id.length; i++) h = (h * 33 ^ id.charCodeAt(i)) >>> 0;
  const emotion = _workerNameEmotions[h % _workerNameEmotions.length];
  const animal  = _workerNameAnimals[Math.floor(h / _workerNameEmotions.length) % _workerNameAnimals.length];
  return `${emotion} ${animal}`;
}

function wName(id) { return id ? `${workerIdToName(id)} (${id})` : 'unregistered'; }

const HEARTBEAT_INTERVAL_MS = 15_000;
const HEARTBEAT_MISS_LIMIT = 4;

function formatHashRate(n) {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(2) + ' GH/s';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + ' MH/s';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + ' KH/s';
  return n + ' H/s';
}

const serverStatus = {
  phase: 'idle',
  detail: 'Server booted',
  updatedAt: Date.now(),
};

function setServerStatus(phase, detail) {
  serverStatus.phase = phase;
  serverStatus.detail = detail;
  serverStatus.updatedAt = Date.now();
  console.log(`[server] ${phase}: ${detail}`);
  broadcast({ type: 'server_status', ...serverStatus });
}

function makeWorkerId(inputId) {
  const normalized = String(inputId || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 24);
  return normalized || crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}


function maybePushWork(workerId, reason = 'scheduler') {
  const worker = workers.get(workerId);
  if (!worker || !worker.ws || worker.ws.readyState !== 1) return 0;

  const desired = worker.desiredInFlight || 1;
  const assigned = stmts.countAssignedToWorker.get(workerId)?.cnt || 0;

  // Push when assigned drops below 3/4 of desired — keeps the pipeline
  // well-fed without pushing on every single chunk_complete.
  const pushThreshold = Math.max(1, Math.ceil(desired * 3 / 4));
  if (assigned >= pushThreshold) return 0;

  const chunks = assignVirtualChunks(workerId, desired);

  if (chunks.length > 0) {
    // Include raw packet data so clients can attempt decryption themselves
    const packetRawData = {};
    for (const chunk of chunks) {
      if (!(chunk.packet_id in packetRawData)) {
        const pkt = stmts.getPacketById.get(chunk.packet_id);
        if (pkt) packetRawData[chunk.packet_id] = pkt.raw_data;
      }
    }
    worker.ws.send(JSON.stringify({
      type: 'work',
      chunks,
      charset: CHARSETS[chunks[0]?.charset] || CHARSETS.alnum,
      packetRawData,
    }));
    console.log(`[sched] pushed ${chunks.length} chunk(s) to ${wName(workerId)} (${reason})`);
    broadcastStats();
  }

  return chunks.length;
}

function broadcast(data) {
  const msg = JSON.stringify(data);
  for (const ws of wss.clients) {
    if (ws.readyState === 1) ws.send(msg);
  }
}

// Throttled stats broadcast — avoids hammering COUNT(*) queries on every event
let _lastStatsBroadcastMs = 0;
function broadcastStats() {
  const now = Date.now();
  if (now - _lastStatsBroadcastMs < 500) return;
  _lastStatsBroadcastMs = now;
  broadcast({ type: 'stats', ...getQueueStats(), activeStats: getActiveJobStats(), totalHashRate: getTotalHashRate() });
}

// Periodic health report — helps diagnose slowdowns over long runs
setInterval(() => {
  const m = process.memoryUsage();
  const s = getQueueStats();
  const workerDetails = [];
  for (const [id, w] of workers) {
    const assigned = stmts.countAssignedToWorker.get(id)?.cnt || 0;
    workerDetails.push(`${workerIdToName(id)}:${formatHashRate(w.hashRate)}/a=${assigned}/d=${w.chunksCompleted}`);
  }
  console.log(`[health] workers=${workers.size} pending=${s.pending} assigned=${s.assigned} completed=${s.completed} rate=${formatHashRate(getTotalHashRate())} rss=${Math.round(m.rss / 1024 / 1024)}MB`);
  if (workerDetails.length > 0) console.log(`[health] ${workerDetails.join(' | ')}`);
}, 30_000);

// ── WebSocket Handler ───────────────────────────────────────────────────────
// ── WebSocket Keepalive ─────────────────────────────────────────────────────
// Heartbeat runs every 15s and allows 4 misses before termination. This keeps
// idle proxies alive while being tolerant of transient network jitter.
const heartbeatInterval = setInterval(() => {
  wss.clients.forEach(client => {
    if (client.isAlive === false) {
      client.missedPings = (client.missedPings || 0) + 1;
      if (client.workerId) {
        console.warn(`[ws] missed heartbeat ${wName(client.workerId)} miss=${client.missedPings}/${HEARTBEAT_MISS_LIMIT}`);
      }
      if (client.missedPings >= HEARTBEAT_MISS_LIMIT) {
        if (client.workerId) console.warn(`[ws] terminating unresponsive worker ${wName(client.workerId)}`);
        client.terminate();
        return;
      }
    } else {
      client.missedPings = 0;
    }
    client.isAlive = false;
    client.ping();
  });
}, HEARTBEAT_INTERVAL_MS);
wss.on('close', () => clearInterval(heartbeatInterval));

function markConnectionAlive(ws) {
  ws.isAlive = true;
  ws.missedPings = 0;
}

// ── Periodic Stats Broadcast ────────────────────────────────────────────────
function getTotalHashRate() {
  let total = 0;
  for (const w of workers.values()) total += w.hashRate;
  return total;
}

setInterval(() => {
  if (wss.clients.size > 0) broadcast({ type: 'stats', ...getQueueStats(), activeStats: getActiveJobStats(), totalHashRate: getTotalHashRate() });
}, 2000);

wss.on('connection', (ws) => {
  let workerId = null;
  markConnectionAlive(ws);
  ws.on('pong', () => markConnectionAlive(ws));
  setServerStatus('connection', 'Worker socket connected. Waiting for registration...');

  function registerWorker(requestedId) {
    const nextWorkerId = makeWorkerId(requestedId);
    if (workerId && workerId === nextWorkerId) return;

    const existing = workers.get(nextWorkerId);
    if (existing && existing.ws !== ws) {
      try { existing.ws.terminate(); } catch {}
      workers.delete(nextWorkerId);
      releaseWorkerChunks(nextWorkerId);
    }

    if (workerId && workerId !== nextWorkerId) {
      workers.delete(workerId);
      releaseWorkerChunks(workerId);
    }

    workerId = nextWorkerId;
    ws.workerId = workerId;
    workers.set(workerId, { ws, chunksCompleted: 0, hashRate: 0, desiredInFlight: 1, lastWorkerUpdateAt: 0 });

    console.log(`[ws] worker registered ${wName(workerId)} total=${workers.size}`);
    setServerStatus('worker_registered', `Worker ${workerIdToName(workerId)} is online (${workers.size} total).`);
    ws.send(JSON.stringify({ type: 'worker_hello', workerId }));
    ws.send(JSON.stringify({ type: 'server_status', ...serverStatus }));
    broadcast({ type: 'worker_count', count: workers.size });
  }

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // Any successfully parsed message proves the client is still responsive,
    // even if it skipped websocket pong frames while busy processing work.
    markConnectionAlive(ws);

    const _t0 = Date.now();
    try {
    switch (msg.type) {
      case 'worker_register': {
        registerWorker(msg.clientId);
        break;
      }

      case 'request_work': {
        if (!workerId) registerWorker(msg.clientId);
        const requestedCount = Math.max(1, Math.min(64, parseInt(msg.count, 10) || 1));
        const expired = recycleStaleChunks();
        if (expired > 0) console.log(`[stale] recycled ${expired} stale chunk(s) back to virtual pool`);
        // Assign exactly what the client asked for — client manages its own
        // pipeline depth via topUpWorkQueue / minAhead.  Don't factor in
        // alreadyAssigned; that count can drift from reality and cause
        // under-assignment.
        const chunks = assignExactChunks(workerId, requestedCount);
        const packetRawData = {};
        for (const chunk of chunks) {
          if (!(chunk.packet_id in packetRawData)) {
            const pkt = stmts.getPacketById.get(chunk.packet_id);
            if (pkt) packetRawData[chunk.packet_id] = pkt.raw_data;
          }
        }
        const dbAssigned = stmts.countAssignedToWorker.get(workerId)?.cnt || 0;
        console.log(`[work] ${wName(workerId)} requested=${requestedCount} → sending ${chunks.length} chunk(s) (db_assigned=${dbAssigned})`);
        ws.send(JSON.stringify({
          type: 'work',
          solicited: true,
          chunks,
          charset: CHARSETS[chunks[0]?.charset] || CHARSETS.alnum,
          packetRawData,
        }));
        broadcastStats();
        break;
      }

      case 'chunk_complete': {
        if (!workerId) registerWorker(msg.clientId);
        const rawIds = Array.isArray(msg.chunkIds)
          ? msg.chunkIds
          : (msg.chunkId != null ? [msg.chunkId] : []);
        const chunkIds = [...new Set(rawIds.map(id => parseInt(id, 10)).filter(Number.isFinite))];
        if (chunkIds.length === 0) break;

        const { completedNow, alreadyCompletedOrMissing } = completeChunksForWorker(workerId, chunkIds);
        const completionNote = alreadyCompletedOrMissing > 0
          ? ` (${alreadyCompletedOrMissing} chunk${alreadyCompletedOrMissing !== 1 ? 's' : ''} already completed, reassigned, or recycled)`
          : '';
        const worker = workers.get(workerId);
        if (worker) {
          worker.chunksCompleted += completedNow;
          worker.hashRate = msg.hashRate || 0;
        }
        const remainingAssigned = stmts.countAssignedToWorker.get(workerId)?.cnt || 0;
        console.log(`[done] ${wName(workerId)} chunks=${chunkIds.length} completed_now=${completedNow} total_done=${worker?.chunksCompleted || '?'} remaining=${remainingAssigned} rate=${formatHashRate(msg.hashRate || 0)}${completionNote}`);
        // Don't push work here — let the client pull via request_work.
        // Server pushes caused assigned count to diverge from what the
        // client actually had queued (push messages piled up in network
        // buffer while the GPU loop starved the event loop).
        broadcastStats();
        broadcast({ type: 'worker_update', workerId, hashRate: msg.hashRate || 0 });
        break;
      }

      case 'prefix_match': {
        const { packetId, channelName, key, prefix } = msg;
        const packet = stmts.getPacketById.get(packetId);
        if (packet && packet.status !== 'cracked') {
          decodeAsync(packet.raw_data, key, (result) => {
            if (result.success) {
              persistWinningCandidate(packetId, channelName, key, prefix);
              broadcast({ type: 'candidate_found', packetId, channelName, key, prefix });
              markPacketCracked(packetId, channelName, key, result.decoded);
            }
          });
        }
        break;
      }

      case 'prefix_match_batch': {
        const { packetId: batchPacketId, matches: batchMatches } = msg;
        const batchPacket = stmts.getPacketById.get(batchPacketId);
        if (!batchPacket || batchPacket.status === 'cracked') break;

        // If a client already decoded a match, validate it then skip the decoder pool
        const preDecoded = batchMatches.find(m => {
          if (!m.clientDecoded) return false;
          const v = validateDecryptedContent(m.clientDecoded);
          return v.valid;
        });
        if (preDecoded) {
          persistWinningCandidate(batchPacketId, preDecoded.channelName, preDecoded.keyHex, preDecoded.prefixHex);
          broadcast({ type: 'candidate_found', packetId: batchPacketId, channelName: preDecoded.channelName, key: preDecoded.keyHex, prefix: preDecoded.prefixHex });
          markPacketCracked(batchPacketId, preDecoded.channelName, preDecoded.keyHex, preDecoded.clientDecoded);
          break;
        }

        findWinningCandidate(batchPacket, batchMatches, (winner) => {
          if (!winner) return;
          const { match, result } = winner;
          persistWinningCandidate(batchPacketId, match.channelName, match.keyHex, match.prefixHex);
          broadcast({ type: 'candidate_found', packetId: batchPacketId, channelName: match.channelName, key: match.keyHex, prefix: match.prefixHex });
          markPacketCracked(batchPacketId, match.channelName, match.keyHex, result.decoded);
        });
        break;
      }

      case 'hashrate_update': {
        if (!workerId) registerWorker(msg.clientId);
        const w = workers.get(workerId);
        if (w) {
          w.hashRate = msg.hashRate || 0;
          // Throttle broadcasts to once per second per worker to avoid an
          // O(workers²) message storm when many clients are active.
          const now = Date.now();
          if (now - w.lastWorkerUpdateAt >= 1000) {
            w.lastWorkerUpdateAt = now;
            broadcast({ type: 'worker_update', workerId, hashRate: w.hashRate });
          }
        }
        break;
      }

      case 'keepalive': {
        // Application-level ping from client — keep the connection marked alive
        // so the heartbeat doesn't terminate it even if a WebSocket ping/pong
        // frame was dropped by an intermediate proxy.
        markConnectionAlive(ws);
        if (!workerId && msg.clientId) registerWorker(msg.clientId);
        break;
      }
    }
    } catch (err) {
      console.error(`[ws-error] unhandled error in ${msg.type} handler (${wName(workerId)}):`, err.message);
    }
    const _elapsed = Date.now() - _t0;
    if (_elapsed > 100) console.warn(`[ws-slow] ${msg.type} took ${_elapsed}ms (${wName(workerId)})`);
  });

  ws.on('close', () => {
    if (!workerId) return;
    const w = workers.get(workerId);
    releaseWorkerChunks(workerId);
    workers.delete(workerId);
    console.log(`[ws] worker disconnected ${wName(workerId)} chunks=${w?.chunksCompleted ?? 0} total=${workers.size}`);
    setServerStatus('worker_disconnected', `Worker ${workerIdToName(workerId)} disconnected. ${workers.size} workers online.`);
    broadcast({ type: 'worker_removed', workerId });
    broadcast({ type: 'worker_count', count: workers.size });
    broadcastStats();
  });
});

// ── REST API ────────────────────────────────────────────────────────────────

app.get('/api/config', (req, res) => {
  res.json({
    chunkSize: CHUNK_SIZE,
    charsets: Object.fromEntries(Object.entries(CHARSETS).map(([k, v]) => [k, v.length])),
  });
});

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
  const { rawData, crackConfig } = req.body;
  if (!rawData) return res.status(400).json({ error: 'rawData required' });
  const cfg = normalizeCrackConfig(crackConfig);

  const hexData = rawData.trim().replace(/\s+/g, '');

  // Decode the packet to extract channelHash
  let decoded = null;
  let channelHash = null;
  let prefix = null;

  try {
    decoded = extractChannelHash(hexData);
    channelHash = decoded.channelHash;
    if (channelHash !== null && channelHash !== undefined) {
      // Decoder may return channelHash as a number (decimal) or a hex string
      prefix = typeof channelHash === 'number' ? channelHash : parseInt(channelHash, 16);
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
          const result = stmts.insertPacket.run(hexData, prefix, channelHash, JSON.stringify(decoded), cfg.charset, cfg.minLen, cfg.maxLen);
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

  const result = stmts.insertPacket.run(hexData, prefix, channelHash, decoded ? JSON.stringify(decoded) : null, cfg.charset, cfg.minLen, cfg.maxLen);
  initWorkForPacket(result.lastInsertRowid, prefix, cfg);
  const packet = stmts.getPacketById.get(result.lastInsertRowid);

  broadcast({ type: 'packets', packets: stmts.getPackets.all() });
  broadcastStats();

  res.json({ packet, alreadyKnown: false, prefixByte: prefixHex, decoded });
});

app.delete('/api/packets/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id' });
  if (!stmts.getPacketById.get(id)) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM work_chunks WHERE packet_id = ?').run(id);
  db.prepare('DELETE FROM candidate_keys WHERE packet_id = ?').run(id);
  db.prepare('DELETE FROM packets WHERE id = ?').run(id);
  broadcast({ type: 'packets', packets: stmts.getPackets.all() });
  broadcastStats();
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

app.post('/api/packets/:id/retry', (req, res) => {
  const packetId = parseInt(req.params.id);
  const packet = stmts.getPacketById.get(packetId);
  if (!packet) return res.status(404).json({ error: 'Packet not found' });

  const channelName = (req.body?.channelName || packet.channel_name || '').trim();
  const cfg = normalizeCrackConfig({
    charset: req.body?.crackConfig?.charset || packet.charset,
    minLen: req.body?.crackConfig?.minLen || packet.min_len,
    maxLen: req.body?.crackConfig?.maxLen || packet.max_len,
  });
  if (channelName) {
    db.prepare('UPDATE candidate_keys SET ignored = 1 WHERE packet_id = ? AND channel_name = ?')
      .run(packetId, channelName);
  }

  db.prepare("UPDATE packets SET status = 'pending', cracked_key = NULL, channel_name = NULL, cracked_at = NULL, decrypted_json = NULL WHERE id = ?")
    .run(packetId);
  db.prepare('UPDATE packets SET charset = ?, min_len = ?, max_len = ? WHERE id = ?')
    .run(cfg.charset, cfg.minLen, cfg.maxLen, packetId);
  // Only delete unfinished chunks — preserve completed ranges so we don't re-crack them
  db.prepare("DELETE FROM work_chunks WHERE packet_id = ? AND status != 'completed'")
    .run(packetId);
  initWorkForPacket(packetId, packet.prefix, cfg);

  broadcast({ type: 'packets', packets: stmts.getPackets.all() });
  broadcast({ type: 'candidates', candidates: stmts.getAllCandidates.all() });
  broadcastStats();

  res.json({ ok: true, ignoredChannel: channelName || null, crackConfig: cfg });
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
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid id' });
  const result = stmts.deleteKnownChannel.run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
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
  recycleStaleChunks();
  const stats = getQueueStats();
  const activeStats = getActiveJobStats();
  const workerList = [];
  for (const [id, w] of workers) {
    workerList.push({ id: id.substring(0, 8), hashRate: w.hashRate, chunksCompleted: w.chunksCompleted });
  }
  res.json({ ...stats, activeStats, workers: workerList, workerCount: workers.size, totalHashRate: getTotalHashRate() });
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
  console.log(`decoder pool: ${DECODER_POOL_SIZE} worker thread${DECODER_POOL_SIZE > 1 ? 's' : ''} (${os.cpus().length} CPU cores)`);

});
