// ── MC-Keygen 2.0 Frontend ──────────────────────────────────────────────────

// ── Worker Name Generator ────────────────────────────────────────────────────
// Maps a raw worker ID to a deterministic two-word "Animal Emotion" display name.
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
  // djb2 hash for stable, well-distributed index
  let h = 5381;
  for (let i = 0; i < id.length; i++) h = (h * 33 ^ id.charCodeAt(i)) >>> 0;
  const emotion = _workerNameEmotions[h % _workerNameEmotions.length];
  const animal  = _workerNameAnimals[Math.floor(h / _workerNameEmotions.length) % _workerNameAnimals.length];
  return `${emotion} ${animal}`;
}

// ── Client Console Logger ───────────────────────────────────────────────────
function clog(msg) {
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  console.log(`[mc ${ts}] ${msg}`);
}

let ws = null;
let cracker = null;
let cracking = false;
let loopRunning = false;
let currentCharset = 'abcdefghijklmnopqrstuvwxyz';
let serverChunkSize = 500000;
let lastMeasuredHashRate = 0;
let _smoothedHashRate = 0;
let _wsReconnectCount = 0;
let _wsConnectStartedAt = 0;
let _gpuRetryAttemptedAfterLoss = false;

const PERF_STORAGE_KEYS = {
  workBatchCount: 'mc-worker-work-batch-count',
  deviceMode: 'mc-worker-device-mode',
  dispatchScale: 'mc-worker-gpu-dispatch-scale',
  yieldIntervalMs: 'mc-worker-gpu-yield-interval',
  mapTimeoutMs: 'mc-worker-gpu-map-timeout',
  fallbackPolicy: 'mc-worker-gpu-fallback-policy',
};

// Exponential moving average for hash rate display — smooths out per-chunk spikes.
// alpha=0.25 → ~4 samples of memory (~4–8 s at current update frequency).
function smoothHashRate(newRate) {
  if (_smoothedHashRate === 0) {
    _smoothedHashRate = newRate; // fast-start only; stop resets directly
  } else {
    _smoothedHashRate = 0.25 * newRate + 0.75 * _smoothedHashRate;
  }
  return Math.round(_smoothedHashRate);
}
let persistedClientId = localStorage.getItem('mc-worker-client-id') || '';
let lastCrackingStatus = 'Idle.';
let lastWsMessageAt = 0;

// ── HTTP Transport ──────────────────────────────────────────────────────────
// All client→server communication uses HTTP POST. WebSocket is receive-only
// (server pushes: stats, key_found, work pushes, broadcasts).
async function apiPost(path, body) {
  const maxRetries = 3;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const res = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.ok) return res.json();
      if (res.status >= 500 && attempt < maxRetries - 1) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }
      throw new Error(`HTTP ${res.status}`);
    } catch (err) {
      if (attempt < maxRetries - 1) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }
      throw err;
    }
  }
}

async function fetchWork() {
  const data = await apiPost('/api/worker/request-work', {
    clientId: getClientId(),
    count: batchCount(),
  });
  return data;
}

const charsetByKey = {
  alnum: 'abcdefghijklmnopqrstuvwxyz0123456789',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  numeric: '0123456789',
  full: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.',
};

// ── Tab Navigation ──────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
  });
});

// ── WebSocket Connection ────────────────────────────────────────────────────
// Close code reference: https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent/code
const WS_CLOSE_CODES = {
  1000: 'Normal Closure', 1001: 'Going Away', 1002: 'Protocol Error',
  1003: 'Unsupported Data', 1005: 'No Status', 1006: 'Abnormal Closure',
  1007: 'Invalid Frame', 1008: 'Policy Violation', 1009: 'Message Too Big',
  1010: 'Extension Required', 1011: 'Internal Error', 1012: 'Service Restart',
  1013: 'Try Again Later', 1015: 'TLS Handshake Failed',
};

async function connectWebSocket() {
  // Register worker via HTTP first
  try {
    const reg = await apiPost('/api/worker/register', { clientId: getClientId() });
    setClientId(reg.workerId);
    document.getElementById('worker-id').textContent = `ID: ${workerIdToName(reg.workerId)}`;
    document.getElementById('connection-status').textContent = 'Connected';
    document.getElementById('connection-status').className = 'connected';
    setCrackingStatus(`Worker registered as ${workerIdToName(reg.workerId)}. Ready.`);
    clog(`worker registered via HTTP as ${workerIdToName(reg.workerId)}`);
  } catch (err) {
    clog(`HTTP registration failed: ${err.message} — retrying in 2s`);
    document.getElementById('connection-status').textContent = 'Disconnected';
    document.getElementById('connection-status').className = 'disconnected';
    setTimeout(connectWebSocket, 2000);
    return;
  }

  // WebSocket is receive-only — server pushes stats, key_found, etc.
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${protocol}//${location.host}`;
  _wsConnectStartedAt = Date.now();
  clog(`websocket connecting to ${url} (receive-only, attempt #${_wsReconnectCount + 1})`);
  ws = new WebSocket(url);

  ws.onopen = () => {
    const handshakeMs = Date.now() - _wsConnectStartedAt;
    _wsReconnectCount++;
    clog(`websocket connected in ${handshakeMs}ms (receive-only, reconnect #${_wsReconnectCount})`);
    lastWsMessageAt = Date.now();
    // Register on WS too so server can associate the WS connection for pushes
    ws.send(JSON.stringify({ type: 'worker_register', clientId: getClientId() }));
    if (cracking && !loopRunning) {
      clog('restarting cracking loop after reconnect');
      runCrackingLoop();
    }
  };

  ws.onerror = (event) => {
    clog(`websocket error — readyState=${ws.readyState} (0=CONNECTING 1=OPEN 2=CLOSING 3=CLOSED) url=${ws.url}`);
    if (navigator.onLine !== undefined) clog(`  navigator.onLine=${navigator.onLine}`);
    if (navigator.connection) {
      const c = navigator.connection;
      clog(`  network type=${c.effectiveType || c.type || '?'} downlink=${c.downlink ?? '?'}Mbps rtt=${c.rtt ?? '?'}ms`);
    }
  };

  ws.onclose = (event) => {
    const codeName = WS_CLOSE_CODES[event.code] || 'Unknown';
    const reason = event.reason ? ` reason="${event.reason}"` : '';
    const silentMs = lastWsMessageAt > 0 ? Date.now() - lastWsMessageAt : -1;
    clog(`websocket closed — code=${event.code} (${codeName})${reason} clean=${event.wasClean} silentFor=${silentMs}ms`);
    if (!event.wasClean) {
      clog(`  unclean close — possible proxy drop, network change, or server crash`);
    }
    // WS is non-critical now — cracking continues via HTTP. Just reconnect for pushes.
    clearInterval(ws._keepAliveTimer);
    setTimeout(() => {
      // Reconnect WS only (HTTP registration already done)
      const protocol2 = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url2 = `${protocol2}//${location.host}`;
      _wsConnectStartedAt = Date.now();
      clog(`websocket reconnecting to ${url2} (receive-only)`);
      const newWs = new WebSocket(url2);
      newWs.onopen = ws.onopen;
      newWs.onerror = ws.onerror;
      newWs.onclose = ws.onclose;
      newWs.onmessage = ws.onmessage;
      newWs._keepAliveTimer = setInterval(() => {
        const silentMs2 = lastWsMessageAt > 0 ? Date.now() - lastWsMessageAt : -1;
        clog(`keepalive tick — readyState=${newWs.readyState} cracking=${cracking} loopRunning=${loopRunning} silentFor=${silentMs2}ms`);
      }, 30000);
      ws = newWs;
    }, 2000);
  };

  ws._keepAliveTimer = setInterval(() => {
    const silentMs = lastWsMessageAt > 0 ? Date.now() - lastWsMessageAt : -1;
    clog(`keepalive tick — readyState=${ws.readyState} cracking=${cracking} loopRunning=${loopRunning} silentFor=${silentMs}ms`);
  }, 30000);

  ws.onmessage = (event) => {
    lastWsMessageAt = Date.now();
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (err) {
      clog(`ws message parse error: ${err.message} — raw(64): ${String(event.data).slice(0, 64)}`);
      return;
    }
    switch (msg.type) {
      case 'worker_count':
        document.getElementById('worker-count').textContent = `Workers: ${msg.count}`;
        break;
      case 'stats':
        updateStats(msg);
        break;
      case 'packets':
        renderPackets(msg.packets);
        break;
      case 'channels':
        renderChannels(msg.channels);
        break;
      case 'candidate_found':
        showNotification(`Prefix match: ${msg.channelName} — trying decryption...`);
        setCrackingStatus(`Prefix match found for packet #${msg.packetId} (${msg.channelName}). Validating decode...`);
        break;
      case 'candidates':
        renderCandidates(msg.candidates);
        break;
      case 'key_found':
        showNotification(`Decrypted! Packet #${msg.packetId}: channel ${msg.channelName}`);
        setCrackingStatus(`Packet #${msg.packetId} cracked with ${msg.channelName}.`);
        loadDecodedPackets();
        break;
      case 'worker_update':
        updateWorkerDisplay(msg.workerId, msg.hashRate);
        break;
      case 'worker_hello':
        // Server confirmed WS association
        clog(`WS worker_hello received for ${workerIdToName(msg.workerId)}`);
        break;
      case 'server_status':
        updateServerStatus(msg);
        break;
      case 'worker_removed':
        workerData.delete(msg.workerId);
        refreshWorkerDisplay();
        break;
      case 'work':
        // Unsolicited push work is ignored — we use HTTP for work requests now
        clog(`work push received (${msg.chunks?.length || 0} chunks) — ignored (using HTTP)`);
        break;
      default:
        clog(`ws unknown message type: "${msg.type}"`);
        break;
    }
  };
}

function isMobile() {
  const mode = localStorage.getItem(PERF_STORAGE_KEYS.deviceMode) || 'auto';
  if (mode === 'desktop') return false;
  if (mode === 'mobile') return true;
  return /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || window.innerWidth < 768;
}

function batchCount() {
  return parseInt(document.getElementById('work-batch-count')?.value, 10) || (isMobile() ? 1 : 16);
}

function clampNumber(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function getGpuTuningSettings() {
  const dispatchScale = clampNumber(document.getElementById('gpu-dispatch-scale')?.value, 0.1, 1.0, isMobile() ? 0.25 : 1.0);
  const yieldIntervalMs = clampNumber(document.getElementById('gpu-yield-interval')?.value, 0, 5000, isMobile() ? 100 : 500);
  const mapTimeoutMs = clampNumber(document.getElementById('gpu-map-timeout')?.value, 1000, 120000, 30000);
  const fallbackPolicy = document.getElementById('gpu-fallback-policy')?.value || 'retry_once';
  const deviceMode = document.getElementById('device-perf-mode')?.value || 'auto';
  return { dispatchScale, yieldIntervalMs, mapTimeoutMs, fallbackPolicy, deviceMode };
}

function applyPerfDefaults() {
  const batchInput = document.getElementById('work-batch-count');
  const deviceMode = document.getElementById('device-perf-mode');
  const dispatchScale = document.getElementById('gpu-dispatch-scale');
  const yieldInterval = document.getElementById('gpu-yield-interval');
  const mapTimeout = document.getElementById('gpu-map-timeout');
  const fallbackPolicy = document.getElementById('gpu-fallback-policy');

  if (deviceMode) deviceMode.value = localStorage.getItem(PERF_STORAGE_KEYS.deviceMode) || 'auto';

  if (batchInput) {
    const saved = localStorage.getItem(PERF_STORAGE_KEYS.workBatchCount);
    batchInput.value = saved || (isMobile() ? 1 : batchInput.value || 16);
  }
  if (dispatchScale) {
    const saved = localStorage.getItem(PERF_STORAGE_KEYS.dispatchScale);
    dispatchScale.value = saved || (isMobile() ? '0.25' : '1.00');
  }
  if (yieldInterval) {
    const saved = localStorage.getItem(PERF_STORAGE_KEYS.yieldIntervalMs);
    yieldInterval.value = saved || (isMobile() ? '100' : '500');
  }
  if (mapTimeout) mapTimeout.value = localStorage.getItem(PERF_STORAGE_KEYS.mapTimeoutMs) || '30000';
  if (fallbackPolicy) fallbackPolicy.value = localStorage.getItem(PERF_STORAGE_KEYS.fallbackPolicy) || 'retry_once';
}

function bindPerfControlPersistence() {
  const bindings = [
    ['work-batch-count', PERF_STORAGE_KEYS.workBatchCount],
    ['device-perf-mode', PERF_STORAGE_KEYS.deviceMode],
    ['gpu-dispatch-scale', PERF_STORAGE_KEYS.dispatchScale],
    ['gpu-yield-interval', PERF_STORAGE_KEYS.yieldIntervalMs],
    ['gpu-map-timeout', PERF_STORAGE_KEYS.mapTimeoutMs],
    ['gpu-fallback-policy', PERF_STORAGE_KEYS.fallbackPolicy],
  ];
  for (const [id, key] of bindings) {
    const el = document.getElementById(id);
    if (!el) continue;
    const handler = () => {
      localStorage.setItem(key, String(el.value));
      if (id === 'device-perf-mode') {
        applyPerfDefaults();
      }
    };
    el.addEventListener('change', handler);
    el.addEventListener('input', handler);
  }
}

function getClientId() {
  if (!persistedClientId) {
    persistedClientId = `client-${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
    localStorage.setItem('mc-worker-client-id', persistedClientId);
  }
  return persistedClientId;
}

function setClientId(id) {
  if (!id) return;
  persistedClientId = id;
  localStorage.setItem('mc-worker-client-id', id);
}

function updateServerStatus(status) {
  const phase = status.phase ? `(${status.phase}) ` : '';
  const detail = status.detail || 'Server active.';
  setCrackingStatus(`Server ${phase}${detail}`);
}

// ── Stats ───────────────────────────────────────────────────────────────────
function updateStats(stats) {
  // Use active job stats (non-cracked packets only) so completed/pending reflect current work
  const active = stats.activeStats || stats;

  document.getElementById('stat-pending').textContent = formatNumber(active.pending);
  document.getElementById('stat-assigned').textContent = formatNumber(active.assigned);
  document.getElementById('stat-completed').textContent = formatNumber(active.completed);

  const total = active.total || 1;
  const pct = total > 0 ? Math.round((active.completed / total) * 100) : 0;
  document.getElementById('progress-bar').style.width = `${pct}%`;
  document.getElementById('progress-text').textContent = `${pct}% (${active.completed}/${total})`;

  const hashRate = stats.totalHashRate ?? 0;
  if (stats.totalHashRate !== undefined && (!loopRunning || hashRate > 0)) {
    const displayRate = smoothHashRate(hashRate);
    document.getElementById('stat-hashrate').textContent = formatHashRate(displayRate);
  }

  // ETA based on remaining chunks × chunk size ÷ smoothed hash rate
  const remaining = (active.pending + active.assigned) * serverChunkSize;
  const eta = _smoothedHashRate > 0 && remaining > 0 ? remaining / _smoothedHashRate : Infinity;
  const etaEl = document.getElementById('stat-eta');
  if (etaEl) etaEl.textContent = formatETA(eta);

  // Update keyspace display to show remaining candidates (decreases as work completes)
  const ksEl = document.getElementById('stat-keyspace-size');
  if (ksEl && active.total > 0) ksEl.textContent = formatNumber(remaining);

  // Candidate stats bar
  if (stats.candidatesFound !== undefined) {
    const foundEl = document.getElementById('stat-candidates-found');
    const testedEl = document.getElementById('stat-candidates-tested');
    if (foundEl) foundEl.textContent = stats.candidatesFound;
    if (testedEl) testedEl.textContent = stats.candidatesTested;
  }
}

function formatNumber(n) {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(1) + 'B';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

function formatETA(seconds) {
  if (!isFinite(seconds) || seconds <= 0) return '—';
  if (seconds < 60) return '< 1m';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h >= 24 * 7) return '> 1wk';
  if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// Convert SQLite UTC timestamp (YYYY-MM-DD HH:MM:SS) to local time string
function formatLocalTime(ts) {
  if (!ts) return 'Unknown';
  // SQLite stores UTC without 'Z'; append it so Date parses correctly as UTC
  const normalized = ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z';
  return new Date(normalized).toLocaleString();
}

function formatHashRate(n) {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(2) + ' GH/s';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + ' MH/s';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + ' KH/s';
  return n + ' H/s';
}

// ── Workers Display ─────────────────────────────────────────────────────────
const workerData = new Map();

let _lastWorkerJson = '';
function refreshWorkerDisplay() {
  const json = JSON.stringify([...workerData]);
  if (json === _lastWorkerJson) return;
  _lastWorkerJson = json;
  const container = document.getElementById('workers-list');
  container.innerHTML = '';

  for (const [id, rate] of workerData) {
    const card = document.createElement('div');
    card.className = 'worker-card';
    card.innerHTML = `
      <div class="worker-id">${workerIdToName(id)}</div>
      <div class="worker-rate">${formatHashRate(rate)}</div>
    `;
    container.appendChild(card);
  }
}

function updateWorkerDisplay(workerId, hashRate) {
  workerData.set(workerId, hashRate);
  refreshWorkerDisplay();
}


// ── Packets Table ───────────────────────────────────────────────────────────
let _lastPacketsJson = '';
function renderPackets(packets) {
  const json = JSON.stringify(packets);
  if (json === _lastPacketsJson) return;
  _lastPacketsJson = json;
  const tbody = document.getElementById('packets-table');
  tbody.innerHTML = '';

  for (const p of packets) {
    const tr = document.createElement('tr');
    const badgeClass = p.status === 'cracked' ? 'badge-cracked' : p.status === 'cracking' ? 'badge-cracking' : 'badge-pending';
    const prefixHex = p.prefix.toString(16).padStart(2, '0');
    const channelHash = p.channel_hash || prefixHex;
    tr.innerHTML = `
      <td>${p.id}</td>
      <td>0x${channelHash}</td>
      <td><span class="badge ${badgeClass}">${p.status}</span></td>
      <td>${p.channel_name || '-'}</td>
      <td title="${p.cracked_key || ''}">${p.cracked_key ? p.cracked_key.substring(0, 16) + '...' : '-'}</td>
      <td>${formatLocalTime(p.created_at)}</td>
      <td>
        <button class="btn-sm" onclick="deletePacket(${p.id})">Delete</button>
        ${p.status !== 'cracked'
          ? `<button class="btn-sm" onclick="joinPacket(${p.id}, '${escapeAttr(p.charset || 'lower')}', ${p.min_len || 1}, ${p.max_len || 5})">Join</button> <button class="btn-sm" onclick="autoDecrypt(${p.id})">Try Decrypt</button> <button class="btn-sm" onclick="retryPacket(${p.id}, '')">Retry / Change Keyspace</button>`
          : `<button class="btn-sm btn-warning" onclick="retryPacket(${p.id}, '${escapeAttr(p.channel_name || '')}')">Retry (Ignore Channel)</button>`}
      </td>
    `;
    tbody.appendChild(tr);
  }

  // Update active packet summary shown near the crack button
  const activePacket = packets.find(p => p.status === 'pending' || p.status === 'cracking');
  const summaryEl = document.getElementById('active-packet-summary');
  if (summaryEl) {
    if (activePacket) {
      const charsetLen = CHARSET_LENS[activePacket.charset] || 26;
      const minLen = activePacket.min_len || 1;
      const maxLen = activePacket.max_len || 5;
      const ksSize = calculateKeyspaceSize(charsetLen, minLen, maxLen);
      const prefixHex = activePacket.prefix ? activePacket.prefix.toString(16).padStart(2, '0') : '??';
      const channelHash = activePacket.channel_hash || prefixHex;
      const badgeClass = activePacket.status === 'cracking' ? 'badge-cracking' : 'badge-pending';
      summaryEl.innerHTML = `<span class="badge ${badgeClass}">${activePacket.status}</span> Packet #${activePacket.id} &middot; 0x${channelHash} &middot; charset: <strong>${activePacket.charset || 'lower'}</strong> &middot; length: <strong>${minLen}&ndash;${maxLen}</strong> &middot; ~<strong>${formatNumber(ksSize)}</strong> candidates`;
      summaryEl.classList.remove('hidden');
    } else {
      summaryEl.classList.add('hidden');
    }
  }
}

async function deletePacket(id) {
  await fetch(`/api/packets/${id}`, { method: 'DELETE' });
}

async function autoDecrypt(id) {
  try {
    const res = await fetch(`/api/packets/${id}/auto-decrypt`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showNotification(`Decrypted packet #${id}!`);
    } else {
      showNotification(`No candidates decrypted packet #${id} yet.`);
    }
  } catch (err) {
    console.error('Auto-decrypt failed:', err);
  }
}

function joinPacket(id, charset, minLen, maxLen) {
  const charsetEl = document.getElementById('keyspace-charset');
  const minEl     = document.getElementById('keyspace-min-len');
  const maxEl     = document.getElementById('keyspace-max-len');
  if (charsetEl) charsetEl.value = charset || 'lower';
  if (minEl)     minEl.value     = minLen  || 1;
  if (maxEl)     maxEl.value     = maxLen  || 5;
  updateKeyspaceEstimate();
  showNotification(`Joined packet #${id} (${charset}, ${minLen}–${maxLen} chars). Starting worker…`);
  if (!cracking) document.getElementById('btn-start-cracking').click();
}

async function retryPacket(id, channelName) {
  const channel = channelName || '';
  const crackConfig = getCrackConfigFromUI();
  setCrackingStatus(`Retrying packet #${id}${channel ? ` and ignoring ${channel}` : ''}...`);
  try {
    const res = await fetch(`/api/packets/${id}/retry`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ channelName: channel, crackConfig })
    });
    const data = await res.json();
    if (data.error) {
      showNotification(`Retry failed for packet #${id}: ${data.error}`);
      return;
    }
    showNotification(`Packet #${id} reset for retry${data.ignoredChannel ? ` (ignored ${data.ignoredChannel})` : ''}.`);
    setCrackingStatus(`Packet #${id} queued with ${crackConfig.charset} length ${crackConfig.minLen}-${crackConfig.maxLen}.`);
  } catch (err) {
    showNotification(`Retry failed for packet #${id}: ${err.message}`);
  }
}

// ── Candidates Table ────────────────────────────────────────────────────────
let _lastCandidatesJson = '';
function renderCandidates(candidates) {
  const json = JSON.stringify(candidates);
  if (json === _lastCandidatesJson) return;
  _lastCandidatesJson = json;
  const tbody = document.getElementById('candidates-table');
  tbody.innerHTML = '';

  for (const c of candidates) {
    const tr = document.createElement('tr');
    const verifiedBadge = c.verified
      ? (c.decode_success ? '<span class="badge badge-cracked">Yes</span>' : '<span class="badge badge-pending">No</span>')
      : '<span class="badge">Pending</span>';
    const decryptBadge = c.decode_success
      ? '<span class="badge badge-cracked">Success</span>'
      : (c.verified ? '<span class="badge badge-pending">Failed</span>' : '-');
    tr.innerHTML = `
      <td>#${c.packet_id}</td>
      <td>${c.channel_name}</td>
      <td title="${c.key}">${c.key.substring(0, 20)}...</td>
      <td>0x${c.prefix}</td>
      <td>${verifiedBadge}</td>
      <td>${decryptBadge}</td>
      <td>${formatLocalTime(c.created_at)}</td>
    `;
    tbody.appendChild(tr);
  }
}

// ── Channels Table ──────────────────────────────────────────────────────────
function renderChannels(channels) {
  const tbody = document.getElementById('channels-table');
  tbody.innerHTML = '';

  for (const c of channels) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${c.channel_name}</td>
      <td title="${c.key}">${c.key.substring(0, 20)}...</td>
      <td>0x${c.prefix}</td>
      <td><button class="btn-sm" onclick="deleteChannel(${c.id})">Delete</button></td>
    `;
    tbody.appendChild(tr);
  }
}

async function deleteChannel(id) {
  await fetch(`/api/channels/${id}`, { method: 'DELETE' });
}

// ── Decoded Packets Tab ─────────────────────────────────────────────────────
async function loadDecodedPackets() {
  try {
    const res = await fetch('/api/packets/decoded');
    const packets = await res.json();
    renderDecodedPackets(packets);
  } catch (err) {
    console.error('Failed to load decoded packets:', err);
  }
}

function renderDecodedPackets(packets) {
  const container = document.getElementById('decoded-packets-list');
  const empty = document.getElementById('decoded-empty');
  container.innerHTML = '';

  if (packets.length === 0) {
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');

  for (const p of packets) {
    const card = document.createElement('div');
    card.className = 'decoded-card';

    let decoded = null;
    try {
      decoded = p.decrypted_json ? JSON.parse(p.decrypted_json) : null;
    } catch {}

    const crackedAt = formatLocalTime(p.cracked_at);
    const keyShort = p.cracked_key ? p.cracked_key.substring(0, 16) + '...' : '-';

    let messageHtml = '';
    if (decoded) {
      const highlighted = extractMessageFields(decoded);
      if (highlighted.length > 0) {
        messageHtml = `<div class="decoded-message-fields">${highlighted.map(({ label, value }) =>
          `<div class="decoded-field"><span class="decoded-field-label">${label}</span><span class="decoded-field-value">${escapeHtml(String(value))}</span></div>`
        ).join('')}</div>`;
      }
      const jsonId = `json-${p.id}`;
      messageHtml += `
        <button class="btn-sm decoded-toggle" onclick="toggleJson('${jsonId}')">View Raw JSON</button>
        <pre id="${jsonId}" class="json-output hidden">${escapeHtml(JSON.stringify(decoded, null, 2))}</pre>
      `;
    } else {
      messageHtml = `
        <p class="decoded-no-data">No decoded content stored.</p>
        <button class="btn-sm btn-decode-now" onclick="decodeNow(${p.id})">Decode Now</button>
        <div id="decode-now-result-${p.id}"></div>
      `;
    }

    card.innerHTML = `
      <div class="decoded-card-header">
        <span class="decoded-card-id">Packet #${p.id}</span>
        ${p.channel_name ? `<span class="badge badge-cracked">${escapeHtml(p.channel_name)}</span>` : ''}
        <span class="decoded-card-time">${crackedAt}</span>
      </div>
      <div class="decoded-card-key">Key: <span title="${p.cracked_key || ''}">${keyShort}</span></div>
      <div class="decoded-card-body">${messageHtml}</div>
    `;
    container.appendChild(card);
  }
}

function extractMessageFields(decoded) {
  const interesting = ['message', 'text', 'msg', 'content', 'sender', 'from', 'source',
    'type', 'payloadType', 'channelName', 'node', 'snr', 'rssi', 'timestamp'];
  const fields = [];

  function search(obj, path) {
    if (typeof obj !== 'object' || obj === null) return;
    for (const [k, v] of Object.entries(obj)) {
      const key = k.toLowerCase();
      if (interesting.some(name => key === name || key.includes(name))) {
        if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
          fields.push({ label: k, value: v });
        }
      }
      if (typeof v === 'object' && v !== null && fields.length < 12) {
        search(v, path + '.' + k);
      }
    }
  }
  search(decoded, '');
  return fields;
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeAttr(str) {
  return String(str || '').replace(/'/g, '&#39;');
}

function toggleJson(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('hidden');
}

async function decodeNow(packetId) {
  const resultEl = document.getElementById(`decode-now-result-${packetId}`);
  resultEl.textContent = 'Decoding...';
  try {
    const res = await fetch(`/api/packets/${packetId}/decode`, { method: 'POST' });
    const data = await res.json();
    if (data.error) {
      resultEl.textContent = `Error: ${data.error}`;
    } else {
      await loadDecodedPackets();
    }
  } catch (err) {
    resultEl.textContent = `Error: ${err.message}`;
  }
}

// ── Upload Packet ───────────────────────────────────────────────────────────
document.getElementById('btn-upload').addEventListener('click', async () => {
  const rawData = document.getElementById('raw-packet').value.trim();
  if (!rawData) return;

  const resultBox = document.getElementById('upload-result');
  resultBox.classList.remove('hidden', 'success', 'info', 'error');

  const crackConfig = getCrackConfigFromUI();

  try {
    const res = await fetch('/api/packets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawData, crackConfig })
    });
    const data = await res.json();

    if (data.error) {
      resultBox.classList.add('error');
      resultBox.textContent = data.error;
    } else if (data.alreadyKnown) {
      resultBox.classList.add('success');
      resultBox.textContent = `Decrypted! Channel: ${data.knownChannel.channel_name}, Key: ${data.knownChannel.key}`;
    } else {
      resultBox.classList.add('info');
      const hashInfo = data.decoded?.channelHash ? `Channel hash: 0x${data.decoded.channelHash}` : `Prefix: 0x${data.prefixByte}`;
      resultBox.textContent = `Packet queued (ID: ${data.packet.id}). ${hashInfo}. Work chunks created.`;
    }
    resultBox.classList.remove('hidden');
    document.getElementById('raw-packet').value = '';
  } catch (err) {
    resultBox.classList.add('error');
    resultBox.textContent = `Error: ${err.message}`;
    resultBox.classList.remove('hidden');
  }
});

// ── Add Channel (auto-derive key & prefix) ──────────────────────────────────
let deriveTimeout = null;
document.getElementById('channel-name').addEventListener('input', (e) => {
  const name = e.target.value.trim();
  clearTimeout(deriveTimeout);
  if (!name) {
    document.getElementById('channel-key').value = '';
    document.getElementById('channel-prefix').value = '';
    return;
  }
  deriveTimeout = setTimeout(async () => {
    try {
      const res = await fetch('/api/derive', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ channelName: name })
      });
      const data = await res.json();
      document.getElementById('channel-key').value = data.key;
      document.getElementById('channel-prefix').value = '0x' + data.prefix;
    } catch (err) {
      console.error('Derive failed:', err);
    }
  }, 300);
});

document.getElementById('btn-add-channel').addEventListener('click', async () => {
  const channelName = document.getElementById('channel-name').value.trim();
  if (!channelName) return;

  try {
    await fetch('/api/channels', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ channelName })
    });
    document.getElementById('channel-name').value = '';
    document.getElementById('channel-key').value = '';
    document.getElementById('channel-prefix').value = '';
  } catch (err) {
    console.error('Failed to add channel:', err);
  }
});

// ── Packet Decoder Tab ──────────────────────────────────────────────────────
document.getElementById('btn-decode').addEventListener('click', async () => {
  const hexData = document.getElementById('decode-hex').value.trim();
  if (!hexData) return;

  const channelKey = document.getElementById('decode-key').value.trim() || undefined;
  const resultBox = document.getElementById('decode-result');
  const jsonBox = document.getElementById('decode-json');

  resultBox.classList.remove('hidden', 'success', 'info', 'error');
  jsonBox.classList.add('hidden');

  try {
    const res = await fetch('/api/decode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hexData, channelKey })
    });
    const data = await res.json();

    if (data.error) {
      resultBox.classList.add('error');
      resultBox.textContent = `Decode error: ${data.error}`;
    } else {
      resultBox.classList.add('success');
      const payloadType = data.payloadType !== undefined ? `Type: ${data.payloadType}` : '';
      const channelHash = data.payload?.decoded?.channelHash;
      const hashInfo = channelHash != null ? ` | Channel Hash: 0x${typeof channelHash === 'number' ? channelHash.toString(16).padStart(2, '0') : channelHash}` : '';
      resultBox.textContent = `Decoded successfully. ${payloadType}${hashInfo}`;
      jsonBox.textContent = JSON.stringify(data, null, 2);
      jsonBox.classList.remove('hidden');
    }
    resultBox.classList.remove('hidden');
  } catch (err) {
    resultBox.classList.add('error');
    resultBox.textContent = `Error: ${err.message}`;
    resultBox.classList.remove('hidden');
  }
});

// ── Cracking Controls ───────────────────────────────────────────────────────
async function initCracker() {
  const gpuStatus = document.getElementById('gpu-status');
  const startBtn = document.getElementById('btn-start-cracking');

  // Disable start button until the cracker is ready — clicking before init
  // completes would leave cracker as null and crash processChunks.
  startBtn.disabled = true;

  cracker = new GPUCracker();
  const gpuOk = await cracker.init();
  _gpuRetryAttemptedAfterLoss = false;

  if (gpuOk) {
    gpuStatus.textContent = 'WebGPU: Ready';
    gpuStatus.classList.add('supported');
  } else {
    cracker = new CPUCracker();
    await cracker.init();
    gpuStatus.textContent = 'WebGPU: N/A (CPU fallback)';
    gpuStatus.classList.add('unsupported');
  }

  startBtn.disabled = false;
}

document.getElementById('btn-start-cracking').addEventListener('click', async () => {
  if (cracking) return;
  cracking = true;

  document.getElementById('btn-start-cracking').classList.add('hidden');
  document.getElementById('btn-stop-cracking').classList.remove('hidden');
  setCrackingStatus('Starting worker loop...');

  await runCrackingLoop();
});

document.getElementById('btn-stop-cracking').addEventListener('click', () => {
  cracking = false;
  if (cracker) cracker.stop();
  document.getElementById('btn-start-cracking').classList.remove('hidden');
  document.getElementById('btn-stop-cracking').classList.add('hidden');
  setCrackingStatus('Stopped.');
  resetLocalProgress();
  _smoothedHashRate = 0;
  apiPost('/api/worker/hashrate', { clientId: getClientId(), hashRate: 0 }).catch(() => {});
});

async function runCrackingLoop() {
  if (loopRunning) return;
  loopRunning = true;
  let batchesCompleted = 0;

  // Pre-fetch next batch via HTTP while GPU processes current one
  let nextWorkPromise = null;

  try {
    clog('cracking loop started (HTTP mode)');

    while (cracking) {
      setCrackingStatus('Requesting work via HTTP...');

      // Use pre-fetched work if available, otherwise fetch now
      let response;
      const t0 = performance.now();
      try {
        response = nextWorkPromise ? await nextWorkPromise : await fetchWork();
        nextWorkPromise = null;
      } catch (err) {
        clog(`HTTP work request failed: ${err.message} — retrying in 2s`);
        setCrackingStatus(`Work request failed: ${err.message}. Retrying...`);
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }
      const waitMs = Math.round(performance.now() - t0);

      const chunks = response.chunks || [];
      const packetRawData = response.packetRawData || {};
      if (response.charset) currentCharset = response.charset;

      if (chunks.length === 0) {
        clog(`no work available (waited ${waitMs}ms) — retrying in 3s`);
        setCrackingStatus('No work available — retrying...');
        await new Promise(r => setTimeout(r, 3000));
        continue;
      }

      const totalCandidates = chunks.reduce((sum, c) => sum + (c.range_end - c.range_start), 0);
      const packetIds = [...new Set(chunks.map(c => c.packet_id))];
      clog(`received ${chunks.length} chunk(s) for packet [${packetIds}] — ${formatNumber(totalCandidates)} candidates (wait=${waitMs}ms)`);

      // Pre-fetch next batch while GPU crunches this one
      nextWorkPromise = fetchWork().catch(err => {
        clog(`pre-fetch failed: ${err.message}`);
        return { chunks: [] };
      });

      setCrackingStatus(`Starting batch: ${chunks.length} chunk(s), ${formatNumber(totalCandidates)} candidates for packet ${packetIds.join(', ')}...`);

      document.getElementById('local-chunk-label').textContent =
        `${chunks.length} chunk${chunks.length !== 1 ? 's' : ''}`;
      setLocalProgress(0, 1);

      // If the GPU device was lost during a previous batch (Windows TDR,
      // driver crash, AV interference), fall back to CPU so the loop keeps
      // running instead of immediately failing again on a dead device.
      if (cracker._deviceLost) {
        const tuning = getGpuTuningSettings();
        if (tuning.fallbackPolicy === 'retry_once' && !_gpuRetryAttemptedAfterLoss) {
          _gpuRetryAttemptedAfterLoss = true;
          clog('GPU device lost — attempting one GPU reinit before CPU fallback');
          const retryCracker = new GPUCracker();
          const retryOk = await retryCracker.init();
          if (retryOk) {
            cracker = retryCracker;
            const gpuStatus = document.getElementById('gpu-status');
            if (gpuStatus) {
              gpuStatus.textContent = 'WebGPU: Recovered';
              gpuStatus.className = 'supported';
            }
          } else {
            clog('GPU reinit failed — falling back to CPU cracker');
            cracker = new CPUCracker();
            await cracker.init();
            const gpuStatus = document.getElementById('gpu-status');
            if (gpuStatus) {
              gpuStatus.textContent = 'WebGPU: Lost (CPU fallback)';
              gpuStatus.className = 'unsupported';
            }
          }
        } else {
          clog('GPU device lost — falling back to CPU cracker for remaining work');
          cracker = new CPUCracker();
          await cracker.init();
          const gpuStatus = document.getElementById('gpu-status');
          if (gpuStatus) {
            gpuStatus.textContent = 'WebGPU: Lost (CPU fallback)';
            gpuStatus.className = 'unsupported';
          }
        }
      }

      const batchStart = performance.now();
      let lastProgressLog = 0;
      let lastHashrateUpdateAt = 0;
      await cracker.processChunks(chunks, {
        onPrefixMatch: (packetId, matches) => {
          apiPost('/api/worker/prefix-match', { clientId: getClientId(), packetId, matches }).catch(err => {
            clog(`prefix-match POST failed: ${err.message}`);
          });
        },
        onChunkComplete: (chunkIds, hashRate) => {
          apiPost('/api/worker/chunk-complete', { clientId: getClientId(), chunkIds, hashRate }).catch(err => {
            clog(`chunk-complete POST failed: ${err.message}`);
          });
        },
        onProgress: (hashRate, processed, total) => {
          lastMeasuredHashRate = hashRate;
          const displayRate = smoothHashRate(hashRate);
          document.getElementById('stat-hashrate').textContent = formatHashRate(displayRate);
          const pct = total > 0 ? Math.round((processed / total) * 100) : 0;
          const elapsed = (performance.now() - batchStart) / 1000;
          const remaining = displayRate > 0 ? (total - processed) / displayRate : 0;
          setCrackingStatus(
            `Crunching: ${pct}% (${formatNumber(processed)}/${formatNumber(total)}) at ${formatHashRate(displayRate)}` +
            (remaining > 0 ? ` — ${formatETA(remaining)} left` : '') +
            ` [batch ${batchesCompleted + 1}]`
          );
          setLocalProgress(processed, total);
          // Log progress every ~10 seconds
          if (elapsed - lastProgressLog >= 10) {
            lastProgressLog = elapsed;
            clog(`progress: ${pct}% (${formatNumber(processed)}/${formatNumber(total)}) at ${formatHashRate(hashRate)} elapsed=${Math.round(elapsed)}s`);
          }
          // Rate-limit hashrate_update to once per second via HTTP
          const now = performance.now();
          if (now - lastHashrateUpdateAt >= 1000) {
            lastHashrateUpdateAt = now;
            apiPost('/api/worker/hashrate', { clientId: getClientId(), hashRate }).catch(() => {});
          }
        },
      }, currentCharset, packetRawData, getGpuTuningSettings());

      const batchMs = Math.round(performance.now() - batchStart);
      batchesCompleted++;
      setLocalProgress(1, 1);
      clog(`batch ${batchesCompleted} done: ${chunks.length} chunk(s), ${formatNumber(totalCandidates)} candidates in ${batchMs}ms`);
      setCrackingStatus(`Batch ${batchesCompleted} complete (${formatNumber(totalCandidates)} candidates in ${(batchMs / 1000).toFixed(1)}s). Loading next...`);
    }
  } finally {
    loopRunning = false;
    clog(`cracking loop exited — batches=${batchesCompleted} cracking=${cracking}`);
    if (cracking) {
      // Loop exited but still cracking — restart
      setTimeout(runCrackingLoop, 0);
      return;
    }
  }
}

function getCrackConfigFromUI() {
  const charsetKey = document.getElementById('keyspace-charset')?.value || 'lower';
  let minLen = parseInt(document.getElementById('keyspace-min-len')?.value, 10) || 1;
  let maxLen = parseInt(document.getElementById('keyspace-max-len')?.value, 10) || 5;
  minLen = Math.max(1, Math.min(minLen, 10));
  maxLen = Math.max(minLen, Math.min(maxLen, 10));

  return {
    charset: charsetKey,
    minLen,
    maxLen,
    charsetString: charsetByKey[charsetKey] || charsetByKey.alnum,
  };
}

function setCrackingStatus(text) {
  lastCrackingStatus = text;
  const el = document.getElementById('cracking-feedback');
  if (el) el.textContent = text;
}

function setLocalProgress(processed, total) {
  const pct = total > 0 ? Math.round((processed / total) * 100) : 0;
  const bar = document.getElementById('local-progress-bar');
  const text = document.getElementById('local-progress-text');
  if (bar) bar.style.width = `${pct}%`;
  if (text) text.textContent = total > 0
    ? `${pct}% (${formatNumber(processed)} / ${formatNumber(total)})`
    : '—';
}

function resetLocalProgress() {
  const bar = document.getElementById('local-progress-bar');
  const text = document.getElementById('local-progress-text');
  const label = document.getElementById('local-chunk-label');
  if (bar) bar.style.width = '0%';
  if (text) text.textContent = '—';
  if (label) label.textContent = '';
}

// ── Notifications ───────────────────────────────────────────────────────────
function showNotification(message) {
  const resultBox = document.getElementById('upload-result');
  resultBox.classList.remove('hidden', 'error', 'info');
  resultBox.classList.add('success');
  resultBox.textContent = message;
}

// ── Initial Load ────────────────────────────────────────────────────────────
async function loadData() {
  try {
    const [packetsRes, channelsRes, statsRes, candidatesRes, decoderRes, decodedRes] = await Promise.all([
      fetch('/api/packets'),
      fetch('/api/channels'),
      fetch('/api/stats'),
      fetch('/api/candidates'),
      fetch('/api/decoder-status'),
      fetch('/api/packets/decoded'),
    ]);
    const packets = await packetsRes.json();
    const channels = await channelsRes.json();
    const stats = await statsRes.json();
    const candidates = await candidatesRes.json();
    const decoderStatus = await decoderRes.json();
    const decodedPackets = await decodedRes.json();

    renderPackets(packets);
    renderChannels(channels);
    updateStats(stats);
    renderCandidates(candidates);
    renderDecodedPackets(decodedPackets);
    document.getElementById('worker-count').textContent = `Workers: ${stats.workerCount}`;

    const decoderEl = document.getElementById('decoder-status');
    if (decoderStatus.available) {
      decoderEl.textContent = 'Decoder: Ready';
      decoderEl.className = 'connected';
    } else {
      decoderEl.textContent = 'Decoder: N/A';
      decoderEl.className = 'disconnected';
    }
  } catch (err) {
    console.error('Failed to load initial data:', err);
  }
}

// ── Keyspace Estimate ────────────────────────────────────────────────────────
const CHARSET_LENS = { alnum: 36, lower: 26, numeric: 10, full: 65 };

function calculateKeyspaceSize(charsetLen, minLen, maxLen) {
  let size = 0;
  for (let len = minLen; len <= maxLen; len++) size += Math.pow(charsetLen, len);
  return size;
}

function updateKeyspaceEstimate() {
  const charsetKey = document.getElementById('keyspace-charset')?.value || 'alnum';
  const minLen = parseInt(document.getElementById('keyspace-min-len')?.value, 10) || 1;
  const maxLen = parseInt(document.getElementById('keyspace-max-len')?.value, 10) || 5;
  const charsetLen = CHARSET_LENS[charsetKey] || 36;
  const keyspaceSize = calculateKeyspaceSize(charsetLen, minLen, maxLen);
  const el = document.getElementById('stat-keyspace-size');
  if (el) el.textContent = formatNumber(keyspaceSize);
}

['keyspace-charset', 'keyspace-min-len', 'keyspace-max-len'].forEach(id => {
  const el = document.getElementById(id);
  if (el) {
    el.addEventListener('change', updateKeyspaceEstimate);
    el.addEventListener('input', updateKeyspaceEstimate);
  }
});

// ── Boot ────────────────────────────────────────────────────────────────────
(async () => {
  // Log environment diagnostics to help debug connection issues on specific machines.
  clog(`--- MC-Keygen 2.0 boot ---`);
  clog(`  url: ${location.href}`);
  clog(`  userAgent: ${navigator.userAgent}`);
  clog(`  onLine: ${navigator.onLine}`);
  clog(`  clientId: ${localStorage.getItem('mc-worker-client-id') || '(none yet)'}`);
  if (navigator.connection) {
    const c = navigator.connection;
    clog(`  network: type=${c.effectiveType || c.type || '?'} downlink=${c.downlink ?? '?'}Mbps rtt=${c.rtt ?? '?'}ms saveData=${c.saveData}`);
  } else {
    clog(`  network: navigator.connection unavailable`);
  }
  if (typeof WebSocket !== 'undefined') {
    clog(`  WebSocket: supported`);
  } else {
    clog(`  WebSocket: NOT SUPPORTED — this will not work`);
  }
  if (typeof navigator.gpu !== 'undefined') {
    clog(`  WebGPU: API present (adapter check deferred to initCracker)`);
  } else {
    clog(`  WebGPU: not available (will use CPU fallback)`);
  }
  clog(`  viewport: ${window.innerWidth}x${window.innerHeight} devicePixelRatio=${window.devicePixelRatio}`);

  applyPerfDefaults();
  bindPerfControlPersistence();

  connectWebSocket();
  await loadData();
  await initCracker();
  fetch('/api/config').then(r => r.json()).then(cfg => {
    serverChunkSize = cfg.chunkSize || 500000;
    updateKeyspaceEstimate();
  }).catch(() => updateKeyspaceEstimate());
})();

// Clean up GPU buffers when the page unloads to prevent VRAM leaks
window.addEventListener('beforeunload', () => {
  if (cracker && typeof cracker.destroy === 'function') cracker.destroy();
});
