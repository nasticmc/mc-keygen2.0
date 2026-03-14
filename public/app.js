// ── MC-Keygen 2.0 Frontend ──────────────────────────────────────────────────

let ws = null;
let cracker = null;
let cracking = false;
let loopRunning = false;
let currentCharset = 'abcdefghijklmnopqrstuvwxyz';
let serverChunkSize = 500000;
const pendingWorkResolvers = [];
const queuedWorkMessages = [];
let lastCrackingStatus = 'Idle.';

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
function connectWebSocket() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${location.host}`);

  ws.onopen = () => {
    // Clear stale work queues from before the disconnect
    pendingWorkResolvers.length = 0;
    queuedWorkMessages.length = 0;
    document.getElementById('connection-status').textContent = 'Connected';
    document.getElementById('connection-status').className = 'connected';
    if (cracking && !loopRunning) runCrackingLoop();
  };

  ws.onclose = () => {
    document.getElementById('connection-status').textContent = 'Disconnected';
    document.getElementById('connection-status').className = 'disconnected';
    setTimeout(connectWebSocket, 2000);
  };

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
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
      case 'worker_removed':
        workerData.delete(msg.workerId);
        refreshWorkerDisplay();
        break;
      case 'work':
        if (pendingWorkResolvers.length > 0) {
          const resolve = pendingWorkResolvers.shift();
          resolve(msg);
        } else {
          queuedWorkMessages.push(msg);
        }
        break;
    }
  };
}

function waitForWork(timeoutMs = 5000) {
  if (queuedWorkMessages.length > 0) {
    return Promise.resolve(queuedWorkMessages.shift());
  }

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      const idx = pendingWorkResolvers.indexOf(resolver);
      if (idx >= 0) pendingWorkResolvers.splice(idx, 1);
      resolve({ chunks: [] });
    }, timeoutMs);

    const resolver = (msg) => {
      clearTimeout(timeout);
      resolve(msg);
    };

    pendingWorkResolvers.push(resolver);
  });
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
  if (stats.totalHashRate !== undefined) {
    document.getElementById('stat-hashrate').textContent = formatHashRate(hashRate);
  }

  // ETA based on remaining chunks × chunk size ÷ hash rate
  const remaining = (active.pending + active.assigned) * serverChunkSize;
  const eta = hashRate > 0 && remaining > 0 ? remaining / hashRate : Infinity;
  const etaEl = document.getElementById('stat-eta');
  if (etaEl) etaEl.textContent = formatETA(eta);
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

function refreshWorkerDisplay() {
  const container = document.getElementById('workers-list');
  container.innerHTML = '';

  for (const [id, rate] of workerData) {
    const card = document.createElement('div');
    card.className = 'worker-card';
    card.innerHTML = `
      <div class="worker-id">${id.substring(0, 8)}</div>
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
function renderPackets(packets) {
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
        ${p.status !== 'cracked' ? `<button class="btn-sm" onclick="autoDecrypt(${p.id})">Try Decrypt</button>` : `<button class="btn-sm btn-warning" onclick="retryPacket(${p.id}, '${escapeAttr(p.channel_name || '')}')">Retry (Ignore Channel)</button>`}
      </td>
    `;
    tbody.appendChild(tr);
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
function renderCandidates(candidates) {
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

  cracker = new GPUCracker();
  const gpuOk = await cracker.init();

  if (gpuOk) {
    gpuStatus.textContent = 'WebGPU: Ready';
    gpuStatus.classList.add('supported');
  } else {
    cracker = new CPUCracker();
    await cracker.init();
    gpuStatus.textContent = 'WebGPU: N/A (CPU fallback)';
    gpuStatus.classList.add('unsupported');
  }
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
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'hashrate_update', hashRate: 0 }));
  }
});

async function runCrackingLoop() {
  if (loopRunning) return;
  loopRunning = true;
  try {
    while (cracking && ws && ws.readyState === WebSocket.OPEN) {
      setCrackingStatus('Requesting work from server...');
      const count = parseInt(document.getElementById('work-batch-count')?.value, 10) || 8;
      ws.send(JSON.stringify({ type: 'request_work', count }));
      const response = await waitForWork(5000);

      const chunks = response.chunks;
      if (response.charset) currentCharset = response.charset;

      if (chunks.length === 0) {
        setCrackingStatus('No work available. Polling again in 2s...');
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }

      const packetIds = [...new Set(chunks.map(c => c.packet_id))];
      setCrackingStatus(`Processing ${chunks.length} chunk(s) for packet ${packetIds.join(', ')}...`);

      await cracker.processChunks(chunks, ws, (hashRate) => {
        document.getElementById('stat-hashrate').textContent = formatHashRate(hashRate);
        setCrackingStatus(`Crunching ${chunks.length} chunk(s) at ${formatHashRate(hashRate)}.`);
        ws.send(JSON.stringify({ type: 'hashrate_update', hashRate }));
      }, currentCharset);

      setCrackingStatus(`Finished ${chunks.length} chunk(s). Requesting more work...`);
    }
  } finally {
    loopRunning = false;
  }

  if (cracking && (!ws || ws.readyState !== WebSocket.OPEN)) {
    setCrackingStatus('Waiting for WebSocket reconnection...');
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
  const maxLen = parseInt(document.getElementById('keyspace-max-len')?.value, 10) || 6;
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
  connectWebSocket();
  await loadData();
  await initCracker();
  fetch('/api/config').then(r => r.json()).then(cfg => {
    serverChunkSize = cfg.chunkSize || 500000;
    updateKeyspaceEstimate();
  }).catch(() => updateKeyspaceEstimate());
})();
