// ── MC-Keygen 2.0 Frontend ──────────────────────────────────────────────────

let ws = null;
let cracker = null;
let cracking = false;

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
    document.getElementById('connection-status').textContent = 'Connected';
    document.getElementById('connection-status').className = 'connected';
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
      case 'key_found':
        showNotification(`Key found for packet #${msg.packetId}: ${msg.key}`);
        break;
      case 'worker_update':
        updateWorkerDisplay(msg.workerId, msg.hashRate);
        break;
    }
  };
}

// ── Stats ───────────────────────────────────────────────────────────────────
function updateStats(stats) {
  document.getElementById('stat-pending').textContent = formatNumber(stats.pending);
  document.getElementById('stat-assigned').textContent = formatNumber(stats.assigned);
  document.getElementById('stat-completed').textContent = formatNumber(stats.completed);

  const total = stats.total || 1;
  const pct = Math.round((stats.completed / total) * 100);
  document.getElementById('progress-bar').style.width = `${pct}%`;
  document.getElementById('progress-text').textContent = `${pct}% (${stats.completed}/${total})`;
}

function formatNumber(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

function formatHashRate(n) {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(2) + ' GH/s';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + ' MH/s';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + ' KH/s';
  return n + ' H/s';
}

// ── Workers Display ─────────────────────────────────────────────────────────
const workerData = new Map();

function updateWorkerDisplay(workerId, hashRate) {
  workerData.set(workerId, hashRate);
  const container = document.getElementById('workers-list');
  container.innerHTML = '';

  let totalRate = 0;
  for (const [id, rate] of workerData) {
    totalRate += rate;
    const card = document.createElement('div');
    card.className = 'worker-card';
    card.innerHTML = `
      <div class="worker-id">${id.substring(0, 8)}</div>
      <div class="worker-rate">${formatHashRate(rate)}</div>
    `;
    container.appendChild(card);
  }

  document.getElementById('stat-hashrate').textContent = formatHashRate(totalRate);
}

// ── Packets Table ───────────────────────────────────────────────────────────
function renderPackets(packets) {
  const tbody = document.getElementById('packets-table');
  tbody.innerHTML = '';

  for (const p of packets) {
    const tr = document.createElement('tr');
    const badgeClass = p.status === 'cracked' ? 'badge-cracked' : p.status === 'cracking' ? 'badge-cracking' : 'badge-pending';
    tr.innerHTML = `
      <td>${p.id}</td>
      <td title="${p.hash}">${p.hash.substring(0, 16)}...</td>
      <td><span class="badge ${badgeClass}">${p.status}</span></td>
      <td>${p.cracked_key || '-'}</td>
      <td>${new Date(p.created_at).toLocaleString()}</td>
      <td><button class="btn-sm" onclick="deletePacket(${p.id})">Delete</button></td>
    `;
    tbody.appendChild(tr);
  }
}

async function deletePacket(id) {
  await fetch(`/api/packets/${id}`, { method: 'DELETE' });
}

// ── Channels Table ──────────────────────────────────────────────────────────
function renderChannels(channels) {
  const tbody = document.getElementById('channels-table');
  tbody.innerHTML = '';

  for (const c of channels) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${c.channel_name}</td>
      <td title="${c.hash}">${c.hash.substring(0, 16)}...</td>
      <td title="${c.key}">${c.key.substring(0, 16)}...</td>
      <td>${c.prefix}</td>
      <td><button class="btn-sm" onclick="deleteChannel(${c.id})">Delete</button></td>
    `;
    tbody.appendChild(tr);
  }
}

async function deleteChannel(id) {
  await fetch(`/api/channels/${id}`, { method: 'DELETE' });
}

// ── Upload Packet ───────────────────────────────────────────────────────────
document.getElementById('btn-upload').addEventListener('click', async () => {
  const rawData = document.getElementById('raw-packet').value.trim();
  if (!rawData) return;

  const resultBox = document.getElementById('upload-result');
  resultBox.classList.remove('hidden', 'success', 'info', 'error');

  try {
    const res = await fetch('/api/packets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawData })
    });
    const data = await res.json();

    if (data.alreadyKnown) {
      resultBox.classList.add('success');
      resultBox.textContent = `Already cracked! Channel: ${data.knownChannel.channel_name}, Key: ${data.knownChannel.key}`;
    } else {
      resultBox.classList.add('info');
      resultBox.textContent = `Packet queued (ID: ${data.packet.id}). Hash: ${data.packet.hash}. Work chunks created.`;
    }
    resultBox.classList.remove('hidden');
    document.getElementById('raw-packet').value = '';
  } catch (err) {
    resultBox.classList.add('error');
    resultBox.textContent = `Error: ${err.message}`;
    resultBox.classList.remove('hidden');
  }
});

// ── Add Channel ─────────────────────────────────────────────────────────────
document.getElementById('channel-name').addEventListener('input', (e) => {
  const name = e.target.value.trim();
  if (name) {
    // Auto-populate hash, key, prefix when channel name is typed
    // These are placeholders - server will generate actual values
    document.getElementById('channel-hash').placeholder = 'Auto: md5(name)';
    document.getElementById('channel-key').placeholder = 'Auto: sha256(name)';
    document.getElementById('channel-prefix').placeholder = 'Auto: md5(name)[0:8]';
  }
});

document.getElementById('btn-add-channel').addEventListener('click', async () => {
  const channelName = document.getElementById('channel-name').value.trim();
  if (!channelName) return;

  const hash = document.getElementById('channel-hash').value.trim();
  const key = document.getElementById('channel-key').value.trim();
  const prefix = document.getElementById('channel-prefix').value.trim();

  try {
    await fetch('/api/channels', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ channelName, hash: hash || undefined, key: key || undefined, prefix: prefix || undefined })
    });
    document.getElementById('channel-name').value = '';
    document.getElementById('channel-hash').value = '';
    document.getElementById('channel-key').value = '';
    document.getElementById('channel-prefix').value = '';
  } catch (err) {
    console.error('Failed to add channel:', err);
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

  await runCrackingLoop();
});

document.getElementById('btn-stop-cracking').addEventListener('click', () => {
  cracking = false;
  if (cracker) cracker.stop();
  document.getElementById('btn-start-cracking').classList.remove('hidden');
  document.getElementById('btn-stop-cracking').classList.add('hidden');
});

async function runCrackingLoop() {
  while (cracking && ws && ws.readyState === WebSocket.OPEN) {
    // Request work from server
    ws.send(JSON.stringify({ type: 'request_work', count: 4 }));

    // Wait for work response
    const chunks = await new Promise((resolve) => {
      const handler = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'work') {
          ws.removeEventListener('message', handler);
          resolve(msg.chunks);
        }
      };
      ws.addEventListener('message', handler);
      // Timeout after 5s if no work available
      setTimeout(() => {
        ws.removeEventListener('message', handler);
        resolve([]);
      }, 5000);
    });

    if (chunks.length === 0) {
      // No work available, wait and retry
      await new Promise(r => setTimeout(r, 2000));
      continue;
    }

    const result = await cracker.processChunks(chunks, ws, (hashRate) => {
      document.getElementById('stat-hashrate').textContent = formatHashRate(hashRate);
      ws.send(JSON.stringify({ type: 'hashrate_update', hashRate }));
    });

    if (result.found) {
      ws.send(JSON.stringify({
        type: 'key_found',
        packetId: result.packetId,
        key: String(result.key),
        chunkId: result.chunkId
      }));
      showNotification(`Key found: ${result.key}`);
    }
  }
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
    const [packetsRes, channelsRes, statsRes] = await Promise.all([
      fetch('/api/packets'),
      fetch('/api/channels'),
      fetch('/api/stats')
    ]);
    const packets = await packetsRes.json();
    const channels = await channelsRes.json();
    const stats = await statsRes.json();

    renderPackets(packets);
    renderChannels(channels);
    updateStats(stats);
    document.getElementById('worker-count').textContent = `Workers: ${stats.workerCount}`;
  } catch (err) {
    console.error('Failed to load initial data:', err);
  }
}

// ── Boot ────────────────────────────────────────────────────────────────────
(async () => {
  connectWebSocket();
  await loadData();
  await initCracker();
})();
