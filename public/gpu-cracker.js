// ── WebGPU SHA-256 Channel Key Cracker ──────────────────────────────────────
// MeshCore key derivation:
//   key    = SHA256("#" + channelName)[0:16]   (first 16 bytes)
//   prefix = SHA256(key)[0]                    (first byte)
//
// We brute-force channel names, derive the prefix, and check against target.
// Matches are sent back to the server as candidate keys.

const SHA256_WGSL = `
// SHA-256 constants
const K = array<u32, 64>(
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
  0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
  0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
  0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
  0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
  0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
  0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
  0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
  0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
);

fn right_rotate(x: u32, n: u32) -> u32 {
  return (x >> n) | (x << (32u - n));
}

// SHA-256 of a single block (64 bytes / 16 u32 words, big-endian)
fn sha256_block(block: array<u32, 16>) -> array<u32, 8> {
  // Prepare message schedule
  var w: array<u32, 64>;
  for (var i: u32 = 0u; i < 16u; i++) {
    w[i] = block[i];
  }
  for (var i: u32 = 16u; i < 64u; i++) {
    let s0 = right_rotate(w[i - 15u], 7u) ^ right_rotate(w[i - 15u], 18u) ^ (w[i - 15u] >> 3u);
    let s1 = right_rotate(w[i - 2u], 17u) ^ right_rotate(w[i - 2u], 19u) ^ (w[i - 2u] >> 10u);
    w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
  }

  // Initialize working variables
  var h: array<u32, 8>;
  h[0] = 0x6a09e667u; h[1] = 0xbb67ae85u;
  h[2] = 0x3c6ef372u; h[3] = 0xa54ff53au;
  h[4] = 0x510e527fu; h[5] = 0x9b05688cu;
  h[6] = 0x1f83d9abu; h[7] = 0x5be0cd19u;

  var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3];
  var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7];

  // Compression
  for (var i: u32 = 0u; i < 64u; i++) {
    let S1 = right_rotate(e, 6u) ^ right_rotate(e, 11u) ^ right_rotate(e, 25u);
    let ch = (e & f) ^ ((~e) & g);
    let temp1 = hh + S1 + ch + K[i] + w[i];
    let S0 = right_rotate(a, 2u) ^ right_rotate(a, 13u) ^ right_rotate(a, 22u);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let temp2 = S0 + maj;

    hh = g; g = f; f = e; e = d + temp1;
    d = c; c = b; b = a; a = temp1 + temp2;
  }

  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  h[4] += e; h[5] += f; h[6] += g; h[7] += hh;

  return h;
}

struct Params {
  target_prefix: u32,   // target prefix byte (lowest 8 bits compared against hash2[0]>>24)
  range_start: u32,
  range_size: u32,
  charset_len: u32,     // length of charset (36 for alnum)
}

struct MatchEntry {
  index: u32,           // the candidate index that matched
  key0: u32,            // hash1[0] — first word of SHA256("#channelName")
  key1: u32,            // hash1[1]
  key2: u32,            // hash1[2]
  key3: u32,            // hash1[3]  (key = first 16 bytes = key0..key3 big-endian)
}

struct Results {
  match_count: atomic<u32>,
  matches: array<MatchEntry, 8192>,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> results: Results;
@group(0) @binding(2) var<storage, read> charset: array<u32, 64>;

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let idx = gid.x;
  if (idx >= params.range_size) { return; }

  let candidate_idx = params.range_start + idx;

  // Convert index to channel name string using charset
  // Index maps to variable-length strings:
  // 0..35 = 1-char, 36..1331 = 2-char, etc.
  let base = params.charset_len;
  var name_bytes: array<u32, 32>;  // max channel name length
  var name_len: u32 = 0u;

  // First byte is always '#' (0x23)
  name_bytes[0] = 0x23u;
  name_len = 1u;

  // Determine which length tier this index falls into
  var remaining = candidate_idx;
  var tier_start: u32 = 0u;
  var tier_len: u32 = 1u;
  var tier_size: u32 = base;

  loop {
    if (remaining < tier_size) { break; }
    remaining -= tier_size;
    tier_start += tier_size;
    tier_len++;
    tier_size *= base;
    if (tier_len > 8u) { return; } // safety limit
  }

  // Convert remaining to base-N digits for the name
  var temp = remaining;
  for (var i: u32 = 0u; i < tier_len; i++) {
    let digit = temp % base;
    name_bytes[name_len + tier_len - 1u - i] = charset[digit];
    temp /= base;
  }
  name_len += tier_len;

  // ── SHA-256("#channelName") ──
  // Build padded message block (big-endian, single block for names <= 55 bytes)
  var block: array<u32, 16>;
  for (var i: u32 = 0u; i < 16u; i++) { block[i] = 0u; }

  // Pack name bytes into big-endian u32 words
  for (var i: u32 = 0u; i < name_len; i++) {
    let word_idx = i / 4u;
    let byte_idx = 3u - (i % 4u);  // big-endian
    block[word_idx] |= name_bytes[i] << (byte_idx * 8u);
  }

  // SHA-256 padding
  let pad_word = name_len / 4u;
  let pad_byte = 3u - (name_len % 4u);
  block[pad_word] |= 0x80u << (pad_byte * 8u);
  // Length in bits at the end of the block
  block[15] = name_len * 8u;

  let hash1 = sha256_block(block);

  // key = first 16 bytes of hash1 (hash1[0], hash1[1], hash1[2], hash1[3])

  // ── SHA-256(key) to get prefix ──
  // key is 16 bytes, so build another padded block
  var block2: array<u32, 16>;
  for (var i: u32 = 0u; i < 16u; i++) { block2[i] = 0u; }

  // Copy first 4 words (16 bytes) of hash1 as the message
  block2[0] = hash1[0];
  block2[1] = hash1[1];
  block2[2] = hash1[2];
  block2[3] = hash1[3];
  // Padding byte after 16 bytes
  block2[4] = 0x80000000u;
  // Length: 16 bytes = 128 bits
  block2[15] = 128u;

  let hash2 = sha256_block(block2);

  // prefix = first byte of hash2 (top 8 bits of hash2[0], big-endian)
  let prefix_byte = (hash2[0] >> 24u) & 0xFFu;

  if (prefix_byte == params.target_prefix) {
    let slot = atomicAdd(&results.match_count, 1u);
    if (slot < 8192u) {
      results.matches[slot].index = candidate_idx;
      results.matches[slot].key0  = hash1[0];
      results.matches[slot].key1  = hash1[1];
      results.matches[slot].key2  = hash1[2];
      results.matches[slot].key3  = hash1[3];
    }
  }
}
`;

class GPUCracker {
  constructor() {
    this.device = null;
    this.pipeline = null;
    this.supported = false;
    this.running = false;
    this.hashRate = 0;
    this._lastCount = 0;
    this._lastTime = 0;
    this.paramsBuffer = null;
    this.resultBuffer = null;
    this.readBuffer = null;
    this.charsetBuffer = null;
    this.bindGroup = null;
    this.cachedCharset = null;
  }

  async init() {
    if (!navigator.gpu) {
      console.warn('WebGPU not supported');
      return false;
    }

    try {
      const adapter = await navigator.gpu.requestAdapter({
        powerPreference: 'high-performance'
      });
      if (!adapter) {
        console.warn('No WebGPU adapter found');
        return false;
      }

      // Request the adapter's actual workgroup dispatch limit so we can
      // size GPU batches as large as the hardware supports.
      const maxDispatch = adapter.limits.maxComputeWorkgroupsPerDimension || 65535;
      this._maxDispatch = maxDispatch;

      this.device = await adapter.requestDevice();

      const shaderModule = this.device.createShaderModule({ code: SHA256_WGSL });
      this.pipeline = this.device.createComputePipeline({
        layout: 'auto',
        compute: { module: shaderModule, entryPoint: 'main' }
      });

      this.supported = true;
      console.log(`WebGPU initialized: maxDispatch=${maxDispatch} → batchSize=${(maxDispatch * 256 / 1e6).toFixed(1)}M candidates/dispatch`);
      return true;
    } catch (err) {
      console.error('WebGPU init failed:', err);
      return false;
    }
  }

  // Convert index back to channel name (must match GPU logic exactly)
  indexToChannelName(index, charset) {
    const base = charset.length;
    let remaining = index;
    let tierLen = 1;
    let tierSize = base;

    while (remaining >= tierSize) {
      remaining -= tierSize;
      tierLen++;
      tierSize *= base;
      if (tierLen > 8) return null;
    }

    let name = '';
    let temp = remaining;
    for (let i = 0; i < tierLen; i++) {
      name = charset[temp % base] + name;
      temp = Math.floor(temp / base);
    }

    return '#' + name;
  }

  ensureBuffers() {
    if (this.bufferSets) return;

    // 4-byte atomic count + 8192 entries × 5 u32s × 4 bytes = 163,844 bytes
    const MATCH_SLOTS = 8192;
    const resultSize = 4 + MATCH_SLOTS * 5 * 4;
    this._matchSlots = MATCH_SLOTS;
    this._resultSize = resultSize;

    // Params and charset are shared across both buffer sets — the GPU queue
    // serialises writeBuffer calls, so params for batch N are always written
    // before batch N's compute pass executes.
    this.paramsBuffer = this.device.createBuffer({
      size: 16,
      usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
    });
    this.charsetBuffer = this.device.createBuffer({
      size: 64 * 4,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
    });

    // Two buffer sets for ping-pong double-buffering.  While the GPU computes
    // batch N on one set, the CPU reads back batch N-1 from the other set.
    this.bufferSets = [0, 1].map(() => {
      const resultBuffer = this.device.createBuffer({
        size: resultSize,
        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
      });
      const readBuffer = this.device.createBuffer({
        size: resultSize,
        usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
      });
      const bindGroup = this.device.createBindGroup({
        layout: this.pipeline.getBindGroupLayout(0),
        entries: [
          { binding: 0, resource: { buffer: this.paramsBuffer } },
          { binding: 1, resource: { buffer: resultBuffer } },
          { binding: 2, resource: { buffer: this.charsetBuffer } },
        ],
      });
      return { resultBuffer, readBuffer, bindGroup };
    });
  }

  // Submit a compute dispatch to the GPU (non-blocking — does not await completion).
  _dispatchBatch(bufSetIdx, targetPrefix, rangeStart, rangeSize, charset) {
    if (this.cachedCharset !== charset) {
      const charsetData = new Uint32Array(64);
      for (let i = 0; i < charset.length; i++) charsetData[i] = charset.charCodeAt(i);
      this.device.queue.writeBuffer(this.charsetBuffer, 0, charsetData);
      this.cachedCharset = charset;
    }

    const { resultBuffer, readBuffer, bindGroup } = this.bufferSets[bufSetIdx];

    // Reset match count then write params for this batch.
    this.device.queue.writeBuffer(resultBuffer, 0, new Uint32Array([0]));
    this.device.queue.writeBuffer(this.paramsBuffer, 0,
      new Uint32Array([targetPrefix, rangeStart, rangeSize, charset.length]));

    const encoder = this.device.createCommandEncoder();
    const pass = encoder.beginComputePass();
    pass.setPipeline(this.pipeline);
    pass.setBindGroup(0, bindGroup);
    pass.dispatchWorkgroups(Math.ceil(rangeSize / 256));
    pass.end();
    encoder.copyBufferToBuffer(resultBuffer, 0, readBuffer, 0, this._resultSize);
    this.device.queue.submit([encoder.finish()]);
  }

  // Map the read buffer for bufSetIdx and extract matches.  Returns a promise
  // that resolves once the GPU has finished writing to that buffer.
  async _readResults(bufSetIdx) {
    const { readBuffer } = this.bufferSets[bufSetIdx];
    await readBuffer.mapAsync(GPUMapMode.READ);
    const resultData = new Uint32Array(readBuffer.getMappedRange());
    const matchCount = resultData[0];
    const matches = [];
    for (let i = 0; i < Math.min(matchCount, this._matchSlots); i++) {
      const base = 1 + i * 5;
      matches.push({
        index: resultData[base],
        key0:  resultData[base + 1],
        key1:  resultData[base + 2],
        key2:  resultData[base + 3],
        key3:  resultData[base + 4],
      });
    }
    readBuffer.unmap();
    return matches;
  }

  async processChunks(chunks, ws, onProgress, charset, packetRawData = {}) {
    this.running = true;
    this.ensureBuffers();

    const totalCandidates = chunks.reduce((sum, c) => sum + (c.range_end - c.range_start), 0);
    let processedCandidates = 0;
    // Track total candidates and wall-clock time for accurate hash rate.
    // The ping-pong pipeline means finishBatch runs while the GPU is already
    // computing the next batch, so we must measure over a longer window.
    let _rateWindowStart = performance.now();
    let _rateWindowCount = 0;

    // workgroup_size(256), so candidates = dispatchWorkgroups * 256.
    // On mobile, cap dispatch size to 1/4 of the GPU max to keep individual
    // GPU jobs short and avoid starving the UI/WebSocket event loop.
    const maxDispatch = this._maxDispatch || 65535;
    const _isMobile = /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || window.innerWidth < 768;
    const dispatchCap = _isMobile ? Math.max(1, Math.ceil(maxDispatch / 4)) : maxDispatch;
    const batchSize = Math.max(256, dispatchCap * 256);
    const _yieldInterval = _isMobile ? 100 : 500;

    // Flatten all work into a single batch list so the ping-pong pipeline can
    // span chunk boundaries without extra complexity.
    const batches = [];
    for (const chunk of chunks) {
      const rangeSize = chunk.range_end - chunk.range_start;
      for (let offset = 0; offset < rangeSize; offset += batchSize) {
        batches.push({
          chunk,
          start: chunk.range_start + offset,
          size: Math.min(batchSize, rangeSize - offset),
          isLastInChunk: offset + batchSize >= rangeSize,
        });
      }
    }

    try {
      console.debug(`[gpu] processing ${chunks.length} chunk(s) as ${batches.length} GPU batch(es), batchSize=${batchSize}`);
    } catch (_) {}

    const sendMatches = async (matches, chunk) => {
      if (matches.length === 0) return;
      const batchMatches = [];
      for (const m of matches) {
        const channelName = this.indexToChannelName(m.index, charset);
        if (!channelName) continue;
        const keyHex = [m.key0, m.key1, m.key2, m.key3]
          .map(w => w.toString(16).padStart(8, '0')).join('');
        const entry = {
          channelName,
          keyHex,
          prefixHex: chunk.target_prefix.toString(16).padStart(2, '0'),
        };
        // Attempt client-side decryption to skip a server round-trip
        const rawData = packetRawData[chunk.packet_id];
        if (rawData && typeof clientTryDecrypt === 'function') {
          const decoded = await clientTryDecrypt(rawData, keyHex);
          if (decoded) entry.clientDecoded = decoded;
        }
        batchMatches.push(entry);
      }
      if (batchMatches.length > 0) {
        try {
          ws.send(JSON.stringify({ type: 'prefix_match_batch', packetId: chunk.packet_id, matches: batchMatches }));
        } catch (_) { /* ws closed mid-batch; loop will detect on next iteration */ }
      }
    };

    let _lastProgressTime = 0;
    const completedChunkIds = new Set();
    const finishBatch = async (matches, batch) => {
      processedCandidates += batch.size;
      _rateWindowCount += batch.size;
      // Compute hash rate over a rolling window of at least 2 seconds so the
      // ping-pong pipeline doesn't skew the measurement (finishBatch runs
      // while the next batch is already on the GPU).
      const elapsed = (performance.now() - _rateWindowStart) / 1000;
      if (elapsed >= 2.0) {
        this.hashRate = Math.round(_rateWindowCount / elapsed);
        _rateWindowCount = 0;
        _rateWindowStart = performance.now();
      }
      // Throttle progress callbacks to ~1/sec to avoid DOM/WebSocket overhead
      // between GPU dispatches starving the pipeline.
      const now = performance.now();
      if (onProgress && (now - _lastProgressTime > 1000 || processedCandidates >= totalCandidates)) {
        _lastProgressTime = now;
        onProgress(this.hashRate, processedCandidates, totalCandidates);
      }
      // Send matches without blocking the pipeline — fire and forget
      if (matches.length > 0) sendMatches(matches, batch.chunk);
      if (batch.isLastInChunk) completedChunkIds.add(batch.chunk.id);
    };

    // Ping-pong pipeline: dispatch batch i, then await batch i-1's readback
    // while the GPU is already computing batch i.  This hides mapAsync latency
    // behind GPU compute time.
    let pending = null; // { promise, bufSetIdx, batch }
    let pingPong = 0;
    let _lastYield = performance.now();

    for (let i = 0; i < batches.length; i++) {
      if (!this.running) break;

      const batch = batches[i];
      const currentPP = pingPong;
      pingPong = 1 - pingPong;

      // Submit this batch to the GPU (returns immediately).
      this._dispatchBatch(currentPP, batch.chunk.target_prefix, batch.start, batch.size, charset);

      // Await the previous batch's GPU results while this batch computes.
      if (pending) {
        try {
          const matches = await pending.promise;
          await finishBatch(matches, pending.batch);
        } catch (err) {
          console.error('GPU readback error:', err);
        }
      }

      // Yield to the macrotask queue periodically so WebSocket onmessage
      // events can fire.  Without this, pushed work messages pile up in
      // the network buffer and the client appears idle to the server.
      const now = performance.now();
      if (now - _lastYield > _yieldInterval) {
        _lastYield = now;
        await new Promise(r => setTimeout(r, 0));
      }

      // Kick off async readback for the batch we just dispatched.
      pending = { promise: this._readResults(currentPP), batch };
    }

    // Drain the final in-flight batch.
    if (pending) {
      try {
        const matches = await pending.promise;
        if (this.running) await finishBatch(matches, pending.batch);
      } catch (err) {
        console.error('GPU readback error:', err);
      }
    }

    if (completedChunkIds.size > 0) {
      try {
        ws.send(JSON.stringify({
          type: 'chunk_complete',
          chunkIds: [...completedChunkIds],
          hashRate: this.hashRate,
        }));
      } catch (_) { /* ws closed; server will re-queue via stale-chunk expiry */ }
    }

    return { found: false };
  }

  stop() {
    this.running = false;
  }

  destroy() {
    this.stop();
    if (this.bufferSets) {
      for (const set of this.bufferSets) {
        set.resultBuffer.destroy();
        set.readBuffer.destroy();
      }
      this.bufferSets = null;
    }
    if (this.paramsBuffer) { this.paramsBuffer.destroy(); this.paramsBuffer = null; }
    if (this.charsetBuffer) { this.charsetBuffer.destroy(); this.charsetBuffer = null; }
    this.cachedCharset = null;
  }
}

// ── JS SHA-256 helpers (for deriving key/prefix on CPU after GPU match) ─────

async function deriveKeyJS(channelName) {
  const name = channelName.startsWith('#') ? channelName : '#' + channelName;
  const data = new TextEncoder().encode(name);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash).subarray(0, 16);
}

async function derivePrefixJS(keyBytes) {
  const hash = await crypto.subtle.digest('SHA-256', keyBytes);
  return new Uint8Array(hash)[0];
}

function bufToHex(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── CPU Fallback Cracker ────────────────────────────────────────────────────

class CPUCracker {
  constructor() {
    this.supported = true;
    this.running = false;
    this.hashRate = 0;
  }

  async init() { return true; }

  indexToChannelName(index, charset) {
    const base = charset.length;
    let remaining = index;
    let tierLen = 1;
    let tierSize = base;

    while (remaining >= tierSize) {
      remaining -= tierSize;
      tierLen++;
      tierSize *= base;
      if (tierLen > 8) return null;
    }

    let name = '';
    let temp = remaining;
    for (let i = 0; i < tierLen; i++) {
      name = charset[temp % base] + name;
      temp = Math.floor(temp / base);
    }

    return '#' + name;
  }

  async processChunks(chunks, ws, onProgress, charset, packetRawData = {}) {
    this.running = true;
    let totalHashed = 0;
    let lastTime = performance.now();

    const totalCandidates = chunks.reduce((sum, c) => sum + (c.range_end - c.range_start), 0);
    let processedCandidates = 0;

    const completedChunkIds = [];

    for (const chunk of chunks) {
      if (!this.running) break;
      let chunkFullyProcessed = true;

      for (let i = chunk.range_start; i < chunk.range_end; i++) {
        if (!this.running) {
          chunkFullyProcessed = false;
          break;
        }
        const channelName = this.indexToChannelName(i, charset);
        if (!channelName) continue;

        const key = await deriveKeyJS(channelName);
        const prefix = await derivePrefixJS(key);

        if (prefix === chunk.target_prefix) {
          const keyHex = bufToHex(key);
          const prefixHex = prefix.toString(16).padStart(2, '0');
          const entry = { channelName, keyHex, prefixHex };
          const rawData = packetRawData[chunk.packet_id];
          if (rawData && typeof clientTryDecrypt === 'function') {
            const decoded = await clientTryDecrypt(rawData, keyHex);
            if (decoded) entry.clientDecoded = decoded;
          }
          try {
            ws.send(JSON.stringify({
              type: 'prefix_match_batch',
              packetId: chunk.packet_id,
              matches: [entry],
            }));
          } catch (_) { /* ws closed; loop will detect and recover */ }
        }

        totalHashed++;
        processedCandidates++;
        if (totalHashed % 5000 === 0) {
          const now = performance.now();
          const elapsed = (now - lastTime) / 1000;
          this.hashRate = Math.round(totalHashed / elapsed);
          if (onProgress) onProgress(this.hashRate, processedCandidates, totalCandidates);
          await new Promise(r => setTimeout(r, 0));
        }
      }

      // Emit a final rate for the chunk even if it had <5000 candidates
      if (totalHashed > 0) {
        const elapsed = (performance.now() - lastTime) / 1000;
        if (elapsed > 0) this.hashRate = Math.round(totalHashed / elapsed);
        if (onProgress) onProgress(this.hashRate, processedCandidates, totalCandidates);
      }

      if (chunkFullyProcessed) completedChunkIds.push(chunk.id);

      totalHashed = 0;
      lastTime = performance.now();
    }

    if (completedChunkIds.length > 0) {
      try {
        ws.send(JSON.stringify({
          type: 'chunk_complete',
          chunkIds: completedChunkIds,
          hashRate: this.hashRate,
        }));
      } catch (_) { /* ws closed; server will re-queue via stale-chunk expiry */ }
    }

    return { found: false };
  }

  stop() {
    this.running = false;
  }
}

window.GPUCracker = GPUCracker;
window.CPUCracker = CPUCracker;
