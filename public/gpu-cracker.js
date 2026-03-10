// ── WebGPU MD5 Hash Cracker ─────────────────────────────────────────────────
// Runs MD5 brute-force on the GPU using compute shaders.

const MD5_WGSL = `
// MD5 constants
const S = array<u32, 64>(
  7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u,
  5u,  9u, 14u, 20u, 5u,  9u, 14u, 20u, 5u,  9u, 14u, 20u, 5u,  9u, 14u, 20u,
  4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u,
  6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u
);

const K = array<u32, 64>(
  0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
  0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
  0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
  0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
  0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
  0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
  0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
  0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
  0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
  0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
  0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
  0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
  0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
  0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
  0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
  0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
);

fn left_rotate(x: u32, c: u32) -> u32 {
  return (x << c) | (x >> (32u - c));
}

// Compute MD5 of a short message (up to 55 bytes, single block)
fn md5_hash(msg: array<u32, 16>) -> vec4<u32> {
  var a0: u32 = 0x67452301u;
  var b0: u32 = 0xefcdab89u;
  var c0: u32 = 0x98badcfeu;
  var d0: u32 = 0x10325476u;

  var A = a0;
  var B = b0;
  var C = c0;
  var D = d0;

  for (var i: u32 = 0u; i < 64u; i++) {
    var F: u32;
    var g: u32;
    if (i < 16u) {
      F = (B & C) | ((~B) & D);
      g = i;
    } else if (i < 32u) {
      F = (D & B) | ((~D) & C);
      g = (5u * i + 1u) % 16u;
    } else if (i < 48u) {
      F = B ^ C ^ D;
      g = (3u * i + 5u) % 16u;
    } else {
      F = C ^ (B | (~D));
      g = (7u * i) % 16u;
    }
    F = F + A + K[i] + msg[g];
    A = D;
    D = C;
    C = B;
    B = B + left_rotate(F, S[i]);
  }

  return vec4<u32>(a0 + A, b0 + B, c0 + C, d0 + D);
}

struct Params {
  target_a: u32,
  target_b: u32,
  target_c: u32,
  target_d: u32,
  range_start: u32,
  range_size: u32,
}

struct Result {
  found: atomic<u32>,
  key_value: u32,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> result: Result;

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let idx = gid.x;
  if (idx >= params.range_size) { return; }

  // Check if already found
  if (atomicLoad(&result.found) != 0u) { return; }

  let candidate = params.range_start + idx;

  // Build the candidate key as bytes in MD5 message format
  // We encode the u32 candidate as a decimal string for hashing
  var msg: array<u32, 16>;
  for (var i = 0u; i < 16u; i++) { msg[i] = 0u; }

  // Convert candidate to decimal string bytes
  var num = candidate;
  var digits: array<u32, 10>;
  var digit_count: u32 = 0u;

  if (num == 0u) {
    digits[0] = 48u; // '0'
    digit_count = 1u;
  } else {
    var temp = num;
    while (temp > 0u) {
      digits[digit_count] = (temp % 10u) + 48u;
      temp = temp / 10u;
      digit_count++;
    }
  }

  // Reverse digits and pack into msg (little-endian)
  var byte_pos: u32 = 0u;
  for (var i: u32 = 0u; i < digit_count; i++) {
    let d = digits[digit_count - 1u - i];
    let word_idx = byte_pos / 4u;
    let byte_idx = byte_pos % 4u;
    msg[word_idx] = msg[word_idx] | (d << (byte_idx * 8u));
    byte_pos++;
  }

  // MD5 padding: append 0x80
  let pad_word = byte_pos / 4u;
  let pad_byte = byte_pos % 4u;
  msg[pad_word] = msg[pad_word] | (0x80u << (pad_byte * 8u));

  // Append length in bits at position 14 (56 bytes)
  msg[14] = byte_pos * 8u;

  let hash = md5_hash(msg);

  if (hash.x == params.target_a && hash.y == params.target_b &&
      hash.z == params.target_c && hash.w == params.target_d) {
    atomicStore(&result.found, 1u);
    result.key_value = candidate;
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

      this.device = await adapter.requestDevice({
        requiredLimits: {
          maxComputeWorkgroupSizeX: 256,
          maxStorageBufferBindingSize: 128 * 1024 * 1024,
        }
      });

      const shaderModule = this.device.createShaderModule({ code: MD5_WGSL });
      this.pipeline = this.device.createComputePipeline({
        layout: 'auto',
        compute: { module: shaderModule, entryPoint: 'main' }
      });

      this.supported = true;
      console.log('WebGPU initialized successfully');
      return true;
    } catch (err) {
      console.error('WebGPU init failed:', err);
      return false;
    }
  }

  // Parse a hex MD5 hash string into 4 u32 values (little-endian)
  parseHash(hexStr) {
    const clean = hexStr.replace(/\s/g, '').toLowerCase();
    if (clean.length !== 32) throw new Error('Hash must be 32 hex chars');

    const bytes = [];
    for (let i = 0; i < 32; i += 2) {
      bytes.push(parseInt(clean.substring(i, i + 2), 16));
    }

    const view = new DataView(new ArrayBuffer(16));
    for (let i = 0; i < 16; i++) view.setUint8(i, bytes[i]);

    return {
      a: view.getUint32(0, true),
      b: view.getUint32(4, true),
      c: view.getUint32(8, true),
      d: view.getUint32(12, true),
    };
  }

  async crackChunk(hash, rangeStart, rangeSize) {
    if (!this.supported || !this.device) {
      throw new Error('WebGPU not initialized');
    }

    const target = this.parseHash(hash);

    // Params buffer: 6 x u32
    const paramsData = new Uint32Array([
      target.a, target.b, target.c, target.d,
      rangeStart, rangeSize
    ]);

    const paramsBuffer = this.device.createBuffer({
      size: paramsData.byteLength,
      usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
    });
    this.device.queue.writeBuffer(paramsBuffer, 0, paramsData);

    // Result buffer: found (u32) + key_value (u32)
    const resultBuffer = this.device.createBuffer({
      size: 8,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC,
    });

    const readBuffer = this.device.createBuffer({
      size: 8,
      usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
    });

    const bindGroup = this.device.createBindGroup({
      layout: this.pipeline.getBindGroupLayout(0),
      entries: [
        { binding: 0, resource: { buffer: paramsBuffer } },
        { binding: 1, resource: { buffer: resultBuffer } },
      ],
    });

    const workgroupSize = 256;
    const numWorkgroups = Math.ceil(rangeSize / workgroupSize);

    const encoder = this.device.createCommandEncoder();
    const pass = encoder.beginComputePass();
    pass.setPipeline(this.pipeline);
    pass.setBindGroup(0, bindGroup);
    pass.dispatchWorkgroups(numWorkgroups);
    pass.end();

    encoder.copyBufferToBuffer(resultBuffer, 0, readBuffer, 0, 8);
    this.device.queue.submit([encoder.finish()]);

    await readBuffer.mapAsync(GPUMapMode.READ);
    const resultData = new Uint32Array(readBuffer.getMappedRange());
    const found = resultData[0];
    const keyValue = resultData[1];
    readBuffer.unmap();

    // Cleanup
    paramsBuffer.destroy();
    resultBuffer.destroy();
    readBuffer.destroy();

    return { found: found !== 0, key: found ? keyValue : null };
  }

  // Process a batch of chunks, running them on the GPU
  async processChunks(chunks, ws, onProgress) {
    this.running = true;
    this._lastTime = performance.now();
    this._lastCount = 0;

    for (const chunk of chunks) {
      if (!this.running) break;

      const rangeSize = chunk.range_end - chunk.range_start;
      const batchSize = 65536; // Process in sub-batches for responsiveness

      for (let offset = 0; offset < rangeSize && this.running; offset += batchSize) {
        const size = Math.min(batchSize, rangeSize - offset);
        const start = chunk.range_start + offset;

        try {
          const result = await this.crackChunk(chunk.hash, start, size);

          this._lastCount += size;
          const elapsed = (performance.now() - this._lastTime) / 1000;
          if (elapsed > 0.5) {
            this.hashRate = Math.round(this._lastCount / elapsed);
            this._lastCount = 0;
            this._lastTime = performance.now();
            if (onProgress) onProgress(this.hashRate);
          }

          if (result.found) {
            return { found: true, key: result.key, chunkId: chunk.id, packetId: chunk.packet_id };
          }
        } catch (err) {
          console.error('GPU batch error:', err);
        }
      }

      // Report chunk complete
      ws.send(JSON.stringify({
        type: 'chunk_complete',
        chunkId: chunk.id,
        hashRate: this.hashRate
      }));
    }

    return { found: false };
  }

  stop() {
    this.running = false;
  }
}

// Fallback CPU cracker for browsers without WebGPU
class CPUCracker {
  constructor() {
    this.supported = true;
    this.running = false;
    this.hashRate = 0;
  }

  async init() { return true; }

  // Simple MD5 in JS (for CPU fallback)
  md5(str) {
    // Using SubtleCrypto is not available for MD5, so we use a minimal implementation
    function md5cycle(x, k) {
      let a = x[0], b = x[1], c = x[2], d = x[3];
      a = ff(a, b, c, d, k[0], 7, -680876936);   d = ff(d, a, b, c, k[1], 12, -389564586);
      c = ff(c, d, a, b, k[2], 17, 606105819);    b = ff(b, c, d, a, k[3], 22, -1044525330);
      a = ff(a, b, c, d, k[4], 7, -176418897);    d = ff(d, a, b, c, k[5], 12, 1200080426);
      c = ff(c, d, a, b, k[6], 17, -1473231341);  b = ff(b, c, d, a, k[7], 22, -45705983);
      a = ff(a, b, c, d, k[8], 7, 1770035416);    d = ff(d, a, b, c, k[9], 12, -1958414417);
      c = ff(c, d, a, b, k[10], 17, -42063);       b = ff(b, c, d, a, k[11], 22, -1990404162);
      a = ff(a, b, c, d, k[12], 7, 1804603682);   d = ff(d, a, b, c, k[13], 12, -40341101);
      c = ff(c, d, a, b, k[14], 17, -1502002290); b = ff(b, c, d, a, k[15], 22, 1236535329);
      a = gg(a, b, c, d, k[1], 5, -165796510);    d = gg(d, a, b, c, k[6], 9, -1069501632);
      c = gg(c, d, a, b, k[11], 14, 643717713);    b = gg(b, c, d, a, k[0], 20, -373897302);
      a = gg(a, b, c, d, k[5], 5, -701558691);    d = gg(d, a, b, c, k[10], 9, 38016083);
      c = gg(c, d, a, b, k[15], 14, -660478335);   b = gg(b, c, d, a, k[4], 20, -405537848);
      a = gg(a, b, c, d, k[9], 5, 568446438);     d = gg(d, a, b, c, k[14], 9, -1019803690);
      c = gg(c, d, a, b, k[3], 14, -187363961);    b = gg(b, c, d, a, k[8], 20, 1163531501);
      a = gg(a, b, c, d, k[13], 5, -1444681467);  d = gg(d, a, b, c, k[2], 9, -51403784);
      c = gg(c, d, a, b, k[7], 14, 1735328473);    b = gg(b, c, d, a, k[12], 20, -1926607734);
      a = hh(a, b, c, d, k[5], 4, -378558);       d = hh(d, a, b, c, k[8], 11, -2022574463);
      c = hh(c, d, a, b, k[11], 16, 1839030562);   b = hh(b, c, d, a, k[14], 23, -35309556);
      a = hh(a, b, c, d, k[1], 4, -1530992060);   d = hh(d, a, b, c, k[4], 11, 1272893353);
      c = hh(c, d, a, b, k[7], 16, -155497632);    b = hh(b, c, d, a, k[10], 23, -1094730640);
      a = hh(a, b, c, d, k[13], 4, 681279174);    d = hh(d, a, b, c, k[0], 11, -358537222);
      c = hh(c, d, a, b, k[3], 16, -722521979);    b = hh(b, c, d, a, k[6], 23, 76029189);
      a = hh(a, b, c, d, k[9], 4, -640364487);    d = hh(d, a, b, c, k[12], 11, -421815835);
      c = hh(c, d, a, b, k[15], 16, 530742520);    b = hh(b, c, d, a, k[2], 23, -995338651);
      a = ii(a, b, c, d, k[0], 6, -198630844);    d = ii(d, a, b, c, k[7], 10, 1126891415);
      c = ii(c, d, a, b, k[14], 15, -1416354905);  b = ii(b, c, d, a, k[5], 21, -57434055);
      a = ii(a, b, c, d, k[12], 6, 1700485571);   d = ii(d, a, b, c, k[3], 10, -1894986606);
      c = ii(c, d, a, b, k[10], 15, -1051523);      b = ii(b, c, d, a, k[1], 21, -2054922799);
      a = ii(a, b, c, d, k[8], 6, 1873313359);    d = ii(d, a, b, c, k[15], 10, -30611744);
      c = ii(c, d, a, b, k[6], 15, -1560198380);   b = ii(b, c, d, a, k[13], 21, 1309151649);
      a = ii(a, b, c, d, k[4], 6, -145523070);    d = ii(d, a, b, c, k[11], 10, -1120210379);
      c = ii(c, d, a, b, k[2], 15, 718787259);     b = ii(b, c, d, a, k[9], 21, -343485551);
      x[0] = add32(a, x[0]); x[1] = add32(b, x[1]); x[2] = add32(c, x[2]); x[3] = add32(d, x[3]);
    }

    function cmn(q, a, b, x, s, t) {
      a = add32(add32(a, q), add32(x, t));
      return add32((a << s) | (a >>> (32 - s)), b);
    }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }

    function md5blk(s) {
      const md5blks = [];
      for (let i = 0; i < 64; i += 4) {
        md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) +
          (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24);
      }
      return md5blks;
    }

    function add32(a, b) { return (a + b) & 0xFFFFFFFF; }

    function rhex(n) {
      const hc = '0123456789abcdef';
      let s = '';
      for (let j = 0; j < 4; j++)
        s += hc.charAt((n >> (j * 8 + 4)) & 0x0F) + hc.charAt((n >> (j * 8)) & 0x0F);
      return s;
    }

    function md5str(s) {
      let n = s.length;
      let state = [1732584193, -271733879, -1732584194, 271733878];
      let tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      let i;
      for (i = 64; i <= n; i += 64) {
        md5cycle(state, md5blk(s.substring(i - 64, i)));
      }
      s = s.substring(i - 64);
      let lo = s.length;
      for (i = 0; i < lo; i++) {
        tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
      }
      tail[i >> 2] |= 0x80 << ((i % 4) << 3);
      if (i > 55) {
        md5cycle(state, tail);
        for (i = 0; i < 16; i++) tail[i] = 0;
      }
      tail[14] = n * 8;
      md5cycle(state, tail);
      return rhex(state[0]) + rhex(state[1]) + rhex(state[2]) + rhex(state[3]);
    }

    return md5str(str);
  }

  async processChunks(chunks, ws, onProgress) {
    this.running = true;
    let totalHashed = 0;
    let lastTime = performance.now();

    for (const chunk of chunks) {
      if (!this.running) break;

      for (let i = chunk.range_start; i < chunk.range_end && this.running; i++) {
        const candidate = String(i);
        const hash = this.md5(candidate);

        if (hash === chunk.hash) {
          return { found: true, key: i, chunkId: chunk.id, packetId: chunk.packet_id };
        }

        totalHashed++;
        if (totalHashed % 10000 === 0) {
          const now = performance.now();
          const elapsed = (now - lastTime) / 1000;
          this.hashRate = Math.round(totalHashed / elapsed);
          if (onProgress) onProgress(this.hashRate);
          // Yield to event loop
          await new Promise(r => setTimeout(r, 0));
        }
      }

      ws.send(JSON.stringify({
        type: 'chunk_complete',
        chunkId: chunk.id,
        hashRate: this.hashRate
      }));

      totalHashed = 0;
      lastTime = performance.now();
    }

    return { found: false };
  }

  stop() {
    this.running = false;
  }
}

// Export the appropriate cracker
window.GPUCracker = GPUCracker;
window.CPUCracker = CPUCracker;
