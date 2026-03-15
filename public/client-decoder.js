// ── Client-side MeshCore GroupText Decoder ──────────────────────────────────
// Decodes GroupText packets using the Web Crypto API only — no extra deps.
//
// Algorithm:
//   1. Parse MeshCore packet structure to extract the GroupText payload.
//   2. Verify HMAC-SHA256 (2-byte MAC) over ciphertext using channelSecret.
//   3. Decrypt with AES-128 ECB (simulated via AES-CBC — see aes128EcbDecrypt).
//   4. Parse decrypted payload: timestamp(4 LE) + flags(1) + UTF-8 text.
//
// Returns a decoded object compatible with server's markPacketCracked() on
// success, or null if the key is wrong or the packet type is not GroupText.

const ROUTE_TYPE_TRANSPORT_FLOOD = 0;
const ROUTE_TYPE_TRANSPORT_DIRECT = 3;
const PAYLOAD_TYPE_GROUP_TEXT = 5;

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Parse the MeshCore packet and return { payloadType, payloadBytes } or null.
function parseMeshCorePacket(hexData) {
  const bytes = hexToBytes(hexData);
  if (bytes.length < 2) return null;

  let offset = 0;
  const header = bytes[offset++];
  const routeType = header & 0x03;
  const payloadType = (header >> 2) & 0x0F;

  // Skip 4 transport-code bytes for Transport-type route
  if (routeType === ROUTE_TYPE_TRANSPORT_FLOOD || routeType === ROUTE_TYPE_TRANSPORT_DIRECT) {
    if (bytes.length < offset + 4) return null;
    offset += 4;
  }

  if (bytes.length < offset + 1) return null;
  const pathLength = bytes[offset++];
  if (bytes.length < offset + pathLength) return null;
  offset += pathLength;

  return { payloadType, payloadBytes: bytes.subarray(offset) };
}

// Simulate AES-128 ECB decryption using Web Crypto's AES-CBC.
//
// Web Crypto doesn't expose ECB mode, but CBC with IV=0 gives us ECB for
// block 0 directly (P[0] = AES_d(C[0]) XOR 0 = ECB_d(C[0])).  For blocks
// i>0 CBC XORs in C[i-1], so we undo that after decryption.
//
// To satisfy Web Crypto's mandatory PKCS7 check we append one crafted
// ciphertext block whose decryption yields exactly [0x00…0x01] — a valid
// single-byte padding value — so the library never throws.
//
// Steps:
//   1. Build extraBlock = first 16 bytes of AES-CBC-encrypt([0x00…0x01], IV=C[N-1])
//   2. Decrypt [C[0]…C[N-1], extraBlock] with CBC IV=0 → PKCS7 strips the 0x01
//   3. XOR blocks 1…N-1 with the previous ciphertext block to recover ECB output
async function aes128EcbDecrypt(ciphertextBytes, keyBytes) {
  if (ciphertextBytes.length === 0 || ciphertextBytes.length % 16 !== 0) return null;

  const N = ciphertextBytes.length / 16;
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['encrypt', 'decrypt']);

  // Step 1 — craft the extra block
  const lastBlock = ciphertextBytes.slice((N - 1) * 16);
  const paddingPlain = new Uint8Array(16);
  paddingPlain[15] = 0x01;
  const encOut = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: lastBlock }, key, paddingPlain));
  const extraBlock = encOut.subarray(0, 16);

  // Step 2 — CBC decrypt
  const extended = new Uint8Array(ciphertextBytes.length + 16);
  extended.set(ciphertextBytes, 0);
  extended.set(extraBlock, ciphertextBytes.length);
  const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, key, extended));

  // Step 3 — undo CBC XOR contributions for blocks 1…N-1
  const result = new Uint8Array(N * 16);
  result.set(decrypted.subarray(0, 16));
  for (let i = 1; i < N; i++) {
    const off = i * 16;
    for (let j = 0; j < 16; j++) result[off + j] = decrypted[off + j] ^ ciphertextBytes[(i - 1) * 16 + j];
  }
  return result;
}

// Try to decode a GroupText packet client-side with the given key hex string.
// Returns a decoded object on success, null if the MAC fails or packet type
// is not GroupText.  The returned object shape matches what the server stores
// in decrypted_json so markPacketCracked() works without modification.
async function clientTryDecrypt(hexData, channelKeyHex) {
  try {
    const parsed = parseMeshCorePacket(hexData);
    if (!parsed || parsed.payloadType !== PAYLOAD_TYPE_GROUP_TEXT) return null;

    const { payloadBytes } = parsed;
    if (payloadBytes.length < 3) return null;

    // GroupText payload: channelHash(1) + MAC(2) + ciphertext(rest)
    const macBytes = payloadBytes.subarray(1, 3);
    const ciphertext = payloadBytes.subarray(3);
    if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) return null;

    const keyBytes = hexToBytes(channelKeyHex);

    // 32-byte channel secret: 16-byte key padded with 16 zero bytes
    const channelSecret = new Uint8Array(32);
    channelSecret.set(keyBytes, 0);

    // Verify HMAC-SHA256: first 2 bytes must match MAC field
    const hmacKey = await crypto.subtle.importKey(
      'raw', channelSecret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, ciphertext));
    if (hmac[0] !== macBytes[0] || hmac[1] !== macBytes[1]) return null;

    // Decrypt
    const plain = await aes128EcbDecrypt(ciphertext, keyBytes);
    if (!plain || plain.length < 5) return null;

    // Parse: timestamp(4 LE) + flags(1) + UTF-8 message (null-terminated)
    const timestamp = plain[0] | (plain[1] << 8) | (plain[2] << 16) | (plain[3] << 24);
    const flags = plain[4];
    let text = new TextDecoder('utf-8').decode(plain.subarray(5));
    const nul = text.indexOf('\0');
    if (nul >= 0) text = text.substring(0, nul);

    // Split "sender: content" if present
    let sender, message;
    const colon = text.indexOf(': ');
    if (colon > 0 && colon < 50 && !/[:\[\]]/.test(text.substring(0, colon))) {
      sender = text.substring(0, colon);
      message = text.substring(colon + 2);
    } else {
      message = text;
    }

    // Shape matches MeshCorePacketDecoder output so server can store it as-is
    return {
      isValid: true,
      payload: {
        decoded: {
          type: PAYLOAD_TYPE_GROUP_TEXT,
          isValid: true,
          decrypted: { timestamp, flags, sender, message },
        },
      },
    };
  } catch (_) {
    return null;
  }
}
