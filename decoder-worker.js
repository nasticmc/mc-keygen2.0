'use strict';
// ── Decoder Worker Thread ────────────────────────────────────────────────────
// Runs MeshCorePacketDecoder.decode() in a worker thread so the main event
// loop is never blocked while verifying prefix-match candidates.

const { parentPort } = require('worker_threads');
const { MeshCorePacketDecoder } = require('@michaelhart/meshcore-decoder');

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

function validateDecryptedContent(decodedPacket) {
  const payload = decodedPacket?.payload?.decoded;
  if (!payload) return { valid: false, reason: 'missing_payload' };

  const interestingPaths = ['decrypted', 'message', 'text', 'msg', 'content', 'payload'];
  const strings = [];

  function visit(value, path = '', depth = 0) {
    if (depth > 4 || strings.length > 20 || value === null || value === undefined) return;
    if (typeof value === 'string') { strings.push({ value, path }); return; }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) visit(value[i], `${path}[${i}]`, depth + 1);
      return;
    }
    if (typeof value === 'object') {
      for (const [key, inner] of Object.entries(value)) {
        visit(inner, path ? `${path}.${key}` : key, depth + 1);
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

parentPort.on('message', ({ id, hexData, channelKey }) => {
  try {
    const keyStore = MeshCorePacketDecoder.createKeyStore({ channelSecrets: [channelKey.trim()] });
    const options = { keyStore, attemptDecryption: true };
    const decoded = MeshCorePacketDecoder.decode(hexData, options);
    const payloadDecoded = decoded.payload?.decoded;
    const decrypted = payloadDecoded?.decrypted ?? payloadDecoded?.message ?? null;
    const validation = validateDecryptedContent(decoded);
    parentPort.postMessage({ id, success: decrypted !== null && validation.valid, decoded, channelKey });
  } catch (err) {
    parentPort.postMessage({ id, success: false, error: err.message, channelKey });
  }
});
