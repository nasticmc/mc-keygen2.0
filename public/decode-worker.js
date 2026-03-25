// ── Decode Web Worker ────────────────────────────────────────────────────────
// Offloads clientTryDecrypt() calls from the main thread so the GPU pipeline
// is never starved by crypto.subtle microtasks.
//
// Acts as a filter stage: processes ALL candidates and returns every one that
// passes client-side verification.  The server performs authoritative
// decryption on the winners.
//
// Protocol:
//   IN  → { type:'decode', id, rawHex, candidates:[{channelName,keyHex,prefixHex}] }
//   OUT ← { type:'result', id, winners:[...matches], count, fallback? }

/* global parseMeshCorePacket, clientTryDecrypt */
importScripts('client-decoder.js');

const BATCH_SIZE = 200; // Process candidates in small batches to limit concurrency

self.onmessage = async (e) => {
  const { type, id, rawHex, candidates } = e.data;
  if (type !== 'decode') return;

  const count = candidates.length;

  // Quick-reject: parse packet once
  const parsed = parseMeshCorePacket(rawHex);
  if (!parsed || parsed.payloadType !== 5 /* GROUP_TEXT */) {
    self.postMessage({ type: 'result', id, winners: [], count, fallback: true });
    return;
  }

  // Process ALL candidates — collect every one that passes client-side decode
  const winners = [];
  for (let i = 0; i < count; i += BATCH_SIZE) {
    const batch = candidates.slice(i, Math.min(i + BATCH_SIZE, count));
    const results = await Promise.all(batch.map(async (m) => {
      const decoded = await clientTryDecrypt(rawHex, m.keyHex);
      if (decoded) return { ...m, clientDecoded: decoded };
      return null;
    }));
    for (const r of results) {
      if (r) winners.push(r);
    }
  }

  self.postMessage({ type: 'result', id, winners, count });
};
