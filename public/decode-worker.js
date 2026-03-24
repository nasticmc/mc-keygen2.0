// ── Decode Web Worker ────────────────────────────────────────────────────────
// Offloads clientTryDecrypt() calls from the main thread so the GPU pipeline
// is never starved by crypto.subtle microtasks.
//
// Protocol:
//   IN  → { type:'decode', id, rawHex, candidates:[{channelName,keyHex,prefixHex}] }
//   OUT ← { type:'result', id, winner: null | {channelName,keyHex,prefixHex,clientDecoded}, count }

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
    self.postMessage({ type: 'result', id, winner: null, count, fallback: true });
    return;
  }

  // Process candidates in batches to limit concurrent crypto operations
  let winner = null;
  for (let i = 0; i < count && !winner; i += BATCH_SIZE) {
    const batch = candidates.slice(i, Math.min(i + BATCH_SIZE, count));
    const results = await Promise.all(batch.map(async (m) => {
      if (winner) return null;
      const decoded = await clientTryDecrypt(rawHex, m.keyHex);
      if (decoded) return { ...m, clientDecoded: decoded };
      return null;
    }));
    for (const r of results) {
      if (r && !winner) { winner = r; break; }
    }
  }

  self.postMessage({ type: 'result', id, winner, count });
};
