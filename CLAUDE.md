# CLAUDE.md — Agent Guide for MC-Keygen 2.0

## Project Overview

Distributed WebGPU hash cracking tool. Node.js/Express backend distributes SHA-256 brute-force work chunks to browser clients that crack using WebGPU compute shaders.

## Tech Stack

- **Backend:** Node.js, Express, `ws` (WebSocket), `better-sqlite3`
- **Frontend:** Vanilla HTML/CSS/JS (no framework), WebGPU (WGSL compute shaders)
- **Database:** SQLite file (`keygen.db`, gitignored)

## Project Structure

```
server.js              — Express server, REST API, WebSocket, work distribution
public/
  index.html           — Single page with 4-tab layout
  style.css            — Dark theme styles
  app.js               — Frontend logic, tab navigation, API calls, cracking loop
  gpu-cracker.js       — WebGPU compute shader (SHA-256) + CPU fallback
```

## Commands

```bash
npm start              # Start the server (port 3000 by default)
PORT=8080 npm start    # Start on custom port
```

No test suite yet. No build step — frontend is plain JS served statically.

## Key Architecture Decisions

- **Single-page app with no build tooling** — keeps it simple, no bundler needed
- **SQLite over Postgres/Redis** — single-file database, zero config, good enough for this use case
- **WebSocket for work distribution** — server pushes work chunks, clients report results in real-time; 30s ping/pong heartbeat detects dead connections
- **Chunk-based work distribution** — keyspace split into 500K-candidate chunks. Stale chunks (assigned >5 min) get reassigned automatically
- **WebGPU with CPU fallback** — `GPUCracker` class uses WGSL compute shader; `CPUCracker` class provides pure JS SHA-256 for browsers without WebGPU
- **4M candidates per GPU batch** — each dispatch covers 4M candidates before yielding; result buffer holds 8192 match slots
- **Periodic stats broadcast** — server broadcasts queue stats to all clients every 2 seconds so the UI stays live during long GPU batches
- **loopRunning guard** — `app.js` uses a `loopRunning` boolean to prevent double-starting the cracking loop after WebSocket reconnect

## Database Schema

Four tables:
- `packets` — uploaded raw packet data with hash, status, cracked key
- `known_channels` — channel name → hash/key/prefix mappings
- `work_chunks` — individual keyspace ranges assigned to workers
- `candidate_keys` — candidate keys reported by workers, pending verification

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/packets` | List all packets |
| POST | `/api/packets` | Upload a packet (hex data) |
| DELETE | `/api/packets/:id` | Delete packet and all associated work |
| POST | `/api/packets/:id/retry` | Re-queue cracking with new config |
| POST | `/api/packets/:id/auto-decrypt` | Try all candidate keys for a packet |
| GET | `/api/channels` | List known channels |
| POST | `/api/channels` | Add a known channel |
| DELETE | `/api/channels/:id` | Remove a known channel |
| GET | `/api/stats` | Queue stats (pending/assigned/completed counts) |
| GET | `/api/config` | Cracker config (CHUNK_SIZE, charsets) — used by UI for estimated chunk count |
| GET | `/api/candidates/:packetId` | List candidate keys for a packet |
| POST | `/api/decode` | Decode a packet without saving |
| POST | `/api/decrypt` | Try to decrypt a packet with a given key |
| GET | `/api/decoder-status` | Whether the MeshCore packet decoder is loaded |
| GET | `/api/packets/decoded` | List packets that have been successfully decrypted |

## Common Modification Patterns

**Adding a new API endpoint:** Add route in `server.js`, add prepared statement to `stmts` object if DB access needed.

**Modifying the hash algorithm:** Update the WGSL shader in `gpu-cracker.js` (the `SHA256_WGSL` string) and the `CPUCracker.sha256()` method. Server-side key derivation is in `derivePrefix()` and `deriveAll()` in `server.js`.

**Adding a new tab:** Add `<button class="tab">` and `<section class="tab-content">` in `index.html`. Tab switching is handled automatically by the click handler in `app.js`.

**Changing chunk size:** Modify `CHUNK_SIZE` in `server.js`. The `/api/config` endpoint exposes this to the frontend automatically.

## Gotchas

- The WGSL shader string is embedded in `gpu-cracker.js` as a template literal — be careful with backticks
- WebGPU requires HTTPS in production (localhost is exempt)
- `better-sqlite3` is a native module — needs rebuild if Node version changes (`npm rebuild`)
- Express 5.x is used (not 4.x) — some middleware API differences
- After a WebSocket reconnect, `pendingWorkResolvers` and `queuedWorkMessages` are cleared in `ws.onopen` to drop stale work from before the disconnect
- The `loopRunning` guard in `app.js` prevents the cracking loop from being started twice if `onopen` fires before the old loop fully exits
