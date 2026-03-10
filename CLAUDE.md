# CLAUDE.md — Agent Guide for MC-Keygen 2.0

## Project Overview

Distributed WebGPU hash cracking tool. Node.js/Express backend distributes MD5 brute-force work chunks to browser clients that crack using WebGPU compute shaders.

## Tech Stack

- **Backend:** Node.js, Express, `ws` (WebSocket), `better-sqlite3`
- **Frontend:** Vanilla HTML/CSS/JS (no framework), WebGPU (WGSL compute shaders)
- **Database:** SQLite file (`keygen.db`, gitignored)

## Project Structure

```
server.js              — Express server, REST API, WebSocket, work distribution
public/
  index.html           — Single page with 3-tab layout
  style.css            — Dark theme styles
  app.js               — Frontend logic, tab navigation, API calls, cracking loop
  gpu-cracker.js       — WebGPU compute shader (MD5) + CPU fallback
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
- **WebSocket for work distribution** — server pushes work chunks, clients report results in real-time
- **Chunk-based work distribution** — 256M keyspace split into 1M chunks. Stale chunks (assigned >5 min) get reassigned automatically
- **WebGPU with CPU fallback** — `GPUCracker` class uses WGSL compute shader; `CPUCracker` class provides pure JS MD5 for browsers without WebGPU

## Database Schema

Three tables:
- `packets` — uploaded raw packet data with hash, status, cracked key
- `known_channels` — channel name → hash/key/prefix mappings
- `work_chunks` — individual keyspace ranges assigned to workers

## Common Modification Patterns

**Adding a new API endpoint:** Add route in `server.js`, add prepared statement to `stmts` object if DB access needed.

**Modifying the hash algorithm:** Update the WGSL shader in `gpu-cracker.js` (the `MD5_WGSL` string) and the `CPUCracker.md5()` method. Server-side hashing is in the `extractHash()`, `generatePrefix()`, and `generateKey()` functions in `server.js`.

**Adding a new tab:** Add `<button class="tab">` and `<section class="tab-content">` in `index.html`. Tab switching is handled automatically by the click handler in `app.js`.

**Changing chunk size or keyspace:** Modify `CHUNK_SIZE` and `TOTAL_KEYSPACE` constants in `server.js`.

## Gotchas

- The WGSL shader string is embedded in `gpu-cracker.js` as a template literal — be careful with backticks
- WebGPU requires HTTPS in production (localhost is exempt)
- `better-sqlite3` is a native module — needs rebuild if Node version changes (`npm rebuild`)
- Express 5.x is used (not 4.x) — some middleware API differences
