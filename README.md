# MC-Keygen 2.0

Distributed hash cracking tool that uses WebGPU to accelerate MD5 brute-force across multiple browser clients. A central server breaks work into chunks and distributes them to connected workers via WebSocket.

## Features

- **WebGPU Acceleration** — WGSL compute shaders run MD5 brute-force on the GPU with automatic CPU fallback
- **Distributed Cracking** — Server splits the keyspace into 1M-key chunks, assigns them to connected browser workers, and reassigns stale chunks after 5 minutes
- **Known Key Matching** — Uploaded packets are checked against a database of known channel keys before queuing for cracking
- **Real-time Dashboard** — Live stats, progress tracking, hash rates, and worker status via WebSocket

## Quick Start

```bash
npm install
npm start
```

Open `http://localhost:3000` in a browser. For distributed cracking, open the URL from multiple machines/tabs.

## Architecture

```
┌─────────────┐     WebSocket      ┌─────────────────┐
│  Browser 1  │◄──────────────────►│                 │
│  (WebGPU)   │                    │   Express       │
├─────────────┤     WebSocket      │   Server        │
│  Browser 2  │◄──────────────────►│                 │
│  (WebGPU)   │                    │  ┌───────────┐  │
├─────────────┤     WebSocket      │  │  SQLite   │  │
│  Browser N  │◄──────────────────►│  │  Database │  │
│  (CPU)      │                    │  └───────────┘  │
└─────────────┘                    └─────────────────┘
```

### Server (`server.js`)

- **Express** serves the static frontend and REST API
- **WebSocket** handles real-time work distribution and result reporting
- **SQLite** (via `better-sqlite3`) stores packets, known channels, and work chunks
- Work chunks cover a 256M keyspace split into 1M-key segments

### Frontend (3 Tabs)

| Tab | Purpose |
|-----|---------|
| **Upload** | Paste raw packet hex data. Auto-checks against known keys before queuing. |
| **Cracking** | View queue stats, progress bar, connected workers, and hash rates. Start/stop cracking. |
| **Known Channels** | Manage known channel names with their hashes, keys, and prefixes. Adding a channel name auto-generates key and prefix. |

### WebGPU Cracker (`public/gpu-cracker.js`)

- WGSL compute shader with 256-thread workgroups
- Processes sub-batches of 64K candidates for UI responsiveness
- Falls back to a pure JavaScript MD5 implementation when WebGPU is unavailable

## Performance & Scaling

See `BACKEND_SCALING_PLAN.md` for an investigation and phased plan to reduce websocket assignment latency, improve fairness across workers, and evaluate migration paths beyond Node.js.

## API

### Packets

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/packets` | List all packets |
| `POST` | `/api/packets` | Upload a packet (`{ rawData: string }`) |
| `DELETE` | `/api/packets/:id` | Delete a packet and its work chunks |

### Known Channels

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/channels` | List all known channels |
| `POST` | `/api/channels` | Add a channel (`{ channelName, hash?, key?, prefix? }`) |
| `DELETE` | `/api/channels/:id` | Delete a known channel |

### Stats

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/stats` | Queue stats and connected worker info |

### WebSocket Messages

**Client → Server:**

| Type | Fields | Description |
|------|--------|-------------|
| `request_work` | `count` | Request N work chunks |
| `chunk_complete` | `chunkId`, `hashRate` | Report a finished chunk |
| `key_found` | `packetId`, `key`, `channelName?` | Report a cracked key |
| `hashrate_update` | `hashRate` | Update worker hash rate |

**Server → Client:**

| Type | Fields | Description |
|------|--------|-------------|
| `work` | `chunks[]` | Assigned work chunks |
| `stats` | `pending`, `assigned`, `completed`, `total` | Queue statistics |
| `worker_count` | `count` | Number of connected workers |
| `key_found` | `packetId`, `key` | Broadcast when a key is cracked |
| `packets` | `packets[]` | Updated packet list |
| `channels` | `channels[]` | Updated channel list |

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PORT` | `3000` | Server listen port |

Internal tuning constants in `server.js`:

| Constant | Default | Description |
|----------|---------|-------------|
| `CHUNK_SIZE` | `1,000,000` | Keys per work chunk |
| `TOTAL_KEYSPACE` | `256,000,000` | Total keyspace to search |

## Requirements

- Node.js 18+
- A browser with WebGPU support (Chrome 113+, Edge 113+) for GPU acceleration
- Falls back to CPU cracking in unsupported browsers

## License

ISC
