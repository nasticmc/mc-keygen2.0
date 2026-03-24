# MC-Keygen 2.0

Distributed WebGPU hash cracking tool for MeshCore GroupText packets. A Node.js/Express backend distributes SHA-256 brute-force work chunks to browser clients that crack using WebGPU compute shaders.

## Features

- **WebGPU Acceleration** — WGSL compute shaders run SHA-256 key derivation on the GPU with automatic CPU fallback
- **Distributed Cracking** — Server splits the keyspace into 128M-candidate chunks, assigns them to connected browser workers, and recycles stale chunks after 5 minutes
- **MeshCore Packet Decoding** — Packets are decoded via `@michaelhart/meshcore-decoder` to extract the channel hash; only GroupText (type 5) packets are accepted
- **Known Key Matching** — Uploaded packets are checked against a database of known channel keys before queuing for cracking
- **Client-side Decoding** — Optional in-browser GroupText decryption using Web Crypto API for faster validation
- **Real-time Dashboard** — Live stats, progress tracking, hash rates, and worker status via WebSocket

## Quick Start

```bash
npm install
npm start
```

Open `http://localhost:3000` in a browser. For distributed cracking, open the URL from multiple machines/tabs.

## Architecture

```
┌─────────────┐     HTTP + WS        ┌─────────────────┐
│  Browser 1  │◄────────────────────►│                 │
│  (WebGPU)   │                      │   Express       │
├─────────────┤     HTTP + WS        │   Server        │
│  Browser 2  │◄────────────────────►│                 │
│  (WebGPU)   │                      │  ┌───────────┐  │
├─────────────┤     HTTP + WS        │  │  SQLite   │  │
│  Browser N  │◄────────────────────►│  │  Database │  │
│  (CPU)      │                      │  └───────────┘  │
└─────────────┘                      └─────────────────┘
```

Work distribution uses HTTP (POST `/api/worker/request-work`). WebSocket is used for real-time stats, notifications, and worker registration.

### Server (`server.js`)

- **Express** serves the static frontend and REST API
- **WebSocket** handles real-time worker registration, stats broadcast, and key-found notifications
- **SQLite** (via `better-sqlite3`) stores packets, known channels, work chunks, and candidate keys
- **MeshCore Decoder** (`@michaelhart/meshcore-decoder`) parses and decrypts packets via a worker-thread pool
- **Virtual chunk system** — work chunks are computed on-the-fly from packet keyspace math, not pre-generated as rows

### Frontend (5 Tabs)

| Tab | Purpose |
|-----|---------|
| **Upload Packets** | Paste raw GroupText packet hex data. Auto-checks against known keys before queuing. |
| **Cracking Queue** | View queue stats, progress, connected workers, hash rates. Start/stop cracking. |
| **Known Channels** | Manage known channel names with their hashes, keys, and prefixes. |
| **Packet Decoder** | Decode/decrypt packets manually with a given key. |
| **Decoded Packets** | View packets that have been successfully decrypted. |

### WebGPU Cracker (`public/gpu-cracker.js`)

- WGSL compute shader with 256-thread workgroups
- ~16.7M candidates per GPU dispatch (65535 workgroups × 256 threads)
- Ping-pong double buffering hides GPU read-back latency
- Falls back to a pure JavaScript SHA-256 implementation when WebGPU is unavailable

### Client Decoder (`public/client-decoder.js`)

- Decodes GroupText packets using Web Crypto API only (no extra dependencies)
- AES-128 ECB decryption + HMAC-SHA256 verification
- Runs in a dedicated Web Worker (`public/decode-worker.js`)

## Performance & Scaling

See `BACKEND_SCALING_PLAN.md` for an investigation and phased plan to reduce assignment latency, improve fairness across workers, and evaluate migration paths beyond Node.js.

## API

### Packets

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/packets` | List all packets |
| `POST` | `/api/packets` | Upload a GroupText packet (`{ rawData, crackConfig? }`) |
| `DELETE` | `/api/packets/:id` | Delete a packet and all associated work |
| `POST` | `/api/packets/:id/retry` | Re-queue cracking with new config |
| `POST` | `/api/packets/:id/auto-decrypt` | Try all candidate keys for a packet |
| `POST` | `/api/packets/:id/decode` | Re-decode a cracked packet |
| `GET` | `/api/packets/decoded` | List successfully decrypted packets |

### Decoding & Decryption

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/decode` | Decode a packet without saving |
| `POST` | `/api/decrypt` | Try to decrypt a packet with a given key |
| `POST` | `/api/derive` | Derive key and prefix from a channel name |
| `GET` | `/api/decoder-status` | MeshCore decoder availability and version |

### Known Channels

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/channels` | List all known channels |
| `POST` | `/api/channels` | Add a channel (`{ channelName, hash?, key?, prefix? }`) |
| `DELETE` | `/api/channels/:id` | Delete a known channel |

### Candidates

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/candidates/:packetId` | List candidate keys for a packet |
| `GET` | `/api/candidates` | List all candidates (limit 100) |

### Stats & Config

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/stats` | Queue stats, worker info, hash rates |
| `GET` | `/api/config` | Cracker config (chunk size, charsets) |

### Worker (HTTP-based work distribution)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/worker/register` | Register a worker |
| `POST` | `/api/worker/request-work` | Request work chunks (max 64) |
| `POST` | `/api/worker/chunk-complete` | Report completed chunk(s) |
| `POST` | `/api/worker/prefix-match` | Report a single prefix match |
| `POST` | `/api/worker/hashrate` | Update worker hash rate |

### WebSocket Messages

**Client → Server:**

| Type | Description |
|------|-------------|
| `worker_register` | Register worker with clientId |
| `request_work` | Request N work chunks |
| `chunk_complete` | Report finished chunk(s) with hash rate |
| `prefix_match` | Report a single prefix match candidate |
| `prefix_match_batch` | Report a batch of prefix matches |
| `hashrate_update` | Update worker hash rate |
| `keepalive` | Application-level ping |

**Server → Client:**

| Type | Description |
|------|-------------|
| `worker_hello` | Acknowledge registration with workerId |
| `server_status` | Server status message |
| `work` | Assigned work chunks with packet raw data |
| `stats` | Queue statistics, active job stats, hash rates |
| `worker_count` | Number of connected workers |
| `worker_update` | Individual worker hash rate update |
| `worker_removed` | Worker disconnected |
| `key_found` | Broadcast when a key is cracked |
| `candidate_found` | Broadcast when a candidate key is found |
| `packets` | Updated packet list |
| `candidates` | Updated candidate list |
| `channels` | Updated channel list |

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PORT` | `3000` | Server listen port |

Internal tuning constants in `server.js`:

| Constant | Default | Description |
|----------|---------|-------------|
| `CHUNK_SIZE` | `128,000,000` | Candidates per work chunk |
| `PAYLOAD_TYPE_GROUP_TEXT` | `5` | Only this packet type is accepted |
| `HEARTBEAT_INTERVAL_MS` | `15,000` | WebSocket ping interval (ms) |
| `HEARTBEAT_MISS_LIMIT` | `4` | Missed pings before disconnect |
| `WS_MAX_BUFFERED_BYTES` | `8 MB` | WebSocket backpressure threshold |

## Requirements

- Node.js 18+
- A browser with WebGPU support (Chrome 113+, Edge 113+) for GPU acceleration
- Falls back to CPU cracking in unsupported browsers
- WebGPU requires HTTPS in production (localhost is exempt)

## License

ISC
