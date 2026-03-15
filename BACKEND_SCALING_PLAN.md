# Backend Responsiveness Investigation & Migration Plan

## Problem Summary

Workers report long idle gaps between finishing work and receiving new assignments, especially when they request batches larger than 5 chunks. At the same time, clients asking for smaller batches appear to get work more consistently.

## Findings From Current Server Implementation

1. **Work is only allocated when a worker sends `request_work`.**
   The server does not proactively top up a worker's queue; it reacts to explicit requests. If the client asks infrequently (or only after draining a large local batch), that worker can idle between batches.

2. **Batch sizing is effectively a hard cap based on in-flight chunk count.**
   `assignWorkRespectingInFlight()` computes capacity as `requestedCount - alreadyAssigned`. If a worker still has assigned chunks, it receives nothing until it drops below this threshold, which can bias scheduling toward workers with smaller request sizes.

3. **Centralized scheduling and DB access are single-process.**
   Even with decoder worker threads, chunk assignment and websocket request handling happen in the main Node.js process. Under load (many websocket messages, DB writes, stats broadcasts), queue response latency can rise.

4. **Chunk refill and maintenance are timer-based.**
   Background refill runs every 5s, stats every 2s, health checks every 30s. This helps throughput but introduces periodic behavior that can add tail latency when queues are briefly empty.

## Why This Feels Unfair With Multiple Clients

- Fast workers that request larger batches can hold in-flight chunks longer, so they are not topped up until they re-request.
- Small-batch workers call `request_work` more often and therefore win races for newly pending chunks.
- Assignment is first-available (`LIMIT ?`) rather than weighted by worker throughput and round-robin fairness.

## Recommended Architecture Direction

### Phase 1 (Immediate, keep Node.js): Improve scheduler fairness + responsiveness

Implement these changes before a language migration:

1. **Low-watermark prefetch policy per worker**
   - Store `desiredInFlight` per worker.
   - On `chunk_complete`, if assigned chunks for that worker drop below a threshold (e.g., 40% of desired), proactively push more work.

2. **Fair scheduler instead of request-race scheduling**
   - Maintain a priority queue by `deficit = desiredInFlight - assignedCount`.
   - Fill workers in rounds so one aggressive requester cannot monopolize pending chunks.

3. **Lease-based assignment with shorter renewals**
   - Keep chunk leases short (e.g., 30-60s), renewed by heartbeat or progress updates.
   - Requeue stale chunks quickly without waiting full 5 minutes.

4. **Move websocket IO and scheduling apart**
   - Keep websocket handler lightweight.
   - Push assignment decisions into an internal scheduler loop so `request_work` is enqueue-only and non-blocking.

5. **Add queue latency telemetry**
   - Track and publish:
     - `work_request_to_assignment_ms`
     - `worker_idle_gap_ms`
     - `chunks_assigned_per_worker`
   - Use this to prove fairness improvements before migration.

### Phase 2 (Near-term): Multi-process Node topology

If Phase 1 still misses SLOs, split responsibilities while staying in Node:

- **Scheduler service** (single writer to queue state)
- **Websocket gateway** (stateless, horizontally scaled)
- **Worker state + pub/sub** via Redis Streams / NATS
- **Queue state** in Postgres (or Redis + durable sink), avoid SQLite hot contention for concurrent writers

This gives real parallelism across CPU cores while minimizing rewrite risk.

### Phase 3 (Migration): Move control plane off Node.js

For “true multi-threaded” backend behavior, the strongest options are:

1. **Rust (Tokio)**
   - Best tail latency and memory efficiency.
   - Excellent websocket and async ecosystem.
   - Strong fit for high-frequency scheduling logic and lock-free/low-lock data structures.

2. **Go**
   - Fast developer velocity with strong concurrency primitives.
   - Great for websocket gateways and scheduling services.
   - Slightly higher GC tail-latency risk than Rust, but usually acceptable.

3. **Elixir/Erlang (BEAM)**
   - Best actor-model distribution and fault tolerance.
   - Excellent for large websocket fanout + soft real-time coordination.
   - Lower raw CPU throughput for heavy per-message compute than Rust/Go.

## Recommendation

**Do not jump directly from Node + SQLite to a full rewrite.**

1. Ship Phase 1 fairness fixes first (1-2 sprints).
2. If p95 assignment latency remains high, implement Phase 2 service split with Redis/Postgres.
3. For long-term scale, migrate scheduler + websocket control plane to **Rust** (preferred) or **Go**.

## Proposed Success Metrics

- p95 `request -> assignment` < 150 ms under 200 concurrent workers
- p99 worker idle gap between chunk completion and next assignment < 500 ms
- No worker gets <50% of expected assignment share over 5-minute windows when equally capable
- Queue throughput scales linearly (±20%) as websocket gateway instances are added

## Migration Risk Notes

- Biggest technical risk is **state consistency** during handoff (assigned/complete/requeue races).
- Mitigate with explicit chunk state machine + idempotent events:
  - `pending -> assigned(lease_id) -> completed`
  - Reject completions with stale lease IDs.
- Run dual-write shadow mode during migration to verify assignment parity before cutover.
