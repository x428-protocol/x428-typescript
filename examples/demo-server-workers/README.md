# x428 Demo Server (Cloudflare Workers)

Live at **demo.x428.org** — an MCP server demonstrating x428 precondition enforcement on Cloudflare Workers with Durable Objects.

## What It Does

Three demo tools, each guarded by x428 preconditions:

| Tool | Preconditions |
|------|--------------|
| `search` | TOS acceptance |
| `lookup` | Age verification (18+) |
| `info` | TOS + age |

When a client calls a guarded tool, the server returns a `structuredContent` challenge. After the user accepts, the client calls `x428-attest` to complete the attestation. Subsequent calls skip the challenge (token cached).

## Architecture

- **Durable Objects** — each MCP session runs in a `X428McpAgent` DO (via `agents` SDK)
- **KV** — accepted preconditions and challenge records are stored in Workers KV for cross-session persistence
- **Dual-write stores** — writes go to both in-memory Map (instant, same-DO) and KV (cross-session), reads check in-memory first

This dual-write pattern is needed because Claude Desktop creates separate DOs for its AppBridge and Model sessions. Without KV, accepting a precondition in one session isn't visible in the other.

## Configuration

### Accepted Precondition TTL

The `DualAcceptedPreconditionStore` constructor controls how long accepted preconditions remain valid:

```typescript
// In mcp-agent.ts
const acceptedPreconditionStore = new DualAcceptedPreconditionStore(
  this.env.X428_KV,
  "x428:accepted:",  // KV key prefix
  86400,             // TTL in seconds (default: 24 hours)
);
```

Common values: `3600` (1 hour), `86400` (1 day), `604800` (7 days). Cloudflare KV minimum TTL is 60 seconds.

### Challenge TTL

Challenge records expire after 5 minutes by default (set in `x428Guard` via `generateChallenge`). The KV TTL for challenges defaults to 300 seconds.

## Source Files

| File | Purpose |
|------|---------|
| `src/index.ts` | Worker entry point, routes `/mcp` to the DO |
| `src/mcp-agent.ts` | `X428McpAgent` DO — initializes stores, registers guarded tools |
| `src/demo-tools.ts` | Tool definitions (name, preconditions, handler) |
| `src/storage.ts` | Dual-write stores (KV + in-memory) and SQLite audit log |

## Development

```bash
npm install
npm run dev          # local dev server (wrangler)
npm run deploy       # deploy to Cloudflare
npm run typecheck    # type-check without emitting
```

## Testing

Integration tests hit the deployed server directly:

```bash
# Single-session flow (challenge → attest → re-call)
node ../../packages/mcp/test/integration-demo.mjs

# Cross-session persistence (accepted preconditions survive new sessions)
node ../../packages/mcp/test/integration-cross-session.mjs
```

## Infrastructure

- **Workers KV namespace:** bound as `X428_KV` in `wrangler.toml`
- **Custom domain:** `demo.x428.org`
- **DO migration:** SQLite-backed (`new_sqlite_classes`) for the audit log
