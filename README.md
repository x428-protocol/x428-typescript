# x428

TypeScript reference implementation of the [x428 Precondition Attestation Protocol](https://github.com/x428-protocol/spec).

x428 extends HTTP 428 ("Precondition Required") into a challenge-response handshake for AI agents. Servers issue precondition challenges (TOS acceptance, age verification, identity attestation); clients respond with signed attestation payloads.

## Packages

| Package | Description |
|---------|-------------|
| [`@x428/core`](packages/core/) | Core protocol — types, JCS canonicalization, signing, verification, token generation, DID resolution |
| [`@x428/mcp`](packages/mcp/) | MCP transport adapter — guard middleware, elicitation, MCP Apps UI |

```bash
npm install @x428/core          # core protocol only
npm install @x428/core @x428/mcp  # core + MCP adapter
```

## Development

Conformance test vectors are pulled from the [spec repo](https://github.com/x428-protocol/spec) via a git submodule (pinned to a spec release tag). `make test` will warn if the vectors are behind `origin/main`.

```bash
git clone --recurse-submodules https://github.com/x428-protocol/x428-typescript.git
cd x428-typescript
make setup    # install deps + init submodule
make test     # run conformance + unit tests (warns if vectors are stale)
make typecheck
make build
```

To pull updated conformance vectors from the spec:

```bash
make update-vectors   # fetches latest from spec repo
make test             # verify everything still passes
git add vendor/spec && git commit -m "update spec vectors"
```

## Quick Start — MCP Guard

Gate any MCP tool behind TOS/AGE confirmation:

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { x428Guard } from "@x428/mcp";

const mcpServer = new McpServer({ name: "my-server", version: "1.0.0" });

x428Guard(mcpServer, {
  preconditions: [
    { type: "tos", documentUrl: "https://example.com/tos", tosVersion: "2.1", documentHash: "sha256-abc" },
    { type: "age", minimumAge: 18 },
  ],
}, "search", {
  description: "Search things",
  inputSchema: { query: { type: "string" } },
}, async (args, extra) => {
  return { content: [{ type: "text", text: `Results for: ${args.query}` }] };
});
```

Or gate all tools at once:

```typescript
import { x428Protect } from "@x428/mcp";

x428Protect(mcpServer, {
  preconditions: [
    { type: "tos", documentUrl: "https://example.com/tos", tosVersion: "2.1", documentHash: "sha256-abc" },
  ],
});

// All tools registered after x428Protect() are automatically guarded
mcpServer.tool("search", { query: { type: "string" } }, async (args, extra) => {
  return { content: [{ type: "text", text: `Results for: ${args.query}` }] };
});
```

### Two guard modes

**`x428Guard`** — MCP Apps mode. Registers tools with `_meta.ui.resourceUri` pointing to a rich inline HTML acceptance UI. For clients that support [MCP Apps](https://modelcontextprotocol.io/docs/extensions/apps) (Claude Desktop, VS Code Copilot, MCP Inspector Apps tab).

**`x428GuardElicitation`** — Elicitation mode. Wraps tool handlers with `elicitInput()` confirmation dialogs. For clients that support MCP elicitation but not Apps (MCP Inspector Tools tab).

```typescript
import { x428Guard, x428GuardElicitation } from "@x428/mcp";

// Apps mode — registers tool with inline UI
x428Guard(mcpServer, { preconditions: [...] }, "search", { ... }, handler);

// Elicitation mode — wraps handler with confirmation dialog
server.tool("search", { ... },
  x428GuardElicitation({ server: server.server, preconditions: [...] }, handler),
);
```

Choose based on your target client. See the demo servers for complete examples.

## Demo Servers

Three demo servers are provided, sharing the same tool definitions:

### Elicitation mode (stdio)

Uses `x428GuardElicitation` with checkbox dialogs. Best for MCP Inspector's Tools tab.

```bash
# Run with MCP Inspector
npx @modelcontextprotocol/inspector npx tsx examples/demo-server.ts
```

### MCP Apps mode (HTTP)

Uses `x428Guard` with a rich inline HTML acceptance UI. Best for Claude Desktop and MCP Inspector's Apps tab.

```bash
# Start the server
npx tsx examples/demo-server-apps.ts

# Open MCP Inspector (in another terminal)
npx @modelcontextprotocol/inspector --transport http --server-url http://localhost:3428/mcp
```

For Claude Desktop, tunnel the HTTP server:

```bash
cloudflared tunnel --url http://localhost:3428
# Add https://<tunnel-url>/mcp as a Streamable HTTP server in Claude Desktop
```

### Cloudflare Workers mode (production-grade)

Uses `McpAgent` from the Cloudflare Agents SDK with Durable Object SQLite storage.
Persistent challenge/token state, replay protection, and attestation audit logging.

```bash
# Local development
cd examples/demo-server-workers
cp .dev.vars.example .dev.vars  # fill in values
npm install
npm run dev

# Connect MCP Inspector
npx @modelcontextprotocol/inspector --transport http --server-url http://localhost:8787/mcp

# Deploy
CLOUDFLARE_ACCOUNT_ID=your-account-id npm run deploy
```

All demos include three tools: `search` (TOS), `lookup` (age verification), `info` (TOS + age).

## Core Protocol API

### Server-side

```typescript
import {
  generateChallenge,
  verifyAttestation,
  generateToken,
  validateToken,
  DidKeyResolver,
  InMemoryNonceStore,
} from "@x428/core";

// Generate a challenge
const challenge = generateChallenge(
  [{ type: "tos", documentUrl: "https://example.com/tos", tosVersion: "2.1", documentHash: "sha256-abc" }],
  "https://api.example.com/data",
  { ttlSeconds: 300 },
);

// Verify an attestation payload
const resolver = new DidKeyResolver();
const nonceStore = new InMemoryNonceStore();

const result = await verifyAttestation(challenge, payload, resolver, nonceStore);
// Returns AttestationToken on success, X428Error on failure
```

### Client-side

```typescript
import { buildAttestation } from "@x428/core";

const payload = buildAttestation(
  challenge,
  operatorDid,
  signingKey,
  [{ preconditionId: "p1", type: "tos", method: "self", documentHash: "sha256-abc", confirmedAt: new Date().toISOString() }],
);
```

### Token Scope Matching

```typescript
import { scopeMatches, validateToken } from "@x428/core";

scopeMatches("https://example.com/api/*", "https://example.com/api/data"); // true
scopeMatches("https://example.com/api/*", "https://example.com/api/v2/data"); // false

// validateToken returns true or X428Error with specific error code
const result = validateToken(token, "https://example.com/api/data");
if (result !== true) {
  console.log(result.code); // "token_expired" or "token_scope_mismatch"
}
```

## Verification Order

`verifyAttestation` checks in the spec-mandated order:

1. Version check
2. Well-formed payload
3. Nonce match
4. Resource match
5. Expiry
6. Replay check
7. DID resolution
8. Signature verification
9. Attestation completeness
10. Per-type validation

Each step maps to a specific error code (e.g., `unsupported_version`, `invalid_signature`).

## Known Limitations

### VC Proof Verification (Simplified)

The spec requires `DataIntegrityProof/eddsa-rdfc-2022` for Verifiable Credential proofs, which uses RDFC-1.0 (RDF Dataset Canonicalization). This implementation uses JCS (RFC 8785) canonicalization instead. This means:

- **Self-attestation (`method: "self"`)** works correctly — this is the primary path for MCP use cases
- **VC attestation (`method: "vc"`)** works when VCs are generated by this library, but will not correctly verify VCs signed by third-party issuers using proper RDFC-1.0

Implementing full RDFC-1.0 requires a JSON-LD processor dependency. See [#1](https://github.com/x428-protocol/x428-typescript/issues/1) for tracking.

## Dependencies

### @x428/core
- `@noble/curves` — Ed25519 (audited, no native deps)
- `canonicalize` — JCS (RFC 8785)

### @x428/mcp
- `@x428/core`
- `@modelcontextprotocol/sdk` — optional peer dependency (MCP server)
- `@modelcontextprotocol/ext-apps` — optional peer dependency (rich inline UI)

## License

MIT
