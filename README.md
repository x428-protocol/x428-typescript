# x428

TypeScript reference implementation of the [x428 Precondition Attestation Protocol](https://github.com/x428-protocol/spec).

x428 extends HTTP 428 ("Precondition Required") into a challenge-response handshake for AI agents. Servers issue precondition challenges (TOS acceptance, age verification, identity attestation); clients respond with signed attestation payloads.

## Quick Start — MCP Guard

Gate any MCP tool behind TOS/AGE confirmation with a single wrapper:

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { x428Guard } from "x428";

const server = new McpServer({ name: "my-server", version: "1.0.0" });

server.tool(
  "search",
  { query: { type: "string" } },
  x428Guard(
    {
      preconditions: [
        { type: "tos", documentUrl: "https://example.com/tos", tosVersion: "2.1" },
        { type: "age", minimumAge: 18 },
      ],
    },
    async (args, ctx) => {
      // Your tool logic — only runs after user accepts TOS and confirms age
      return { content: [{ type: "text", text: `Results for: ${args.query}` }] };
    },
  ),
);
```

When a user calls the guarded tool, the MCP client shows confirmation dialogs for each precondition. After acceptance, a token is cached so subsequent calls skip re-confirmation.

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
} from "x428";

// Generate a challenge
const challenge = generateChallenge(
  [{ type: "tos", documentUrl: "https://example.com/tos", tosVersion: "2.1" }],
  "https://api.example.com/data",
  { ttlSeconds: 300 },
);

// Verify an attestation payload
const resolver = new DidKeyResolver();
const nonceStore = new InMemoryNonceStore();
nonceStore.add(challenge.nonce);

const result = await verifyAttestation(challenge, payload, resolver, nonceStore);
// Returns AttestationToken on success, X428Error on failure
```

### Client-side

```typescript
import { buildAttestation } from "x428";

const payload = await buildAttestation(
  challenge,
  operatorDid,
  signingKey,
  [{ preconditionId: "p1", method: "self", confirmedAt: new Date().toISOString() }],
);
```

### Token Scope Matching

```typescript
import { scopeMatches, validateToken } from "x428";

scopeMatches("https://example.com/api/*", "https://example.com/api/data"); // true
scopeMatches("https://example.com/api/*", "https://example.com/api/v2/data"); // false
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

## Dependencies

- `@noble/curves` — Ed25519 (audited, no native deps)
- `canonicalize` — JCS (RFC 8785)
- `@modelcontextprotocol/sdk` — optional peer dependency (only needed for MCP guard)

## License

MIT
