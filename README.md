# x428

TypeScript reference implementation of the [x428 Precondition Attestation Protocol](https://github.com/x428-protocol/spec).

x428 extends HTTP 428 ("Precondition Required") into a challenge-response handshake for AI agents. Servers issue precondition challenges (TOS acceptance, age verification, identity attestation); clients respond with signed attestation payloads.

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
import { x428Guard } from "x428";

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
import { x428Protect } from "x428";

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

### Automatic MCP Apps support

When the MCP client supports [MCP Apps](https://modelcontextprotocol.io/docs/extensions/apps) (Claude Desktop, VS Code Copilot, etc.), the guard automatically renders a rich inline acceptance UI directly in the conversation — showing TOS documents, age requirements, and identity prompts with styled Accept/Decline buttons.

For clients without MCP Apps support, the guard falls back to standard MCP elicitation dialogs. No code changes needed — detection is automatic via capability negotiation at connection time.

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
import { buildAttestation } from "x428";

const payload = buildAttestation(
  challenge,
  operatorDid,
  signingKey,
  [{ preconditionId: "p1", type: "tos", method: "self", documentHash: "sha256-abc", confirmedAt: new Date().toISOString() }],
);
```

### Token Scope Matching

```typescript
import { scopeMatches, validateToken } from "x428";

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

- `@noble/curves` — Ed25519 (audited, no native deps)
- `canonicalize` — JCS (RFC 8785)
- `@modelcontextprotocol/sdk` — optional peer dependency (only needed for MCP guard)
- `@modelcontextprotocol/ext-apps` — optional peer dependency (enables rich inline UI for MCP Apps-capable clients)

## License

MIT
