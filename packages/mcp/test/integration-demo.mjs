/**
 * Integration test: hits the deployed demo.x428.org MCP server
 * using Streamable HTTP transport to verify x428 guard + attest flow.
 *
 * Run: node packages/mcp/test/integration-demo.mjs
 */

const BASE = "https://demo.x428.org/mcp";

async function main() {
  console.log("=== x428 MCP Integration Test ===\n");

  let sessionId = null;

  // Helper: send JSON-RPC over Streamable HTTP, read SSE response
  let rpcId = 0;
  async function rpc(method, params = {}, isNotification = false) {
    const id = isNotification ? undefined : ++rpcId;
    const body = { jsonrpc: "2.0", method, params };
    if (id != null) body.id = id;

    const headers = { "Content-Type": "application/json", Accept: "text/event-stream, application/json" };
    if (sessionId) headers["Mcp-Session-Id"] = sessionId;

    console.log(`>> ${method}`, JSON.stringify(params).slice(0, 200));

    const res = await fetch(BASE, { method: "POST", headers, body: JSON.stringify(body) });

    // Capture session ID from response
    const newSessionId = res.headers.get("mcp-session-id");
    if (newSessionId) sessionId = newSessionId;

    if (!res.ok) {
      const text = await res.text();
      console.error(`   HTTP ${res.status}: ${text.slice(0, 500)}`);
      return null;
    }

    if (isNotification) {
      console.log(`   (notification, status ${res.status})`);
      return null;
    }

    // Parse SSE response
    const text = await res.text();
    const lines = text.split("\n");
    for (const line of lines) {
      if (line.startsWith("data: ")) {
        const data = line.slice(6).trim();
        if (!data) continue;
        try {
          const msg = JSON.parse(data);
          if (msg.id === id) {
            return msg;
          }
        } catch {}
      }
    }

    console.log(`   (raw response) ${text.slice(0, 500)}`);
    return null;
  }

  // Step 1: Initialize
  console.log("1. Initializing MCP session...");
  const initResult = await rpc("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "x428-test", version: "0.1.0" },
  });
  console.log("   Session ID:", sessionId);
  console.log("   Server:", JSON.stringify(initResult?.result?.serverInfo));
  console.log("   Capabilities:", JSON.stringify(initResult?.result?.capabilities)?.slice(0, 200));

  // Send initialized notification
  await rpc("notifications/initialized", {}, true);

  // Step 2: List tools
  console.log("\n2. Listing tools...");
  const listResult = await rpc("tools/list", {});
  const tools = listResult?.result?.tools || [];
  console.log("   Tools:", tools.map(t => t.name).join(", "));

  // Step 3: Call "search" tool — should return precondition challenge
  console.log("\n3. Calling 'search' tool (expect precondition challenge)...");
  const searchResult = await rpc("tools/call", { name: "search", arguments: { query: "test" } });
  const sr = searchResult?.result;
  console.log("   isError:", sr?.isError);
  console.log("   content:", JSON.stringify(sr?.content).slice(0, 300));
  console.log("   structuredContent:", JSON.stringify(sr?.structuredContent).slice(0, 500));

  const sc = sr?.structuredContent;
  if (!sc || !sc.challengeId) {
    console.error("   No structuredContent or challengeId!");
    // If there's text content, it might have gone through (token cached?)
    if (sr?.content?.[0]?.text?.includes("Search results")) {
      console.log("   Tool ran directly (no precondition needed — token cached?)");
    }
    process.exit(1);
  }

  console.log("   challengeId:", sc.challengeId);
  console.log("   preconditions:", JSON.stringify(sc.preconditions));

  // Step 4: Call x428-attest with the challengeId
  console.log("\n4. Calling 'x428-attest' tool...");
  const attestResult = await rpc("tools/call", {
    name: "x428-attest",
    arguments: { challengeId: sc.challengeId, accepted: true },
  });
  const ar = attestResult?.result;
  console.log("   isError:", ar?.isError);
  console.log("   content:", JSON.stringify(ar?.content).slice(0, 500));

  if (ar?.isError) {
    console.error("\n   ATTESTATION FAILED!");
    console.error("   Error text:", ar.content?.[0]?.text);
    process.exit(1);
  }

  console.log("\n   Attestation succeeded!");

  // Step 5: Re-call search — should now pass through
  console.log("\n5. Re-calling 'search' tool (expect actual result)...");
  const search2Result = await rpc("tools/call", { name: "search", arguments: { query: "hello world" } });
  const s2r = search2Result?.result;
  console.log("   isError:", s2r?.isError);
  console.log("   content:", JSON.stringify(s2r?.content).slice(0, 300));

  if (s2r?.content?.[0]?.text?.includes("Search results")) {
    console.log("\n   SUCCESS: Tool returned actual results after attestation!");
  } else if (s2r?.structuredContent?.x428Status === "pending") {
    console.error("\n   FAIL: Tool still asking for preconditions after attestation!");
    process.exit(1);
  }

  // Step 6: Call "lookup" (different tool, different precondition type) — should still need attestation
  console.log("\n6. Calling 'lookup' tool (different precondition: age)...");
  const lookupResult = await rpc("tools/call", { name: "lookup", arguments: { id: "123" } });
  const lr = lookupResult?.result;
  console.log("   isError:", lr?.isError);
  console.log("   structuredContent:", JSON.stringify(lr?.structuredContent).slice(0, 300));

  if (lr?.structuredContent?.x428Status === "pending") {
    console.log("   Correctly requires age verification (separate precondition)");
  } else if (lr?.content?.[0]?.text?.includes("Record 123")) {
    console.log("   Tool ran directly (age already accepted?)");
  }

  console.log("\n=== Done ===");
  process.exit(0);
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
