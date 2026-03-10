/**
 * Cross-session integration test: verifies that accepted preconditions
 * persist across MCP sessions via KV (simulates Claude Desktop's
 * multi-session architecture: AppBridge + Model use separate DOs).
 *
 * Run: node packages/mcp/test/integration-cross-session.mjs
 */

const BASE = "https://demo.x428.org/mcp";

let globalRpcId = 0;

async function createSession(name) {
  let sessionId = null;

  async function rpc(method, params = {}, isNotification = false) {
    const id = isNotification ? undefined : ++globalRpcId;
    const body = { jsonrpc: "2.0", method, params };
    if (id != null) body.id = id;

    const headers = {
      "Content-Type": "application/json",
      Accept: "text/event-stream, application/json",
    };
    if (sessionId) headers["Mcp-Session-Id"] = sessionId;

    const res = await fetch(BASE, { method: "POST", headers, body: JSON.stringify(body) });
    const newSid = res.headers.get("mcp-session-id");
    if (newSid) sessionId = newSid;

    if (!res.ok) {
      const text = await res.text();
      console.error(`   [${name}] HTTP ${res.status}: ${text.slice(0, 300)}`);
      return null;
    }

    if (isNotification) return null;

    const text = await res.text();
    for (const line of text.split("\n")) {
      if (line.startsWith("data: ")) {
        try {
          const msg = JSON.parse(line.slice(6).trim());
          if (msg.id === id) return msg;
        } catch {}
      }
    }
    return null;
  }

  // Initialize
  await rpc("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: `x428-test-${name}`, version: "0.1.0" },
  });
  await rpc("notifications/initialized", {}, true);

  console.log(`   [${name}] Session: ${sessionId}`);
  return { rpc, name, getSessionId: () => sessionId };
}

async function main() {
  console.log("=== x428 Cross-Session Persistence Test ===\n");

  // Session A: Accept TOS precondition via search tool
  console.log("1. Creating Session A (simulates AppBridge)...");
  const sessionA = await createSession("A");

  console.log("\n2. [A] Calling 'search' — expect precondition challenge...");
  const searchResult = await sessionA.rpc("tools/call", { name: "search", arguments: { query: "test" } });
  const sc = searchResult?.result?.structuredContent;
  const searchContent = searchResult?.result?.content?.[0]?.text;
  if (searchContent?.includes("Search results")) {
    console.log("   [A] TOS already accepted from previous run (KV cached). Skipping attest step.");
  } else if (!sc?.challengeId) {
    console.error("   Unexpected result:", JSON.stringify(searchResult?.result).slice(0, 300));
    process.exit(1);
  } else {
    console.log(`   [A] challengeId: ${sc.challengeId}`);

    console.log("\n3. [A] Accepting precondition via x428-attest...");
    const attestResult = await sessionA.rpc("tools/call", {
      name: "x428-attest",
      arguments: { challengeId: sc.challengeId, accepted: true },
    });
    const ar = attestResult?.result;
    console.log(`   [A] Result: ${ar?.content?.[0]?.text}`);
    if (ar?.isError) {
      console.error("   Attestation failed!");
      process.exit(1);
    }

    // Wait for KV propagation (eventual consistency)
    console.log("\n4. Waiting 2s for KV propagation...");
    await new Promise((r) => setTimeout(r, 2000));
  }

  // Session B: New session — should NOT need TOS re-acceptance for search
  console.log("\n5. Creating Session B (simulates Model session)...");
  const sessionB = await createSession("B");

  console.log("\n6. [B] Calling 'search' — should pass through (TOS already accepted)...");
  const search2Result = await sessionB.rpc("tools/call", { name: "search", arguments: { query: "cross-session" } });
  const s2r = search2Result?.result;

  if (s2r?.structuredContent?.x428Status === "pending") {
    console.error("\n   FAIL: Session B still requires TOS acceptance!");
    console.error("   Preconditions:", JSON.stringify(s2r.structuredContent.preconditions));
    console.log("\n   This means KV cross-session persistence is NOT working.");
    process.exit(1);
  }

  if (s2r?.content?.[0]?.text?.includes("Search results")) {
    console.log(`   [B] Result: ${s2r.content[0].text.slice(0, 100)}`);
    console.log("\n   SUCCESS: Session B got results without re-accepting TOS!");
  } else {
    console.log("   Unexpected result:", JSON.stringify(s2r).slice(0, 300));
  }

  // Session B: Call 'lookup' — different precondition (age), should still require it
  console.log("\n7. [B] Calling 'lookup' — should still require age verification...");
  const lookupResult = await sessionB.rpc("tools/call", { name: "lookup", arguments: { id: "456" } });
  const lr = lookupResult?.result;

  if (lr?.structuredContent?.x428Status === "pending") {
    console.log("   [B] Correctly requires age verification (not yet accepted)");

    // Accept age precondition
    const ageChallengeId = lr.structuredContent.challengeId;
    console.log("\n8. [B] Accepting age precondition...");
    const ageAttest = await sessionB.rpc("tools/call", {
      name: "x428-attest",
      arguments: { challengeId: ageChallengeId, accepted: true },
    });
    console.log(`   [B] Result: ${ageAttest?.result?.content?.[0]?.text}`);

    if (!ageAttest?.result?.isError) {
      // Re-call lookup
      console.log("\n9. [B] Re-calling 'lookup'...");
      const lookup2 = await sessionB.rpc("tools/call", { name: "lookup", arguments: { id: "456" } });
      if (lookup2?.result?.content?.[0]?.text?.includes("Record 456")) {
        console.log(`   [B] Result: ${lookup2.result.content[0].text.slice(0, 100)}`);
        console.log("   SUCCESS: lookup works after age acceptance!");
      }
    }
  } else if (lr?.content?.[0]?.text?.includes("Record")) {
    console.log("   [B] Age already accepted (possibly from previous test run)");
  }

  // Session B: Call 'info' — requires BOTH TOS + age. Both should be accepted now.
  console.log("\n10. [B] Calling 'info' — requires both TOS + age (both should be accepted)...");
  const infoResult = await sessionB.rpc("tools/call", { name: "info", arguments: { topic: "cross-session" } });
  const ir = infoResult?.result;

  if (ir?.content?.[0]?.text?.includes("Detailed info")) {
    console.log(`   [B] Result: ${ir.content[0].text.slice(0, 100)}`);
    console.log("   SUCCESS: 'info' passed through — both preconditions satisfied!");
  } else if (ir?.structuredContent?.x428Status === "pending") {
    console.error("   FAIL: Still requires preconditions for 'info'");
    console.error("   Remaining:", JSON.stringify(ir.structuredContent.preconditions));
  } else {
    console.log("   Result:", JSON.stringify(ir).slice(0, 300));
  }

  console.log("\n=== All cross-session tests complete ===");
  process.exit(0);
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
