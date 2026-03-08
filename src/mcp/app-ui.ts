/**
 * Inline MCP App HTML template for x428 precondition acceptance.
 *
 * Self-contained HTML with inline CSS/JS — no build step required.
 * Uses the postMessage JSON-RPC protocol to communicate with the MCP host.
 *
 * Flow:
 * 1. App receives tool result via ontoolresult notification
 * 2. If structuredContent.x428Status === "pending", renders precondition cards
 * 3. User clicks Accept → app calls x428/attest server tool
 * 4. App re-calls the original tool (structuredContent.toolName/toolArgs)
 * 5. Second call succeeds (token cached), app shows result
 */
export function buildAppHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>x428 Precondition Gate</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: var(--font-sans, system-ui, -apple-system, sans-serif);
    background: var(--color-background-primary, #fff);
    color: var(--color-text-primary, #1a1a1a);
    padding: 16px;
    line-height: 1.5;
  }

  .container { max-width: 480px; margin: 0 auto; }

  h2 {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 12px;
    color: var(--color-text-primary, #1a1a1a);
  }

  .card {
    border: 1px solid var(--color-border-primary, #e0e0e0);
    border-radius: var(--border-radius-lg, 8px);
    padding: 14px;
    margin-bottom: 10px;
    background: var(--color-background-secondary, #f8f8f8);
  }

  .card-type {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--color-text-secondary, #666);
    margin-bottom: 6px;
  }

  .card-detail {
    font-size: 13px;
    color: var(--color-text-primary, #1a1a1a);
  }

  .card-detail a {
    color: var(--color-accent-primary, #0066cc);
    text-decoration: underline;
  }

  .actions {
    display: flex;
    gap: 10px;
    margin-top: 16px;
  }

  .btn {
    flex: 1;
    padding: 10px 16px;
    border-radius: var(--border-radius-md, 6px);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    border: 1px solid transparent;
    transition: opacity 0.15s;
  }

  .btn:hover { opacity: 0.85; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }

  .btn-accept {
    background: var(--color-accent-primary, #0066cc);
    color: #fff;
  }

  .btn-decline {
    background: transparent;
    border-color: var(--color-border-primary, #e0e0e0);
    color: var(--color-text-secondary, #666);
  }

  .status {
    text-align: center;
    padding: 24px;
    font-size: 14px;
    color: var(--color-text-secondary, #666);
  }

  .status.accepted { color: var(--color-accent-primary, #0066cc); }
  .status.error { color: #cc3300; }

  .spinner {
    display: inline-block;
    width: 16px;
    height: 16px;
    border: 2px solid var(--color-border-primary, #e0e0e0);
    border-top-color: var(--color-accent-primary, #0066cc);
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
    margin-right: 8px;
    vertical-align: middle;
  }

  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="container" id="root">
  <div class="status">Waiting for tool result...</div>
</div>

<script>
(function() {
  "use strict";

  // --- Minimal postMessage JSON-RPC client ---
  let requestId = 0;
  const pending = new Map();
  let hostContext = null;
  let toolResultData = null;

  function sendRpc(method, params) {
    const id = ++requestId;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      window.parent.postMessage({ jsonrpc: "2.0", id, method, params }, "*");
    });
  }

  function sendNotification(method, params) {
    window.parent.postMessage({ jsonrpc: "2.0", method, params }, "*");
  }

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (!msg || msg.jsonrpc !== "2.0") return;

    // Response to our request
    if (msg.id != null && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(msg.error.message || "RPC error"));
      else resolve(msg.result);
      return;
    }

    // Notification from host
    if (msg.method === "ui/notifications/tool-result") {
      toolResultData = msg.params;
      handleToolResult(msg.params);
    } else if (msg.method === "ui/notifications/host-context-changed") {
      hostContext = { ...hostContext, ...msg.params };
      applyTheme();
    } else if (msg.method === "ui/notifications/tool-cancelled") {
      showStatus("Tool call cancelled.", "error");
    }
  });

  // --- Initialize ---
  async function init() {
    try {
      const result = await sendRpc("ui/initialize", {
        appInfo: { name: "x428-guard", version: "0.1.0" },
        capabilities: {},
        protocolVersion: "2026-01-26"
      });
      hostContext = result.hostContext || {};
      applyTheme();
    } catch (e) {
      console.error("Init failed:", e);
    }
  }

  function applyTheme() {
    if (!hostContext || !hostContext.styles) return;
    const styles = hostContext.styles;
    for (const [key, value] of Object.entries(styles)) {
      document.documentElement.style.setProperty(key, value);
    }
  }

  // --- Render preconditions ---
  function handleToolResult(params) {
    const sc = params.structuredContent;
    if (!sc || sc.x428Status !== "pending") {
      // Not an x428 pending result — show the regular content
      const text = params.content?.find(c => c.type === "text")?.text || "Done.";
      showStatus(text, "accepted");
      return;
    }

    const root = document.getElementById("root");
    let html = '<h2>Precondition Acceptance Required</h2>';

    for (const p of sc.preconditions || []) {
      html += '<div class="card">';
      if (p.type === "tos") {
        html += '<div class="card-type">Terms of Service</div>';
        html += '<div class="card-detail">';
        html += 'Please review the <a href="' + escapeHtml(p.documentUrl || "#") + '" target="_blank">Terms of Service</a>';
        if (p.tosVersion) html += ' (v' + escapeHtml(p.tosVersion) + ')';
        html += '</div>';
      } else if (p.type === "age") {
        html += '<div class="card-type">Age Verification</div>';
        html += '<div class="card-detail">You must be ' + escapeHtml(String(p.minimumAge || 18)) + ' or older to continue.</div>';
      } else if (p.type === "identity") {
        html += '<div class="card-type">Identity Confirmation</div>';
        html += '<div class="card-detail">Please confirm your identity to proceed.</div>';
      }
      html += '</div>';
    }

    html += '<div class="actions">';
    html += '<button class="btn btn-decline" id="btn-decline">Decline</button>';
    html += '<button class="btn btn-accept" id="btn-accept">Accept</button>';
    html += '</div>';

    root.innerHTML = html;

    document.getElementById("btn-accept").addEventListener("click", () => onAccept(sc));
    document.getElementById("btn-decline").addEventListener("click", () => onDecline());
  }

  async function onAccept(sc) {
    const acceptBtn = document.getElementById("btn-accept");
    const declineBtn = document.getElementById("btn-decline");
    if (acceptBtn) { acceptBtn.disabled = true; acceptBtn.innerHTML = '<span class="spinner"></span>Confirming...'; }
    if (declineBtn) declineBtn.disabled = true;

    try {
      // Call the hidden x428/attest tool to build + verify attestation
      const attestResult = await sendRpc("tools/call", {
        name: "x428/attest",
        arguments: {
          challengeId: sc.challengeId,
          accepted: true
        }
      });

      if (attestResult.isError) {
        showStatus("Attestation failed: " + (attestResult.content?.[0]?.text || "Unknown error"), "error");
        return;
      }

      // Re-call the original tool — token is now cached
      const toolResult = await sendRpc("tools/call", {
        name: sc.toolName,
        arguments: sc.toolArgs || {}
      });

      // Show success and the tool result
      const text = toolResult.content?.find(c => c.type === "text")?.text || "Accepted.";
      showStatus(text, "accepted");
    } catch (e) {
      showStatus("Error: " + e.message, "error");
    }
  }

  function onDecline() {
    showStatus("Preconditions declined. Tool access denied.", "error");
  }

  function showStatus(message, className) {
    const root = document.getElementById("root");
    root.innerHTML = '<div class="status ' + (className || "") + '">' + escapeHtml(message) + '</div>';
    notifySize();
  }

  function notifySize() {
    const height = document.documentElement.scrollHeight;
    sendNotification("ui/notifications/size-changed", { height });
  }

  function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // Start
  init();

  // Notify host of initial size
  new ResizeObserver(() => notifySize()).observe(document.documentElement);
})();
</script>
</body>
</html>`;
}
