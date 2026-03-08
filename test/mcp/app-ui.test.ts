import { describe, it, expect } from "vitest";
import { buildAppHtml } from "../../src/mcp/app-ui.js";

describe("buildAppHtml", () => {
  it("returns valid HTML document", () => {
    const html = buildAppHtml();
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("x428");
    expect(html).toContain("</html>");
  });

  it("implements postMessage JSON-RPC protocol", () => {
    const html = buildAppHtml();
    expect(html).toContain("ui/initialize");
    expect(html).toContain("postMessage");
    expect(html).toContain("ui/notifications/tool-result");
  });

  it("uses correct ui/initialize params", () => {
    const html = buildAppHtml();
    expect(html).toContain("appCapabilities");
    expect(html).not.toContain('"capabilities": {}');
    expect(html).toContain('protocolVersion: "2025-11-21"');
  });

  it("contains accept and decline UI", () => {
    const html = buildAppHtml();
    expect(html).toContain("Accept");
    expect(html).toContain("Decline");
  });

  it("handles pending x428Status from tool result", () => {
    const html = buildAppHtml();
    expect(html).toContain("x428Status");
    expect(html).toContain("pending");
  });

  it("calls x428/attest tool on accept", () => {
    const html = buildAppHtml();
    expect(html).toContain("x428/attest");
  });

  it("renders precondition types: tos, age, identity", () => {
    const html = buildAppHtml();
    expect(html).toContain("Terms of Service");
    expect(html).toContain("Age Verification");
    expect(html).toContain("Identity");
  });

  it("uses host theme CSS variables", () => {
    const html = buildAppHtml();
    expect(html).toContain("--color-background-primary");
    expect(html).toContain("--color-text-primary");
    expect(html).toContain("--font-sans");
  });
});
