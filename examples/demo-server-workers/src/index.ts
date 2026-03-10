import { X428McpAgent } from "./mcp-agent.js";

// Export the DO class so Wrangler can bind it
export { X428McpAgent };

// Worker entry point — routes /mcp to the McpAgent
export default X428McpAgent.serve("/mcp");
