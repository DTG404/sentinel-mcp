import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./lib/config.js";

const config = await loadConfig();
const server = new McpServer({ name: "sentinel", version: "1.0.0" });
const transport = new StdioServerTransport();
await server.connect(transport);
