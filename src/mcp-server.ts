import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { ZeekConfig } from "./config.js";
import { getConfig } from "./config.js";
import { registerAnomalyTools } from "./tools/anomaly.js";
import { registerBaselineTools } from "./tools/baseline.js";
import { registerBeaconingTools } from "./tools/beaconing.js";
import { registerConnectionTools } from "./tools/connections.js";
import { registerDhcpTools } from "./tools/dhcp.js";
import { registerDnsTools } from "./tools/dns.js";
import { registerFileTools } from "./tools/files.js";
import { registerHttpTools } from "./tools/http.js";
import { registerInvestigationTools } from "./tools/investigation.js";
import { registerJa3Tools } from "./tools/ja3.js";
import { registerMispTools } from "./tools/misp.js";
import { registerNoticeTools } from "./tools/notices.js";
import { registerPcapTools } from "./tools/pcap.js";
import { registerSensorTools } from "./tools/sensor.js";
import { registerSoftwareTools } from "./tools/software.js";
import { registerSshTools } from "./tools/ssh.js";
import { registerSslTools } from "./tools/ssl.js";
import { registerSuricataTools } from "./tools/suricata.js";
import { registerTheHiveTools } from "./tools/thehive.js";
import { registerPrompts } from "./prompts.js";
import { registerResources } from "./resources.js";

export function createZeekMcpServer(config: ZeekConfig = getConfig()): McpServer {
  const server = new McpServer({
    name: "zeek-mcp",
    version: "3.1.0",
    description:
      "MCP server for Zeek + Suricata NIDS with TheHive/MISP integration - query, analyze, hunt, and respond via AI",
  });

  registerConnectionTools(server, config);
  registerDnsTools(server, config);
  registerHttpTools(server, config);
  registerSslTools(server, config);
  registerFileTools(server, config);
  registerNoticeTools(server, config);
  registerSshTools(server, config);
  registerInvestigationTools(server, config);
  registerSoftwareTools(server, config);
  registerDhcpTools(server, config);

  registerBeaconingTools(server, config);
  registerAnomalyTools(server, config);
  registerJa3Tools(server, config);
  registerBaselineTools(server, config);

  registerSuricataTools(server);
  registerPcapTools(server);
  registerTheHiveTools(server);
  registerMispTools(server);
  registerSensorTools(server, config);

  registerResources(server);
  registerPrompts(server);

  return server;
}

export function stripDraftSchemaFromTransport(transport: StdioServerTransport): void {
  const send = transport.send.bind(transport);
  (transport as unknown as { send: typeof transport.send }).send = (message) => {
    const rpcMessage = message as { result?: { tools?: unknown } };
    const tools = rpcMessage.result?.tools;
    if (Array.isArray(tools)) {
      for (const tool of tools) {
        if (tool?.inputSchema) delete tool.inputSchema.$schema;
        if (tool?.outputSchema) delete tool.outputSchema.$schema;
      }
    }
    return send(message);
  };
}

export async function serveMcp(config: ZeekConfig = getConfig()): Promise<void> {
  const server = createZeekMcpServer(config);
  const transport = new StdioServerTransport();
  stripDraftSchemaFromTransport(transport);
  await server.connect(transport);
}
