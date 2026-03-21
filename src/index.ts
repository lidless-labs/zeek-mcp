import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getConfig } from "./config.js";
import { registerConnectionTools } from "./tools/connections.js";
import { registerDnsTools } from "./tools/dns.js";
import { registerHttpTools } from "./tools/http.js";
import { registerSslTools } from "./tools/ssl.js";
import { registerFileTools } from "./tools/files.js";
import { registerNoticeTools } from "./tools/notices.js";
import { registerSshTools } from "./tools/ssh.js";
import { registerInvestigationTools } from "./tools/investigation.js";
import { registerSoftwareTools } from "./tools/software.js";
import { registerBeaconingTools } from "./tools/beaconing.js";
import { registerAnomalyTools } from "./tools/anomaly.js";
import { registerSuricataTools } from "./tools/suricata.js";
import { registerSensorTools } from "./tools/sensor.js";
import { registerDhcpTools } from "./tools/dhcp.js";
import { registerPcapTools } from "./tools/pcap.js";
import { registerTheHiveTools } from "./tools/thehive.js";
import { registerMispTools } from "./tools/misp.js";
import { registerJa3Tools } from "./tools/ja3.js";
import { registerBaselineTools } from "./tools/baseline.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";

const server = new McpServer({
  name: "zeek-mcp",
  version: "3.0.0",
  description:
    "MCP server for Zeek + Suricata NIDS with TheHive/MISP integration - query, analyze, hunt, and respond via AI",
});

const config = getConfig();

// Zeek log tools
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

// Analytics tools
registerBeaconingTools(server, config);
registerAnomalyTools(server, config);
registerJa3Tools(server, config);
registerBaselineTools(server, config);

// Suricata tools
registerSuricataTools(server);

// PCAP analysis
registerPcapTools(server);

// Incident response
registerTheHiveTools(server);
registerMispTools(server);

// Sensor management
registerSensorTools(server, config);

registerResources(server);
registerPrompts(server);

const transport = new StdioServerTransport();
await server.connect(transport);
