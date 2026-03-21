import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { readLogFile, resolveLogPath } from "../parser/index.js";
import type { ZeekRecord } from "../types.js";
import { topN, groupBy } from "../query/aggregation.js";

export function registerDhcpTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_query_dhcp",
    "Search Zeek DHCP logs for lease assignments, device discovery, and hostname-to-IP mapping. Useful for asset inventory and identifying rogue devices.",
    {
      clientAddr: z.string().optional().describe("Client IP address"),
      mac: z.string().optional().describe("Client MAC address (partial match)"),
      hostname: z.string().optional().describe("Client hostname (partial match)"),
      assignedAddr: z.string().optional().describe("Assigned IP address"),
      msgType: z.string().optional().describe("DHCP message type (DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE, INFORM)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(1).max(10000).default(100).describe("Max results"),
    },
    async (params) => {
      try {
        const logPaths = resolveLogPath(config, "dhcp" as any);
        let allRecords: ZeekRecord[] = [];

        for (const p of logPaths) {
          try {
            const records = await readLogFile(p, config.logFormat);
            allRecords.push(...records);
          } catch {
            // skip
          }
        }

        // Apply time filtering
        if (params.timeFrom || params.timeTo) {
          const fromTs = params.timeFrom ? new Date(params.timeFrom).getTime() / 1000 : undefined;
          const toTs = params.timeTo ? new Date(params.timeTo).getTime() / 1000 : undefined;
          allRecords = allRecords.filter((r) => {
            if (fromTs && r.ts < fromTs) return false;
            if (toTs && r.ts > toTs) return false;
            return true;
          });
        }

        // Apply filters
        let filtered = allRecords;

        if (params.clientAddr) {
          filtered = filtered.filter((r) => String(r.client_addr ?? "") === params.clientAddr);
        }
        if (params.mac) {
          filtered = filtered.filter((r) =>
            String(r.mac ?? "").toLowerCase().includes(params.mac!.toLowerCase()),
          );
        }
        if (params.hostname) {
          filtered = filtered.filter((r) =>
            String(r.host_name ?? "").toLowerCase().includes(params.hostname!.toLowerCase()),
          );
        }
        if (params.assignedAddr) {
          filtered = filtered.filter((r) => String(r.assigned_addr ?? "") === params.assignedAddr);
        }
        if (params.msgType) {
          filtered = filtered.filter((r) =>
            String(r.msg_types ?? "").toUpperCase().includes(params.msgType!.toUpperCase()),
          );
        }

        // Sort by timestamp descending
        filtered.sort((a, b) => b.ts - a.ts);
        const results = filtered.slice(0, params.limit);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              count: results.length,
              leases: results.map(formatDhcp),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying DHCP: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_dhcp_asset_map",
    "Build an asset map from DHCP logs: MAC address to IP/hostname mappings. Useful for identifying all devices on the network and spotting unknown/rogue devices.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (params) => {
      try {
        const logPaths = resolveLogPath(config, "dhcp" as any);
        let allRecords: ZeekRecord[] = [];

        for (const p of logPaths) {
          try {
            const records = await readLogFile(p, config.logFormat);
            allRecords.push(...records);
          } catch {
            // skip
          }
        }

        if (params.timeFrom || params.timeTo) {
          const fromTs = params.timeFrom ? new Date(params.timeFrom).getTime() / 1000 : undefined;
          const toTs = params.timeTo ? new Date(params.timeTo).getTime() / 1000 : undefined;
          allRecords = allRecords.filter((r) => {
            if (fromTs && r.ts < fromTs) return false;
            if (toTs && r.ts > toTs) return false;
            return true;
          });
        }

        // Build MAC -> device mapping
        const devices = new Map<string, {
          mac: string;
          ips: Set<string>;
          hostnames: Set<string>;
          firstSeen: number;
          lastSeen: number;
          leaseCount: number;
        }>();

        for (const r of allRecords) {
          const mac = String(r.mac ?? "");
          if (!mac || mac === "-") continue;

          if (!devices.has(mac)) {
            devices.set(mac, {
              mac,
              ips: new Set(),
              hostnames: new Set(),
              firstSeen: r.ts,
              lastSeen: r.ts,
              leaseCount: 0,
            });
          }

          const device = devices.get(mac)!;
          const assignedAddr = String(r.assigned_addr ?? "");
          const clientAddr = String(r.client_addr ?? "");
          const hostname = String(r.host_name ?? "");

          if (assignedAddr && assignedAddr !== "-") device.ips.add(assignedAddr);
          if (clientAddr && clientAddr !== "-" && clientAddr !== "0.0.0.0") device.ips.add(clientAddr);
          if (hostname && hostname !== "-") device.hostnames.add(hostname);
          device.firstSeen = Math.min(device.firstSeen, r.ts);
          device.lastSeen = Math.max(device.lastSeen, r.ts);
          device.leaseCount++;
        }

        const assetMap = [...devices.values()]
          .sort((a, b) => b.lastSeen - a.lastSeen)
          .map((d) => ({
            mac: d.mac,
            ips: [...d.ips],
            hostnames: [...d.hostnames],
            firstSeen: new Date(d.firstSeen * 1000).toISOString(),
            lastSeen: new Date(d.lastSeen * 1000).toISOString(),
            leaseCount: d.leaseCount,
          }));

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalDevices: assetMap.length,
              totalDhcpRecords: allRecords.length,
              devices: assetMap,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error building asset map: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function formatDhcp(record: Record<string, unknown>): Record<string, unknown> {
  return {
    timestamp: record.ts ? new Date((record.ts as number) * 1000).toISOString() : undefined,
    uid: record.uid,
    clientAddr: record.client_addr,
    serverAddr: record.server_addr,
    mac: record.mac,
    hostname: record.host_name,
    assignedAddr: record.assigned_addr,
    leaseTime: record.lease_time,
    msgTypes: record.msg_types,
  };
}
