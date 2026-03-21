import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery, type FilterDef } from "../query/engine.js";
// Known malicious/suspicious JA3 hashes
// Source: https://sslbl.abuse.ch/ja3-fingerprints/ and community research
export const KNOWN_MALICIOUS_JA3: Record<string, string> = {
  "e7d705a3286e19ea42f587b344ee6865": "Tofsee Botnet",
  "6734f37431670b3ab4292b8f60f29984": "Tofsee Botnet",
  "4d7a28d6f2263ed61de88ca66eb011e3": "TrickBot",
  "c12f54a3f91dc7bafd92cb59fe009a35": "AsyncRAT",
  "72a589da586844d7f0818ce684948eea": "Metasploit Meterpreter",
  "3b5074b1b5d032e5620f69f9f700ff0e": "CobaltStrike",
  "a0e9f5d64349fb13191bc781f81f42e1": "CobaltStrike",
  "b742b407517bac9536a77a7b0fee28e9": "Dridex",
  "e35df3e00ca4ef31d42b34bebaa2f86e": "QakBot",
  "51c64c77e60f3980eea90869b68c58a8": "IcedID",
  "ec74a5c51106f0419184d0dd08fb05bc": "Emotet",
  "f436b9416f37d134cadd04886327d3e8": "Emotet (2022)",
  "3e5820e6b1b6e3c5aba2ca0e055c581b": "Bumblebee Loader",
};

export function registerJa3Tools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_ja3_fingerprints",
    "Extract and analyze JA3/JA3S TLS fingerprints from SSL logs. Identifies client TLS implementations and can detect known malicious fingerprints. JA3 fingerprints persist even when domains/IPs change, making them valuable for tracking threat actors.",
    {
      srcIp: z.string().optional().describe("Filter by source IP"),
      dstIp: z.string().optional().describe("Filter by destination IP"),
      serverName: z.string().optional().describe("Filter by SNI hostname"),
      ja3Hash: z.string().optional().describe("Search for specific JA3 hash"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(1).max(10000).default(500).describe("Max records to analyze"),
    },
    async (params) => {
      try {
        const filters: FilterDef[] = [];

        if (params.srcIp) {
          filters.push({ field: "id.orig_h", op: params.srcIp.includes("/") ? "cidr" : "eq", value: params.srcIp });
        }
        if (params.dstIp) {
          filters.push({ field: "id.resp_h", op: params.dstIp.includes("/") ? "cidr" : "eq", value: params.dstIp });
        }
        if (params.serverName) {
          filters.push({
            field: "server_name",
            op: params.serverName.includes("*") ? "wildcard" : "contains",
            value: params.serverName,
          });
        }

        const records = await executeQuery(config, {
          logType: "ssl",
          filters,
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: params.limit,
        });

        // Group by JA3 hash (from cert_chain_fps or ssl_history fields if available)
        // Zeek stores JA3 in separate ja3.log or as field in ssl.log depending on config
        // We also check for ja3 field directly
        const ja3Map = new Map<string, {
          hash: string;
          count: number;
          sources: Set<string>;
          destinations: Set<string>;
          serverNames: Set<string>;
          versions: Set<string>;
          ciphers: Set<string>;
          known?: string;
        }>();

        for (const record of records) {
          // Try to get JA3 from various possible fields
          const ja3 = String(record.ja3 ?? record.ja3_hash ?? "");
          const ja3s = String(record.ja3s ?? record.ja3s_hash ?? "");

          // Even without explicit JA3, we can fingerprint by cipher+version combo
          const cipher = String(record.cipher ?? "");
          const version = String(record.version ?? "");
          const srcIp = String(record["id.orig_h"] ?? "");
          const dstIp = String(record["id.resp_h"] ?? "");
          const sni = String(record.server_name ?? "");

          // Use JA3 if available, otherwise create a pseudo-fingerprint from cipher suite
          const fingerprintKey = ja3 || `${version}|${cipher}`;

          if (fingerprintKey === "|" || fingerprintKey === "-|-") continue;

          if (!ja3Map.has(fingerprintKey)) {
            ja3Map.set(fingerprintKey, {
              hash: ja3 || `pseudo:${fingerprintKey}`,
              count: 0,
              sources: new Set(),
              destinations: new Set(),
              serverNames: new Set(),
              versions: new Set(),
              ciphers: new Set(),
              known: ja3 ? KNOWN_MALICIOUS_JA3[ja3] : undefined,
            });
          }

          const entry = ja3Map.get(fingerprintKey)!;
          entry.count++;
          if (srcIp && srcIp !== "-") entry.sources.add(srcIp);
          if (dstIp && dstIp !== "-") entry.destinations.add(dstIp);
          if (sni && sni !== "-") entry.serverNames.add(sni);
          if (version && version !== "-") entry.versions.add(version);
          if (cipher && cipher !== "-") entry.ciphers.add(cipher);
        }

        // Filter by specific JA3 hash if requested
        let fingerprints = [...ja3Map.values()];
        if (params.ja3Hash) {
          fingerprints = fingerprints.filter((f) =>
            f.hash.toLowerCase().includes(params.ja3Hash!.toLowerCase()),
          );
        }

        // Sort by count descending
        fingerprints.sort((a, b) => b.count - a.count);

        const maliciousHits = fingerprints.filter((f) => f.known);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalRecordsAnalyzed: records.length,
              uniqueFingerprints: fingerprints.length,
              maliciousHits: maliciousHits.length,
              malicious: maliciousHits.map((f) => ({
                ja3: f.hash,
                malwareFamily: f.known,
                connectionCount: f.count,
                sources: [...f.sources],
                destinations: [...f.destinations],
                serverNames: [...f.serverNames].slice(0, 10),
              })),
              fingerprints: fingerprints.slice(0, 50).map((f) => ({
                hash: f.hash,
                connectionCount: f.count,
                uniqueSources: f.sources.size,
                uniqueDestinations: f.destinations.size,
                sources: [...f.sources].slice(0, 10),
                versions: [...f.versions],
                ciphers: [...f.ciphers].slice(0, 5),
                serverNames: [...f.serverNames].slice(0, 10),
                known: f.known,
              })),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error analyzing JA3 fingerprints: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_ja3_hunt",
    "Hunt for known malicious JA3 fingerprints across SSL logs. Compares all observed JA3 hashes against a built-in database of malware families (CobaltStrike, Emotet, TrickBot, etc.) and returns any matches.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      customHashes: z.array(z.object({
        hash: z.string().describe("JA3 hash to hunt for"),
        label: z.string().describe("Description of what this hash identifies"),
      })).optional().describe("Additional JA3 hashes to hunt for beyond the built-in database"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "ssl",
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        // Build combined lookup table
        const huntHashes = { ...KNOWN_MALICIOUS_JA3 };
        if (params.customHashes) {
          for (const custom of params.customHashes) {
            huntHashes[custom.hash] = custom.label;
          }
        }

        const hits: Array<{
          timestamp: string;
          srcIp: string;
          dstIp: string;
          dstPort: number;
          serverName: string;
          ja3Hash: string;
          malwareFamily: string;
          version: string;
          cipher: string;
          uid: string;
        }> = [];

        for (const record of records) {
          const ja3 = String(record.ja3 ?? record.ja3_hash ?? "");
          if (!ja3 || ja3 === "-") continue;

          const match = huntHashes[ja3];
          if (match) {
            hits.push({
              timestamp: record.ts ? new Date((record.ts as number) * 1000).toISOString() : "",
              srcIp: String(record["id.orig_h"] ?? ""),
              dstIp: String(record["id.resp_h"] ?? ""),
              dstPort: record["id.resp_p"] as number,
              serverName: String(record.server_name ?? ""),
              ja3Hash: ja3,
              malwareFamily: match,
              version: String(record.version ?? ""),
              cipher: String(record.cipher ?? ""),
              uid: String(record.uid ?? ""),
            });
          }
        }

        // Also analyze cipher/version combos for non-JA3 detection
        const weakTls = records.filter((r) => {
          const version = String(r.version ?? "");
          return version === "SSLv3" || version === "TLSv10" || version === "TLSv11";
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalRecordsAnalyzed: records.length,
              knownMaliciousHashes: Object.keys(huntHashes).length,
              ja3Hits: hits.length,
              deprecatedTlsConnections: weakTls.length,
              hits,
              deprecatedTls: weakTls.slice(0, 20).map((r) => ({
                timestamp: r.ts ? new Date((r.ts as number) * 1000).toISOString() : "",
                src: `${r["id.orig_h"]}:${r["id.orig_p"]}`,
                dst: `${r["id.resp_h"]}:${r["id.resp_p"]}`,
                version: r.version,
                cipher: r.cipher,
                serverName: r.server_name,
              })),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error hunting JA3: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}
