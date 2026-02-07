import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery, type FilterDef } from "../query/engine.js";
import { groupBy, topN, countUnique } from "../query/aggregation.js";
import { shannonEntropy } from "../analytics/entropy.js";

export function registerDnsTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_query_dns",
    "Search Zeek DNS query logs. Supports wildcard domain matching, query type filtering, and response code filtering.",
    {
      query: z.string().optional().describe("Domain query (supports wildcards: *.evil.com)"),
      srcIp: z.string().optional().describe("Querying host IP"),
      qtype: z.string().optional().describe("Query type (A, AAAA, MX, TXT, CNAME, NS, PTR, SRV, SOA)"),
      rcode: z.string().optional().describe("Response code (NOERROR, NXDOMAIN, SERVFAIL, REFUSED)"),
      answers: z.string().optional().describe("Search in DNS answers"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(1).max(10000).default(100).describe("Max results"),
    },
    async (params) => {
      try {
        const filters: FilterDef[] = [];

        if (params.query) {
          filters.push({
            field: "query",
            op: params.query.includes("*") ? "wildcard" : "contains",
            value: params.query,
          });
        }
        if (params.srcIp) {
          filters.push({ field: "id.orig_h", op: params.srcIp.includes("/") ? "cidr" : "eq", value: params.srcIp });
        }
        if (params.qtype) {
          filters.push({ field: "qtype_name", op: "eq", value: params.qtype });
        }
        if (params.rcode) {
          filters.push({ field: "rcode_name", op: "eq", value: params.rcode });
        }
        if (params.answers) {
          filters.push({ field: "answers", op: "contains", value: params.answers });
        }

        const records = await executeQuery(config, {
          logType: "dns",
          filters,
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: params.limit,
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              count: records.length,
              queries: records.map(formatDns),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying DNS: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_dns_summary",
    "DNS query statistics - top queried domains, NXDOMAIN counts (potential DGA detection), query type distribution, and top DNS clients.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "dns",
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        const nxdomainRecords = records.filter(
          (r) => r.rcode_name === "NXDOMAIN",
        );

        const summary = {
          totalQueries: records.length,
          uniqueDomains: countUnique(records, "query"),
          uniqueClients: countUnique(records, "id.orig_h"),
          topQueriedDomains: topN(records, "query", 20),
          topClients: topN(records, "id.orig_h", 10),
          queryTypeDistribution: groupBy(records, "qtype_name"),
          responseCodeDistribution: groupBy(records, "rcode_name"),
          nxdomainCount: nxdomainRecords.length,
          topNxdomainDomains: topN(nxdomainRecords, "query", 20),
          topNxdomainClients: topN(nxdomainRecords, "id.orig_h", 10),
        };

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify(summary, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error generating DNS summary: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_dns_tunneling_check",
    "Detect potential DNS tunneling by analyzing query entropy, subdomain lengths, and TXT/NULL query volumes.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      entropyThreshold: z.number().default(3.5).describe("Shannon entropy threshold for flagging suspicious queries (default 3.5)"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "dns",
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        const suspicious: Array<{
          query: string;
          srcIp: string;
          entropy: number;
          subdomainLength: number;
          qtype: string;
          reason: string[];
        }> = [];

        const domainTxtCounts = new Map<string, number>();
        const domainQueryLengths = new Map<string, number[]>();

        for (const record of records) {
          const query = String(record.query ?? "");
          const srcIp = String(record["id.orig_h"] ?? "");
          const qtype = String(record.qtype_name ?? "");

          if (!query) continue;

          const parts = query.split(".");
          const subdomain = parts.length > 2 ? parts.slice(0, -2).join(".") : parts[0];
          const baseDomain = parts.length > 2 ? parts.slice(-2).join(".") : query;
          const entropy = shannonEntropy(subdomain);

          if (qtype === "TXT" || qtype === "NULL") {
            domainTxtCounts.set(baseDomain, (domainTxtCounts.get(baseDomain) ?? 0) + 1);
          }

          if (!domainQueryLengths.has(baseDomain)) {
            domainQueryLengths.set(baseDomain, []);
          }
          domainQueryLengths.get(baseDomain)!.push(query.length);

          const reasons: string[] = [];

          if (entropy > params.entropyThreshold) {
            reasons.push(`High entropy subdomain (${entropy.toFixed(2)})`);
          }
          if (subdomain.length > 40) {
            reasons.push(`Long subdomain (${subdomain.length} chars)`);
          }
          if (qtype === "TXT" || qtype === "NULL") {
            reasons.push(`Suspicious query type: ${qtype}`);
          }
          if (/^[a-z0-9+/=]+$/i.test(subdomain) && subdomain.length > 20) {
            reasons.push("Possible base64 encoded subdomain");
          }
          if (/^[0-9a-f]+$/i.test(subdomain) && subdomain.length > 20) {
            reasons.push("Possible hex encoded subdomain");
          }

          if (reasons.length > 0) {
            suspicious.push({
              query,
              srcIp,
              entropy,
              subdomainLength: subdomain.length,
              qtype,
              reason: reasons,
            });
          }
        }

        const highTxtDomains = [...domainTxtCounts.entries()]
          .filter(([, count]) => count > 10)
          .sort((a, b) => b[1] - a[1])
          .map(([domain, count]) => ({ domain, txtQueryCount: count }));

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalQueriesAnalyzed: records.length,
              suspiciousQueries: suspicious.length,
              entropyThreshold: params.entropyThreshold,
              suspicious: suspicious.slice(0, 100),
              highTxtQueryDomains: highTxtDomains,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error checking DNS tunneling: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function formatDns(record: Record<string, unknown>): Record<string, unknown> {
  return {
    timestamp: record.ts ? new Date((record.ts as number) * 1000).toISOString() : undefined,
    uid: record.uid,
    srcIp: record["id.orig_h"],
    query: record.query,
    qtype: record.qtype_name,
    rcode: record.rcode_name,
    answers: record.answers,
    ttls: record.TTLs,
  };
}
