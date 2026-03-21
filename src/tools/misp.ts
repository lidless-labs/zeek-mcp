import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export interface MispConfig {
  url: string;
  apiKey: string;
  verifySsl: boolean;
}

export function getMispConfig(): MispConfig {
  return {
    url: process.env.MISP_URL ?? "https://localhost",
    apiKey: process.env.MISP_API_KEY ?? "",
    verifySsl: process.env.MISP_VERIFY_SSL !== "false",
  };
}

async function mispRequest(
  config: MispConfig,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; data: unknown }> {
  const url = `${config.url}${path}`;
  const headers: Record<string, string> = {
    "Authorization": config.apiKey,
    "Content-Type": "application/json",
    "Accept": "application/json",
  };

  const tlsOptions: RequestInit = {};
  if (!config.verifySsl) {
    // Node 18+ supports this via --insecure-http-parser or env
    // For self-signed certs, we rely on NODE_TLS_REJECT_UNAUTHORIZED=0
  }

  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    ...tlsOptions,
  });

  const data = await response.json().catch(() => null);
  return { status: response.status, data };
}

export function registerMispTools(server: McpServer): void {
  const config = getMispConfig();

  server.tool(
    "misp_search_iocs",
    "Search MISP for indicators of compromise (IOCs). Look up IPs, domains, hashes, URLs, and other observables against MISP's threat intelligence database. Returns matching events, attributes, and context.",
    {
      value: z.string().describe("IOC value to search (IP, domain, hash, URL, email)"),
      type: z.string().optional().describe("Attribute type filter (ip-src, ip-dst, domain, md5, sha256, url, hostname, email-src)"),
      limit: z.number().int().min(1).max(100).default(20).describe("Max results"),
      includeEventInfo: z.boolean().default(true).describe("Include parent event details"),
    },
    async (params) => {
      try {
        if (!config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "MISP API key not configured. Set MISP_API_KEY environment variable." }],
            isError: true,
          };
        }

        const searchBody: Record<string, unknown> = {
          returnFormat: "json",
          value: params.value,
          limit: params.limit,
          includeEventTags: true,
        };

        if (params.type) {
          searchBody.type = params.type;
        }

        const result = await mispRequest(config, "POST", "/attributes/restSearch", searchBody);

        if (result.status !== 200) {
          return {
            content: [{ type: "text" as const, text: `MISP error (${result.status}): ${JSON.stringify(result.data)}` }],
            isError: true,
          };
        }

        const responseData = result.data as { response?: { Attribute?: unknown[] } };
        const attributes = responseData?.response?.Attribute ?? [];

        const matches = (attributes as Array<Record<string, unknown>>).map((attr) => ({
          id: attr.id,
          eventId: attr.event_id,
          category: attr.category,
          type: attr.type,
          value: attr.value,
          comment: attr.comment,
          toIds: attr.to_ids,
          timestamp: attr.timestamp ? new Date(parseInt(String(attr.timestamp)) * 1000).toISOString() : undefined,
          tags: Array.isArray(attr.Tag) ? (attr.Tag as Array<Record<string, unknown>>).map((t) => t.name) : [],
          eventInfo: (attr.Event as Record<string, unknown>)?.info,
          eventThreatLevel: (attr.Event as Record<string, unknown>)?.threat_level_id,
        }));

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              query: params.value,
              matchCount: matches.length,
              found: matches.length > 0,
              matches,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error searching MISP: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "misp_bulk_lookup",
    "Check multiple IOCs against MISP in a single call. Useful for batch-checking IPs, domains, or hashes found during Zeek/Suricata analysis.",
    {
      indicators: z.array(z.object({
        value: z.string().describe("IOC value"),
        type: z.string().optional().describe("Attribute type (ip-src, domain, md5, sha256, etc.)"),
        context: z.string().optional().describe("Where this IOC was found (e.g. 'Zeek conn.log src_ip')"),
      })).min(1).max(100).describe("List of indicators to check"),
    },
    async (params) => {
      try {
        if (!config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "MISP API key not configured. Set MISP_API_KEY environment variable." }],
            isError: true,
          };
        }

        const results: Array<{
          value: string;
          type?: string;
          context?: string;
          found: boolean;
          matchCount: number;
          topMatch?: {
            category: string;
            eventInfo: string;
            tags: string[];
            threatLevel: unknown;
          };
        }> = [];

        // Process in batches of 10 to avoid overwhelming MISP
        const batchSize = 10;
        for (let i = 0; i < params.indicators.length; i += batchSize) {
          const batch = params.indicators.slice(i, i + batchSize);

          const batchPromises = batch.map(async (indicator) => {
            const searchBody: Record<string, unknown> = {
              returnFormat: "json",
              value: indicator.value,
              limit: 5,
            };
            if (indicator.type) searchBody.type = indicator.type;

            try {
              const result = await mispRequest(config, "POST", "/attributes/restSearch", searchBody);
              const responseData = result.data as { response?: { Attribute?: unknown[] } };
              const attrs = (responseData?.response?.Attribute ?? []) as Array<Record<string, unknown>>;

              return {
                value: indicator.value,
                type: indicator.type,
                context: indicator.context,
                found: attrs.length > 0,
                matchCount: attrs.length,
                topMatch: attrs.length > 0 ? {
                  category: String(attrs[0].category ?? ""),
                  eventInfo: String((attrs[0].Event as Record<string, unknown>)?.info ?? ""),
                  tags: Array.isArray(attrs[0].Tag)
                    ? (attrs[0].Tag as Array<Record<string, unknown>>).map((t) => String(t.name))
                    : [],
                  threatLevel: (attrs[0].Event as Record<string, unknown>)?.threat_level_id,
                } : undefined,
              };
            } catch {
              return {
                value: indicator.value,
                type: indicator.type,
                context: indicator.context,
                found: false,
                matchCount: 0,
              };
            }
          });

          const batchResults = await Promise.all(batchPromises);
          results.push(...batchResults);
        }

        const hits = results.filter((r) => r.found);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalChecked: results.length,
              totalHits: hits.length,
              hitRate: `${((hits.length / results.length) * 100).toFixed(1)}%`,
              hits,
              clean: results.filter((r) => !r.found).map((r) => ({ value: r.value, type: r.type, context: r.context })),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error in bulk MISP lookup: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "misp_add_event",
    "Create a MISP event from NIDS findings to share threat intelligence. Includes attributes (IOCs), tags, and threat level classification.",
    {
      info: z.string().describe("Event description/title"),
      threatLevel: z.number().int().min(1).max(4).default(2).describe("1=High, 2=Medium, 3=Low, 4=Undefined"),
      analysis: z.number().int().min(0).max(2).default(1).describe("0=Initial, 1=Ongoing, 2=Complete"),
      distribution: z.number().int().min(0).max(3).default(0).describe("0=Org only, 1=Community, 2=Connected, 3=All"),
      tags: z.array(z.string()).optional().describe("Event tags (e.g. 'tlp:amber', 'type:OSINT')"),
      attributes: z.array(z.object({
        type: z.string().describe("Attribute type (ip-src, ip-dst, domain, md5, sha256, url, hostname)"),
        value: z.string().describe("Attribute value"),
        category: z.string().optional().describe("Category (Network activity, Payload delivery, etc.)"),
        comment: z.string().optional().describe("Context comment"),
        toIds: z.boolean().optional().describe("Use for IDS signature generation"),
      })).optional().describe("Attributes/IOCs to include"),
    },
    async (params) => {
      try {
        if (!config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "MISP API key not configured. Set MISP_API_KEY environment variable." }],
            isError: true,
          };
        }

        const event = {
          Event: {
            info: params.info,
            threat_level_id: String(params.threatLevel),
            analysis: String(params.analysis),
            distribution: String(params.distribution),
            Tag: params.tags?.map((t) => ({ name: t })) ?? [],
            Attribute: params.attributes?.map((a) => ({
              type: a.type,
              value: a.value,
              category: a.category ?? inferCategory(a.type),
              comment: a.comment ?? "",
              to_ids: a.toIds ?? true,
            })) ?? [],
          },
        };

        const result = await mispRequest(config, "POST", "/events/add", event);

        if (result.status !== 200) {
          return {
            content: [{ type: "text" as const, text: `MISP error (${result.status}): ${JSON.stringify(result.data)}` }],
            isError: true,
          };
        }

        const eventData = (result.data as { Event?: Record<string, unknown> })?.Event;

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              success: true,
              eventId: eventData?.id,
              uuid: eventData?.uuid,
              info: params.info,
              attributeCount: params.attributes?.length ?? 0,
              mispUrl: `${config.url}/events/view/${eventData?.id}`,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error creating MISP event: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function inferCategory(type: string): string {
  const categoryMap: Record<string, string> = {
    "ip-src": "Network activity",
    "ip-dst": "Network activity",
    "domain": "Network activity",
    "hostname": "Network activity",
    "url": "Network activity",
    "md5": "Payload delivery",
    "sha1": "Payload delivery",
    "sha256": "Payload delivery",
    "filename": "Payload delivery",
    "email-src": "Payload delivery",
    "email-dst": "Payload delivery",
    "user-agent": "Network activity",
  };
  return categoryMap[type] ?? "Other";
}
