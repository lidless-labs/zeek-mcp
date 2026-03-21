import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export interface TheHiveConfig {
  url: string;
  apiKey: string;
}

export function getTheHiveConfig(): TheHiveConfig {
  return {
    url: process.env.THEHIVE_URL ?? "http://localhost:9000",
    apiKey: process.env.THEHIVE_API_KEY ?? "",
  };
}

async function theHiveRequest(
  config: TheHiveConfig,
  method: string,
  path: string,
  body?: unknown,
  timeoutMs = 30000,
): Promise<{ status: number; data: unknown }> {
  const url = `${config.url}${path}`;
  const headers: Record<string, string> = {
    "Authorization": `Bearer ${config.apiKey}`,
    "Content-Type": "application/json",
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    const data = await response.json().catch(() => null);
    return { status: response.status, data };
  } finally {
    clearTimeout(timeout);
  }
}

export function registerTheHiveTools(server: McpServer): void {
  const config = getTheHiveConfig();

  server.tool(
    "thehive_create_alert",
    "Create a TheHive alert from NIDS findings. Includes observables (IPs, domains, hashes), severity, TLP marking, and alert description. Use after investigating suspicious activity in Zeek/Suricata logs.",
    {
      title: z.string().describe("Alert title"),
      description: z.string().describe("Detailed description of the finding"),
      severity: z.number().int().min(1).max(4).default(2).describe("Severity: 1=Low, 2=Medium, 3=High, 4=Critical"),
      tlp: z.number().int().min(0).max(4).default(2).describe("TLP: 0=Clear, 1=Green, 2=Amber, 3=Amber+Strict, 4=Red"),
      pap: z.number().int().min(0).max(3).default(2).describe("PAP: 0=Clear, 1=Green, 2=Amber, 3=Red"),
      type: z.string().default("nids-alert").describe("Alert type identifier"),
      source: z.string().default("zeek-mcp").describe("Alert source"),
      sourceRef: z.string().optional().describe("Source reference (e.g. Suricata SID, Zeek UID)"),
      tags: z.array(z.string()).optional().describe("Tags for categorization"),
      observables: z.array(z.object({
        dataType: z.enum(["ip", "domain", "url", "hash", "filename", "mail", "user-agent", "other"]),
        data: z.string().describe("Observable value"),
        message: z.string().optional().describe("Context for this observable"),
        tlp: z.number().int().min(0).max(4).optional(),
        ioc: z.boolean().optional().describe("Mark as IOC"),
        sighted: z.boolean().optional().describe("Mark as sighted"),
        tags: z.array(z.string()).optional(),
      })).optional().describe("Observables to attach to the alert"),
    },
    async (params) => {
      try {
        if (!config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "TheHive API key not configured. Set THEHIVE_API_KEY environment variable." }],
            isError: true,
          };
        }

        const alert = {
          title: params.title,
          description: params.description,
          severity: params.severity,
          tlp: params.tlp,
          pap: params.pap,
          type: params.type,
          source: params.source,
          sourceRef: params.sourceRef ?? `zeek-${Date.now()}`,
          tags: params.tags ?? ["nids", "zeek-mcp"],
        };

        const result = await theHiveRequest(config, "POST", "/api/v1/alert", alert);

        if (result.status !== 201) {
          return {
            content: [{ type: "text" as const, text: `TheHive error (${result.status}): ${JSON.stringify(result.data)}` }],
            isError: true,
          };
        }

        const alertData = result.data as Record<string, unknown>;
        const alertId = alertData._id as string;

        // Add observables if provided
        if (params.observables && params.observables.length > 0) {
          for (const obs of params.observables) {
            await theHiveRequest(config, "POST", `/api/v1/alert/${alertId}/observable`, {
              dataType: obs.dataType,
              data: obs.data,
              message: obs.message ?? "",
              tlp: obs.tlp ?? params.tlp,
              ioc: obs.ioc ?? false,
              sighted: obs.sighted ?? true,
              tags: obs.tags ?? [],
            });
          }
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              success: true,
              alertId,
              title: params.title,
              severity: params.severity,
              observableCount: params.observables?.length ?? 0,
              theHiveUrl: `${config.url}/index.html#!/alert/${alertId}/details`,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error creating TheHive alert: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "thehive_create_case",
    "Create a TheHive case for in-depth investigation. Escalate from alerts or create directly from significant NIDS findings. Cases support tasks, observables, and collaborative investigation.",
    {
      title: z.string().describe("Case title"),
      description: z.string().describe("Detailed case description"),
      severity: z.number().int().min(1).max(4).default(2).describe("Severity: 1=Low, 2=Medium, 3=High, 4=Critical"),
      tlp: z.number().int().min(0).max(4).default(2).describe("TLP marking"),
      pap: z.number().int().min(0).max(3).default(2).describe("PAP marking"),
      tags: z.array(z.string()).optional().describe("Tags"),
      tasks: z.array(z.object({
        title: z.string(),
        description: z.string().optional(),
        group: z.string().optional(),
      })).optional().describe("Investigation tasks to create"),
      observables: z.array(z.object({
        dataType: z.enum(["ip", "domain", "url", "hash", "filename", "mail", "user-agent", "other"]),
        data: z.string(),
        message: z.string().optional(),
        tlp: z.number().int().min(0).max(4).optional(),
        ioc: z.boolean().optional(),
        tags: z.array(z.string()).optional(),
      })).optional().describe("Observables to attach"),
    },
    async (params) => {
      try {
        if (!config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "TheHive API key not configured. Set THEHIVE_API_KEY environment variable." }],
            isError: true,
          };
        }

        const caseBody = {
          title: params.title,
          description: params.description,
          severity: params.severity,
          tlp: params.tlp,
          pap: params.pap,
          tags: params.tags ?? ["nids", "zeek-mcp"],
        };

        const result = await theHiveRequest(config, "POST", "/api/v1/case", caseBody);

        if (result.status !== 201) {
          return {
            content: [{ type: "text" as const, text: `TheHive error (${result.status}): ${JSON.stringify(result.data)}` }],
            isError: true,
          };
        }

        const caseData = result.data as Record<string, unknown>;
        const caseId = caseData._id as string;

        // Add tasks
        if (params.tasks) {
          for (const task of params.tasks) {
            await theHiveRequest(config, "POST", `/api/v1/case/${caseId}/task`, {
              title: task.title,
              description: task.description,
              group: task.group ?? "default",
            });
          }
        }

        // Add observables
        if (params.observables) {
          for (const obs of params.observables) {
            await theHiveRequest(config, "POST", `/api/v1/case/${caseId}/observable`, {
              dataType: obs.dataType,
              data: obs.data,
              message: obs.message ?? "",
              tlp: obs.tlp ?? params.tlp,
              ioc: obs.ioc ?? false,
              tags: obs.tags ?? [],
            });
          }
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              success: true,
              caseId,
              caseNumber: caseData.number,
              title: params.title,
              taskCount: params.tasks?.length ?? 0,
              observableCount: params.observables?.length ?? 0,
              theHiveUrl: `${config.url}/index.html#!/case/${caseId}/details`,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error creating TheHive case: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "thehive_search_cases",
    "Search existing TheHive cases and alerts. Find related investigations, check for duplicates, or review open cases.",
    {
      query: z.string().optional().describe("Search query text"),
      severity: z.number().int().min(1).max(4).optional().describe("Filter by severity"),
      status: z.enum(["New", "InProgress", "Resolved", "Closed"]).optional().describe("Filter by status"),
      tags: z.array(z.string()).optional().describe("Filter by tags"),
      limit: z.number().int().min(1).max(100).default(20).describe("Max results"),
      entityType: z.enum(["case", "alert"]).default("case").describe("Search cases or alerts"),
    },
    async (params) => {
      try {
        if (!config.apiKey) {
          return {
            content: [{ type: "text" as const, text: "TheHive API key not configured." }],
            isError: true,
          };
        }

        const filters: unknown[] = [];

        if (params.query) {
          filters.push({ _name: "filter", _field: "title", _value: `*${params.query}*` });
        }
        if (params.severity !== undefined) {
          filters.push({ _name: "filter", _field: "severity", _value: params.severity });
        }
        if (params.status) {
          filters.push({ _name: "filter", _field: "status", _value: params.status });
        }
        if (params.tags && params.tags.length > 0) {
          for (const tag of params.tags) {
            filters.push({ _name: "filter", _field: "tags", _value: tag });
          }
        }

        const endpoint = params.entityType === "alert"
          ? "/api/v1/query?name=alerts"
          : "/api/v1/query?name=cases";

        const queryBody = {
          query: [
            { _name: params.entityType === "alert" ? "listAlert" : "listCase" },
            ...(filters.length > 0 ? filters : []),
            { _name: "sort", _fields: [{ _createdAt: "desc" }] },
            { _name: "page", from: 0, to: params.limit },
          ],
        };

        const result = await theHiveRequest(config, "POST", endpoint, queryBody);

        const items = (Array.isArray(result.data) ? result.data : []) as Array<Record<string, unknown>>;

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              entityType: params.entityType,
              count: items.length,
              results: items.map((item) => ({
                id: item._id,
                number: item.number,
                title: item.title,
                severity: item.severity,
                status: item.status,
                tlp: item.tlp,
                tags: item.tags,
                createdAt: item._createdAt ? new Date(item._createdAt as number).toISOString() : undefined,
                updatedAt: item._updatedAt ? new Date(item._updatedAt as number).toISOString() : undefined,
                description: String(item.description ?? "").slice(0, 200),
              })),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error searching TheHive: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}
