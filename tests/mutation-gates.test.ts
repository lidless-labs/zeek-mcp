import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerTheHiveTools } from "../src/tools/thehive.js";
import { registerMispTools } from "../src/tools/misp.js";
import { registerPcapTools } from "../src/tools/pcap.js";

const sideEffects = vi.hoisted(() => ({ file: vi.fn(), exec: vi.fn() }));
vi.mock("node:fs", async (original) => ({
  ...await original<typeof import("node:fs")>(),
  existsSync: sideEffects.file,
  mkdirSync: sideEffects.file,
}));
vi.mock("node:child_process", () => ({ execFile: sideEffects.exec }));

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const tools = [
  ["thehive_create_alert", { title: "example", description: "example" }],
  ["thehive_create_case", { title: "example", description: "example" }],
  ["misp_add_event", { info: "example" }],
  ["pcap_analyze", { filename: "example.pcap" }],
] as const;

describe.each(tools)("%s mutation gate", (name, args) => {
  it.each([
    [undefined, true, "ZEEK_ALLOW_MUTATION=1"],
    ["0", true, "ZEEK_ALLOW_MUTATION=1"],
    ["true", true, "ZEEK_ALLOW_MUTATION=1"],
    ["1", undefined, "confirm: true"],
    ["1", false, "confirm: true"],
  ] as const)("refuses with opt-in %s and confirm %s before side effects", async (optIn, confirm, message) => {
    vi.stubEnv("ZEEK_ALLOW_MUTATION", optIn);
    vi.stubEnv("THEHIVE_API_KEY", "example-key");
    vi.stubEnv("MISP_API_KEY", "example-key");
    const fetch = vi.fn(async () => new Response("{}"));
    vi.stubGlobal("fetch", fetch);
    const server = new McpServer({ name: "example", version: "1.0.0" });
    registerTheHiveTools(server);
    registerMispTools(server);
    registerPcapTools(server);
    const client = new Client({ name: "example-client", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const result = await client.callTool({ name, arguments: { ...args, ...(confirm === undefined ? {} : { confirm }) } });
      expect(result.isError).toBe(true);
      expect(result.content).toEqual([expect.objectContaining({ text: expect.stringContaining(message) })]);
      expect(fetch).not.toHaveBeenCalled();
      expect(sideEffects.file).not.toHaveBeenCalled();
      expect(sideEffects.exec).not.toHaveBeenCalled();
    } finally {
      await client.close();
      await server.close();
    }
  });
});

it("publishes the state and external-system annotations of gated tools", async () => {
  const server = new McpServer({ name: "example", version: "1.0.0" });
  registerTheHiveTools(server);
  registerMispTools(server);
  registerPcapTools(server);
  const client = new Client({ name: "example-client", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    const listed = await client.listTools();
    for (const [name] of tools) {
      expect(listed.tools.find((tool) => tool.name === name)?.annotations).toEqual({
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: name !== "pcap_analyze",
      });
    }
  } finally {
    await client.close();
    await server.close();
  }
});
