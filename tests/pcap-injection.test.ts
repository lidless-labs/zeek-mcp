import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as path from "node:path";
import * as fs from "node:fs";

// Regression tests for the pcap_analyze command-injection / path-traversal fixes.
//
// We mock child_process.execFile so no real Zeek/docker is invoked, capture the
// argv array passed to it, and assert that:
//   1. user-controlled values (filename, scripts) arrive as DISCRETE argv
//      elements and are never concatenated into a shell string;
//   2. shell metacharacters in a filename cannot escape the pcap directory or
//      reach a shell;
//   3. absolute and traversal paths outside PCAP_DIR are rejected.

const execFileCalls: Array<{ file: string; args: string[] }> = [];

vi.mock("node:child_process", () => {
  return {
    execFile: (
      file: string,
      args: string[],
      _opts: unknown,
      cb: (err: unknown, stdout: string, stderr: string) => void,
    ) => {
      execFileCalls.push({ file, args });
      // Simulate Zeek producing no logs; just return cleanly.
      cb(null, "", "");
    },
  };
});

// Minimal McpServer stub that captures the registered tool handler.
type ToolHandler = (params: Record<string, unknown>) => Promise<unknown>;
function makeServerStub() {
  const handlers: Record<string, ToolHandler> = {};
  const server = {
    tool: (name: string, _desc: string, _schema: unknown, handler: ToolHandler) => {
      handlers[name] = handler;
    },
  };
  return { server, handlers };
}

let tmpPcapDir: string;
let registerPcapTools: typeof import("../src/tools/pcap.js")["registerPcapTools"];

beforeEach(async () => {
  execFileCalls.length = 0;
  tmpPcapDir = fs.mkdtempSync(path.join(process.cwd(), "test-data", "pcap-inj-"));
  process.env.PCAP_DIR = tmpPcapDir;
  // Force the host (non-docker) branch for deterministic argv assertions.
  process.env.ZEEK_CONTAINER = "";
  process.env.ZEEK_BINARY = "/usr/local/zeek/bin/zeek";
  process.env.PCAP_OUTPUT_DIR = path.join(tmpPcapDir, "out");
  vi.resetModules();
  ({ registerPcapTools } = await import("../src/tools/pcap.js"));
});

afterEach(() => {
  fs.rmSync(tmpPcapDir, { recursive: true, force: true });
  delete process.env.PCAP_DIR;
  delete process.env.ZEEK_CONTAINER;
  delete process.env.ZEEK_BINARY;
  delete process.env.PCAP_OUTPUT_DIR;
});

function getAnalyze() {
  const { server, handlers } = makeServerStub();
  registerPcapTools(server as never);
  return handlers["pcap_analyze"];
}

describe("pcap_analyze command injection / path traversal", () => {
  it("passes a malicious filename as a single argv element (no shell)", async () => {
    // A filename containing shell metacharacters. It must NOT be split or
    // interpreted; it should simply fail the path-confinement check OR, if it
    // resolves inside the dir, be passed verbatim as one argument.
    const evil = "$(touch pwned);`id`& .pcap";
    const evilPath = path.join(tmpPcapDir, evil);
    fs.writeFileSync(evilPath, "x");

    const analyze = getAnalyze();
    await analyze({ filename: evil, timeoutSeconds: 10 });

    // execFile must have been invoked (host branch) with zeek + discrete args.
    expect(execFileCalls.length).toBeGreaterThan(0);
    const zeekCall = execFileCalls.find((c) => c.file === "/usr/local/zeek/bin/zeek");
    expect(zeekCall).toBeDefined();
    // -r and the resolved pcap path are separate elements; the metachars survive
    // intact as ONE argument (proof they were never handed to a shell).
    expect(zeekCall!.args[0]).toBe("-r");
    expect(zeekCall!.args[1]).toBe(evilPath);
    expect(zeekCall!.args).toContain(evilPath);
  });

  it("passes each script as a separate argv element and rejects injection in scripts", async () => {
    const pcap = "capture.pcap";
    fs.writeFileSync(path.join(tmpPcapDir, pcap), "x");
    const analyze = getAnalyze();

    // A script name with shell metacharacters must be rejected by the allowlist.
    const bad = await analyze({ filename: pcap, scripts: ["evil; rm -rf /"], timeoutSeconds: 10 });
    expect(JSON.stringify(bad)).toContain("Invalid script name");
    expect(execFileCalls.length).toBe(0);

    // A traversal script must also be rejected.
    const traversal = await analyze({ filename: pcap, scripts: ["../../etc/passwd"], timeoutSeconds: 10 });
    expect(JSON.stringify(traversal)).toContain("Invalid script name");

    // Valid namespaced scripts pass and arrive as discrete argv elements.
    await analyze({ filename: pcap, scripts: ["protocols/ssl/log-hostcerts-only"], timeoutSeconds: 10 });
    const zeekCall = execFileCalls.find((c) => c.file === "/usr/local/zeek/bin/zeek");
    expect(zeekCall).toBeDefined();
    expect(zeekCall!.args).toContain("protocols/ssl/log-hostcerts-only");
  });

  it("rejects absolute paths outside PCAP_DIR", async () => {
    const analyze = getAnalyze();
    const res = await analyze({ filename: "/etc/passwd", timeoutSeconds: 10 });
    expect(JSON.stringify(res)).toContain("Path traversal blocked");
    expect(execFileCalls.length).toBe(0);
  });

  it("rejects relative traversal escaping PCAP_DIR", async () => {
    const analyze = getAnalyze();
    const res = await analyze({ filename: "../../../etc/passwd", timeoutSeconds: 10 });
    expect(JSON.stringify(res)).toContain("Path traversal blocked");
    expect(execFileCalls.length).toBe(0);
  });
});
