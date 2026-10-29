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
    tool: (name: string, _desc: string, _schema: unknown, ...args: unknown[]) => {
      handlers[name] = args.at(-1) as ToolHandler;
    },
  };
  return { server, handlers };
}

let tmpPcapDir: string;
let registerPcapTools: typeof import("../src/tools/pcap.js")["registerPcapTools"];

beforeEach(async () => {
  vi.stubEnv("ZEEK_ALLOW_MUTATION", "1");
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
  vi.unstubAllEnvs();
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
    await analyze({ confirm: true, filename: evil, timeoutSeconds: 10 });

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
    const bad = await analyze({ confirm: true, filename: pcap, scripts: ["evil; rm -rf /"], timeoutSeconds: 10 });
    expect(JSON.stringify(bad)).toContain("Invalid script name");
    expect(execFileCalls.length).toBe(0);

    // A traversal script must also be rejected.
    const traversal = await analyze({ confirm: true, filename: pcap, scripts: ["../../etc/passwd"], timeoutSeconds: 10 });
    expect(JSON.stringify(traversal)).toContain("Invalid script name");

    // Valid namespaced scripts pass and arrive as discrete argv elements.
    await analyze({ confirm: true, filename: pcap, scripts: ["protocols/ssl/log-hostcerts-only"], timeoutSeconds: 10 });
    const zeekCall = execFileCalls.find((c) => c.file === "/usr/local/zeek/bin/zeek");
    expect(zeekCall).toBeDefined();
    expect(zeekCall!.args).toContain("protocols/ssl/log-hostcerts-only");
  });

  it.each(["-e", "--help", "--", "-C", "-r", "-i"]) (
    "rejects option-shaped script %s before host or Docker execution",
    async (script) => {
      fs.writeFileSync(path.join(tmpPcapDir, "capture.pcap"), "x");
      for (const container of ["", "zeek"]) {
        process.env.ZEEK_CONTAINER = container;
        const result = await getAnalyze()({ confirm: true, filename: "capture.pcap", scripts: [script], timeoutSeconds: 10 });
        expect(JSON.stringify(result)).toContain("Invalid script name");
        expect(execFileCalls).toHaveLength(0);
      }
    },
  );

  it.each(["file", "directory"])("blocks a %s symlink escaping the host capture root", async (kind) => {
    const outside = fs.mkdtempSync(path.join(process.cwd(), "test-data", "pcap-outside-"));
    try {
      fs.writeFileSync(path.join(outside, "secret.pcap"), "x");
      fs.symlinkSync(kind === "file" ? path.join(outside, "secret.pcap") : outside, path.join(tmpPcapDir, "link"));
      const result = await getAnalyze()({ confirm: true, filename: kind === "file" ? "link" : "link/secret.pcap", timeoutSeconds: 10 });
      expect(JSON.stringify(result)).toContain("outside the allowed PCAP directory");
      expect(execFileCalls).toHaveLength(0);
      expect(fs.existsSync(process.env.PCAP_OUTPUT_DIR!)).toBe(false);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it("requires a regular host capture file", async () => {
    fs.mkdirSync(path.join(tmpPcapDir, "directory.pcap"));
    const result = await getAnalyze()({ confirm: true, filename: "directory.pcap", timeoutSeconds: 10 });
    expect(JSON.stringify(result)).toContain("regular file");
    expect(execFileCalls).toHaveLength(0);
  });

  it("uses a canonical file within a symlinked host capture root", async () => {
    fs.writeFileSync(path.join(tmpPcapDir, "capture.pcap"), "x");
    fs.symlinkSync(path.join(tmpPcapDir, "capture.pcap"), path.join(tmpPcapDir, "alias.pcap"));
    const rootAlias = tmpPcapDir + "-alias";
    fs.symlinkSync(tmpPcapDir, rootAlias);
    process.env.PCAP_DIR = rootAlias;
    try {
      const result = await getAnalyze()({ confirm: true, filename: "alias.pcap", timeoutSeconds: 10 }) as { isError?: boolean };
      expect(result.isError).not.toBe(true);
      expect(execFileCalls[0].args).toEqual(["-r", fs.realpathSync(path.join(tmpPcapDir, "capture.pcap"))]);
    } finally {
      fs.unlinkSync(rootAlias);
    }
  });

  it("preserves the Docker capture mount and argv execution", async () => {
    fs.writeFileSync(path.join(tmpPcapDir, "capture.pcap"), "x");
    process.env.ZEEK_CONTAINER = "zeek";
    const result = await getAnalyze()({ confirm: true, filename: "capture.pcap", scripts: ["protocols/ssl/log-hostcerts-only"], timeoutSeconds: 10 }) as { isError?: boolean };
    expect(result.isError).not.toBe(true);
    const replay = execFileCalls.find((call) => call.args.includes("-r"));
    expect(replay?.file).toBe("docker");
    expect(replay?.args.slice(-3)).toEqual(["-r", "/pcaps/capture.pcap", "protocols/ssl/log-hostcerts-only"]);
  });

  it("rejects absolute paths outside PCAP_DIR", async () => {
    const analyze = getAnalyze();
    const res = await analyze({ confirm: true, filename: "/etc/passwd", timeoutSeconds: 10 });
    expect(JSON.stringify(res)).toContain("Path traversal blocked");
    expect(execFileCalls.length).toBe(0);
  });

  it("rejects relative traversal escaping PCAP_DIR", async () => {
    const analyze = getAnalyze();
    const res = await analyze({ confirm: true, filename: "../../../etc/passwd", timeoutSeconds: 10 });
    expect(JSON.stringify(res)).toContain("Path traversal blocked");
    expect(execFileCalls.length).toBe(0);
  });
});
