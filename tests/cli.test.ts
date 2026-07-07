import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";

const TEST_DATA_DIR = path.join(process.cwd(), "test-data");
const tempDirs: string[] = [];

function envFor(logDir = TEST_DATA_DIR): NodeJS.ProcessEnv {
  return {
    ...process.env,
    ZEEK_LOG_DIR: logDir,
    ZEEK_LOG_ARCHIVE: logDir,
    ZEEK_LOG_FORMAT: "json",
    ZEEK_MAX_RESULTS: "1000",
  };
}

function makeIo(env = envFor()) {
  let stdout = "";
  let stderr = "";

  return {
    io: {
      env,
      stdout: { write: (value: string) => { stdout += value; return true; } },
      stderr: { write: (value: string) => { stderr += value; return true; } },
    },
    output: () => ({ stdout, stderr }),
  };
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { force: true, recursive: true });
  }
});

describe("zeekctrl CLI", () => {
  it("prints help", async () => {
    const { io, output } = makeIo();

    const code = await runCli(["help"], io);

    expect(code).toBe(0);
    expect(output().stdout).toContain("zeekctrl");
    expect(output().stdout).toContain("zeek-mcp");
  });

  it("reports status as JSON", async () => {
    const { io, output } = makeIo();

    const code = await runCli(["status", "--json"], io);
    const status = JSON.parse(output().stdout);

    expect(code).toBe(0);
    expect(status.ok).toBe(true);
    expect(status.config.logDir).toBe(TEST_DATA_DIR);
    expect(status.paths.currentConnLog.exists).toBe(true);
  });

  it("queries connection records", async () => {
    const { io, output } = makeIo();

    const code = await runCli([
      "conn",
      "query",
      "--src-ip",
      "192.168.1.100",
      "--limit",
      "2",
      "--json",
    ], io);
    const records = JSON.parse(output().stdout);

    expect(code).toBe(0);
    expect(records).toHaveLength(2);
    expect(records.every((record: Record<string, unknown>) => record["id.orig_h"] === "192.168.1.100")).toBe(true);
  });

  it("queries DNS records", async () => {
    const { io, output } = makeIo();

    const code = await runCli([
      "dns",
      "query",
      "--query",
      "*.example.com",
      "--json",
    ], io);
    const records = JSON.parse(output().stdout);

    expect(code).toBe(0);
    expect(records.length).toBeGreaterThan(0);
    expect(records[0].query).toBe("www.example.com");
  });

  it("detects beaconing candidates", async () => {
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "zeekctrl-"));
    tempDirs.push(logDir);
    const records = [];
    for (let i = 0; i < 12; i++) {
      records.push(JSON.stringify({
        ts: 1706745600 + i * 60,
        uid: `C${i}`,
        "id.orig_h": "192.168.50.10",
        "id.orig_p": 50000 + i,
        "id.resp_h": "203.0.113.55",
        "id.resp_p": 443,
        proto: "tcp",
        orig_bytes: 100,
        resp_bytes: 200,
      }));
    }
    fs.writeFileSync(path.join(logDir, "conn.log"), `${records.join("\n")}\n`);
    fs.writeFileSync(path.join(logDir, "dns.log"), "");

    const { io, output } = makeIo(envFor(logDir));
    const code = await runCli([
      "beaconing",
      "detect",
      "--min-connections",
      "10",
      "--json",
    ], io);
    const candidates = JSON.parse(output().stdout);

    expect(code).toBe(0);
    expect(candidates).toHaveLength(1);
    expect(candidates[0].srcIp).toBe("192.168.50.10");
    expect(candidates[0].jitter).toBe(0);
  });

  it("returns an error for unknown commands", async () => {
    const { io, output } = makeIo();

    const code = await runCli(["nonsense"], io);

    expect(code).toBe(2);
    expect(output().stderr).toContain("Unknown command");
  });
});
