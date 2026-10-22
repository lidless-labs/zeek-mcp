import { it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

it("reports the package version during MCP initialization", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "example-zeek-version-"));
  const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
  pkg.version = "0.0.0-example";
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify(pkg));
  fs.cpSync("src", path.join(root, "src"), { recursive: true });
  fs.symlinkSync(path.resolve("node_modules"), path.join(root, "node_modules"), "dir");
  const client = new Client({ name: "example", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["--import", "tsx", path.join(root, "src/index.ts")],
    cwd: root,
    stderr: "pipe",
  });
  try {
    await client.connect(transport, { timeout: 10000 });
    expect(client.getServerVersion()?.version).toBe("0.0.0-example");
  } finally {
    await client.close();
    await transport.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
}, 15000);
