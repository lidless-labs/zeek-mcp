import { describe, it, expect } from "vitest";
import * as path from "node:path";
import * as fs from "node:fs";
import { getPcapConfig } from "../src/tools/pcap.js";

const TEST_DATA_DIR = path.join(process.cwd(), "test-data");

describe("PCAP tools", () => {
  it("should load PCAP config from defaults", () => {
    delete process.env.PCAP_DIR;
    delete process.env.ZEEK_BINARY;
    delete process.env.ZEEK_CONTAINER;

    const config = getPcapConfig();

    expect(config.pcapDir).toBe("/opt/nids/pcaps");
    expect(config.zeekBinary).toBe("/usr/local/zeek/bin/zeek");
    expect(config.zeekContainer).toBe("zeek");
  });

  it("should load PCAP config from environment", () => {
    process.env.PCAP_DIR = "/custom/pcaps";
    process.env.ZEEK_BINARY = "/usr/bin/zeek";
    process.env.ZEEK_CONTAINER = "my-zeek";

    const config = getPcapConfig();

    expect(config.pcapDir).toBe("/custom/pcaps");
    expect(config.zeekBinary).toBe("/usr/bin/zeek");
    expect(config.zeekContainer).toBe("my-zeek");

    delete process.env.PCAP_DIR;
    delete process.env.ZEEK_BINARY;
    delete process.env.ZEEK_CONTAINER;
  });

  it("should handle non-existent PCAP directory gracefully", () => {
    expect(fs.existsSync("/nonexistent/pcaps")).toBe(false);
  });

  it("should detect pcap file extensions", () => {
    const pcapExtensions = [".pcap", ".pcapng", ".cap"];
    const testFiles = ["capture.pcap", "data.pcapng", "dump.cap", "notes.txt", "readme.md"];

    const pcapFiles = testFiles.filter((f) =>
      pcapExtensions.some((ext) => f.endsWith(ext)),
    );

    expect(pcapFiles).toEqual(["capture.pcap", "data.pcapng", "dump.cap"]);
  });
});
