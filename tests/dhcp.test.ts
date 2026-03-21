import { describe, it, expect } from "vitest";
import * as path from "node:path";
import { readLogFile } from "../src/parser/index.js";

const TEST_DATA_DIR = path.join(process.cwd(), "test-data");

describe("DHCP log parsing", () => {
  it("should parse DHCP TSV log records", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "dhcp.log"),
      "tsv",
    );

    expect(records.length).toBe(5);
  });

  it("should extract MAC addresses", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "dhcp.log"),
      "tsv",
    );

    expect(records[0].mac).toBe("aa:bb:cc:dd:ee:01");
    expect(records[1].mac).toBe("aa:bb:cc:dd:ee:02");
  });

  it("should extract assigned addresses", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "dhcp.log"),
      "tsv",
    );

    expect(records[0].assigned_addr).toBe("192.168.1.100");
    expect(records[1].assigned_addr).toBe("192.168.1.101");
  });

  it("should extract hostnames", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "dhcp.log"),
      "tsv",
    );

    expect(records[0].host_name).toBe("workstation-01");
    expect(records[1].host_name).toBe("laptop-alice");
  });

  it("should handle unset hostnames", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "dhcp.log"),
      "tsv",
    );

    // Record index 2 has "-" for hostname which should be undefined (unset)
    expect(records[2].host_name).toBeUndefined();
  });

  it("should parse message types as vectors", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "dhcp.log"),
      "tsv",
    );

    expect(records[0].msg_types).toEqual(["DISCOVER", "OFFER", "REQUEST", "ACK"]);
    expect(records[3].msg_types).toEqual(["REQUEST", "ACK"]);
  });

  it("should extract lease times", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "dhcp.log"),
      "tsv",
    );

    expect(records[0].lease_time).toBe(86400);
    expect(records[4].lease_time).toBe(3600);
  });

  it("should build asset map from multiple records for same MAC", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "dhcp.log"),
      "tsv",
    );

    // MAC aa:bb:cc:dd:ee:01 appears twice (records 0 and 3)
    const mac01Records = records.filter((r) => r.mac === "aa:bb:cc:dd:ee:01");
    expect(mac01Records.length).toBe(2);
  });
});
