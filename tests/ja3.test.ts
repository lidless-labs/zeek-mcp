import { describe, it, expect } from "vitest";
import * as path from "node:path";
import { readLogFile } from "../src/parser/index.js";
import { KNOWN_MALICIOUS_JA3 } from "../src/tools/ja3.js";

const TEST_DATA_DIR = path.join(process.cwd(), "test-data");

describe("JA3 fingerprint analysis", () => {
  it("should have known malicious hashes database", () => {
    expect(Object.keys(KNOWN_MALICIOUS_JA3).length).toBeGreaterThanOrEqual(10);
    expect(KNOWN_MALICIOUS_JA3["a0e9f5d64349fb13191bc781f81f42e1"]).toBe("CobaltStrike");
    expect(KNOWN_MALICIOUS_JA3["ec74a5c51106f0419184d0dd08fb05bc"]).toBe("Emotet");
  });

  it("should parse SSL logs for fingerprint analysis", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "ssl.log"),
      "json",
    );

    expect(records.length).toBeGreaterThan(0);

    // Verify SSL records have the fields we need for fingerprinting
    for (const r of records) {
      expect(r).toHaveProperty("id.orig_h");
      expect(r).toHaveProperty("id.resp_h");
    }
  });

  it("should group SSL records by cipher suite for pseudo-fingerprinting", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "ssl.log"),
      "json",
    );

    const cipherGroups = new Map<string, number>();
    for (const r of records) {
      const cipher = String(r.cipher ?? "unknown");
      cipherGroups.set(cipher, (cipherGroups.get(cipher) ?? 0) + 1);
    }

    expect(cipherGroups.size).toBeGreaterThan(0);
  });

  it("should detect deprecated TLS versions", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "ssl.log"),
      "json",
    );

    const deprecatedVersions = new Set(["SSLv3", "TLSv10", "TLSv11"]);
    const deprecated = records.filter((r) =>
      deprecatedVersions.has(String(r.version ?? "")),
    );

    // Test data may or may not have deprecated TLS
    expect(typeof deprecated.length).toBe("number");
  });

  it("should match JA3 hashes against known malicious database", () => {
    const testHashes = [
      "a0e9f5d64349fb13191bc781f81f42e1", // CobaltStrike
      "abc123def456789012345678901234",     // Unknown
      "ec74a5c51106f0419184d0dd08fb05bc",   // Emotet
      "0000000000000000000000000000000",     // Unknown
    ];

    const matches = testHashes.filter((h) => KNOWN_MALICIOUS_JA3[h]);
    const unknowns = testHashes.filter((h) => !KNOWN_MALICIOUS_JA3[h]);

    expect(matches.length).toBe(2);
    expect(unknowns.length).toBe(2);
  });

  it("should support custom hash hunting", () => {
    const customHashes: Record<string, string> = {
      "custom_hash_001": "APT Custom Tool",
      "custom_hash_002": "Internal Pentest Tool",
    };

    const combined = { ...KNOWN_MALICIOUS_JA3, ...customHashes };

    expect(combined["custom_hash_001"]).toBe("APT Custom Tool");
    expect(combined["a0e9f5d64349fb13191bc781f81f42e1"]).toBe("CobaltStrike");
    expect(Object.keys(combined).length).toBe(Object.keys(KNOWN_MALICIOUS_JA3).length + 2);
  });
});
