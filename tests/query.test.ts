import { describe, it, expect } from "vitest";
import {
  matchCidr,
  matchWildcard,
  matchPartial,
  inRange,
  matchIp,
} from "../src/query/filters.js";
import {
  groupBy,
  sumField,
  avgField,
  countUnique,
  topN,
  getNestedValue,
} from "../src/query/aggregation.js";
import type { ZeekRecord } from "../src/types.js";

describe("CIDR matching", () => {
  it("should match exact IP", () => {
    expect(matchCidr("192.168.1.100", "192.168.1.100")).toBe(true);
    expect(matchCidr("192.168.1.100", "192.168.1.101")).toBe(false);
  });

  it("should match /24 CIDR", () => {
    expect(matchCidr("192.168.1.100", "192.168.1.0/24")).toBe(true);
    expect(matchCidr("192.168.1.255", "192.168.1.0/24")).toBe(true);
    expect(matchCidr("192.168.2.1", "192.168.1.0/24")).toBe(false);
  });

  it("should match /16 CIDR", () => {
    expect(matchCidr("10.0.5.100", "10.0.0.0/16")).toBe(true);
    expect(matchCidr("10.1.0.1", "10.0.0.0/16")).toBe(false);
  });

  it("should match /8 CIDR", () => {
    expect(matchCidr("10.255.255.255", "10.0.0.0/8")).toBe(true);
    expect(matchCidr("11.0.0.1", "10.0.0.0/8")).toBe(false);
  });

  it("should handle /32 CIDR (exact match)", () => {
    expect(matchCidr("192.168.1.1", "192.168.1.1/32")).toBe(true);
    expect(matchCidr("192.168.1.2", "192.168.1.1/32")).toBe(false);
  });

  it("should handle /0 CIDR (match all)", () => {
    expect(matchCidr("1.2.3.4", "0.0.0.0/0")).toBe(true);
    expect(matchCidr("255.255.255.255", "0.0.0.0/0")).toBe(true);
  });

  it("should return false for invalid IPs", () => {
    expect(matchCidr("not-an-ip", "192.168.1.0/24")).toBe(false);
    expect(matchCidr("192.168.1.1", "not-a-cidr/24")).toBe(false);
  });
});

describe("Wildcard matching", () => {
  it("should match exact strings", () => {
    expect(matchWildcard("example.com", "example.com")).toBe(true);
    expect(matchWildcard("example.com", "example.org")).toBe(false);
  });

  it("should be case insensitive", () => {
    expect(matchWildcard("Example.COM", "example.com")).toBe(true);
  });

  it("should match leading wildcard", () => {
    expect(matchWildcard("sub.evil.com", "*.evil.com")).toBe(true);
    expect(matchWildcard("deep.sub.evil.com", "*.evil.com")).toBe(true);
    expect(matchWildcard("evil.com", "*.evil.com")).toBe(false);
  });

  it("should match trailing wildcard", () => {
    expect(matchWildcard("api.example.com", "api.*")).toBe(true);
    expect(matchWildcard("web.example.com", "api.*")).toBe(false);
  });

  it("should match middle wildcard", () => {
    expect(matchWildcard("www.example.com", "www.*.com")).toBe(true);
    expect(matchWildcard("www.test.com", "www.*.com")).toBe(true);
  });
});

describe("Partial matching", () => {
  it("should match substrings", () => {
    expect(matchPartial("Mozilla/5.0 (Windows)", "mozilla")).toBe(true);
    expect(matchPartial("python-requests/2.28", "python")).toBe(true);
    expect(matchPartial("curl/7.68.0", "wget")).toBe(false);
  });

  it("should be case insensitive", () => {
    expect(matchPartial("User-Agent", "user-agent")).toBe(true);
  });
});

describe("Range checking", () => {
  it("should check minimum value", () => {
    expect(inRange(100, 50)).toBe(true);
    expect(inRange(50, 100)).toBe(false);
  });

  it("should check maximum value", () => {
    expect(inRange(50, undefined, 100)).toBe(true);
    expect(inRange(150, undefined, 100)).toBe(false);
  });

  it("should check both bounds", () => {
    expect(inRange(75, 50, 100)).toBe(true);
    expect(inRange(25, 50, 100)).toBe(false);
    expect(inRange(150, 50, 100)).toBe(false);
  });

  it("should handle undefined values", () => {
    expect(inRange(undefined, 50)).toBe(false);
  });
});

describe("matchIp", () => {
  it("should match exact IP", () => {
    expect(matchIp("192.168.1.1", "192.168.1.1")).toBe(true);
    expect(matchIp("192.168.1.2", "192.168.1.1")).toBe(false);
  });

  it("should match CIDR ranges", () => {
    expect(matchIp("192.168.1.100", "192.168.1.0/24")).toBe(true);
    expect(matchIp("10.0.0.1", "192.168.1.0/24")).toBe(false);
  });
});

describe("Aggregation", () => {
  const testRecords: ZeekRecord[] = [
    { ts: 1, "id.orig_h": "192.168.1.1", "id.resp_p": 80, service: "http", orig_bytes: 100 },
    { ts: 2, "id.orig_h": "192.168.1.1", "id.resp_p": 443, service: "ssl", orig_bytes: 200 },
    { ts: 3, "id.orig_h": "192.168.1.2", "id.resp_p": 80, service: "http", orig_bytes: 300 },
    { ts: 4, "id.orig_h": "192.168.1.2", "id.resp_p": 22, service: "ssh", orig_bytes: 50 },
    { ts: 5, "id.orig_h": "192.168.1.3", "id.resp_p": 80, service: "http", orig_bytes: 150 },
  ];

  it("should group by field", () => {
    const result = groupBy(testRecords, "service");
    expect(result.total).toBe(5);
    expect(result.groups[0].key).toBe("http");
    expect(result.groups[0].count).toBe(3);
    expect(result.groups[0].percentage).toBe(60);
  });

  it("should sum a numeric field", () => {
    const total = sumField(testRecords, "orig_bytes");
    expect(total).toBe(800);
  });

  it("should average a numeric field", () => {
    const avg = avgField(testRecords, "orig_bytes");
    expect(avg).toBe(160);
  });

  it("should count unique values", () => {
    expect(countUnique(testRecords, "id.orig_h")).toBe(3);
    expect(countUnique(testRecords, "service")).toBe(3);
  });

  it("should get top N values", () => {
    const top = topN(testRecords, "service", 2);
    expect(top).toHaveLength(2);
    expect(top[0].value).toBe("http");
    expect(top[0].count).toBe(3);
  });

  it("should get nested values using dot notation", () => {
    const record: ZeekRecord = {
      ts: 1,
      "id.orig_h": "192.168.1.1",
      nested: { deep: { value: "found" } },
    };

    expect(getNestedValue(record, "id.orig_h")).toBe("192.168.1.1");
    expect(getNestedValue(record, "ts")).toBe(1);
  });

  it("should limit group results", () => {
    const result = groupBy(testRecords, "id.orig_h", 2);
    expect(result.groups).toHaveLength(2);
  });
});
