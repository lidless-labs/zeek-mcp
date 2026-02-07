import type { ZeekRecord } from "../types.js";

export interface BeaconCandidate {
  srcIp: string;
  dstIp: string;
  dstPort: number;
  connectionCount: number;
  avgInterval: number;
  stdDevInterval: number;
  jitter: number;
  avgBytes: number;
  score: number;
}

/**
 * Detect potential beaconing activity by analyzing connection regularity.
 * C2 beacons often connect at regular intervals, producing low jitter.
 *
 * Returns candidates sorted by beacon score (higher = more suspicious).
 */
export function detectBeaconing(
  records: ZeekRecord[],
  minConnections = 10,
  maxJitterPercent = 30,
): BeaconCandidate[] {
  const pairs = new Map<string, number[]>();

  for (const record of records) {
    const src = String(record["id.orig_h"] ?? "");
    const dst = String(record["id.resp_h"] ?? "");
    const port = record["id.resp_p"] as number;
    const ts = record.ts;

    if (!src || !dst || !ts) continue;

    const key = `${src}|${dst}|${port}`;
    if (!pairs.has(key)) pairs.set(key, []);
    pairs.get(key)!.push(ts);
  }

  const candidates: BeaconCandidate[] = [];

  for (const [key, timestamps] of pairs) {
    if (timestamps.length < minConnections) continue;

    timestamps.sort((a, b) => a - b);

    const intervals: number[] = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }

    if (intervals.length === 0) continue;

    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (avgInterval === 0) continue;

    const variance =
      intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) /
      intervals.length;
    const stdDev = Math.sqrt(variance);
    const jitter = (stdDev / avgInterval) * 100;

    if (jitter > maxJitterPercent) continue;

    const [src, dst, port] = key.split("|");

    const relatedRecords = records.filter(
      (r) =>
        String(r["id.orig_h"]) === src &&
        String(r["id.resp_h"]) === dst &&
        (r["id.resp_p"] as number) === parseInt(port, 10),
    );

    let totalBytes = 0;
    let byteCount = 0;
    for (const r of relatedRecords) {
      const orig = r.orig_bytes as number;
      const resp = r.resp_bytes as number;
      if (typeof orig === "number") {
        totalBytes += orig;
        byteCount++;
      }
      if (typeof resp === "number") {
        totalBytes += resp;
      }
    }

    const avgBytes = byteCount > 0 ? totalBytes / byteCount : 0;

    const regularityScore = Math.max(0, 100 - jitter);
    const volumeScore = Math.min(100, timestamps.length / 2);
    const score = (regularityScore * 0.7 + volumeScore * 0.3);

    candidates.push({
      srcIp: src,
      dstIp: dst,
      dstPort: parseInt(port, 10),
      connectionCount: timestamps.length,
      avgInterval: Math.round(avgInterval * 100) / 100,
      stdDevInterval: Math.round(stdDev * 100) / 100,
      jitter: Math.round(jitter * 100) / 100,
      avgBytes: Math.round(avgBytes),
      score: Math.round(score * 100) / 100,
    });
  }

  return candidates.sort((a, b) => b.score - a.score);
}
