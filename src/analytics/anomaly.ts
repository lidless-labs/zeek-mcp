import type { ZeekRecord } from "../types.js";

export interface AnomalyResult {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  details: Record<string, unknown>;
}

/**
 * Detect statistical anomalies in connection patterns.
 */
export function detectConnectionAnomalies(
  records: ZeekRecord[],
): AnomalyResult[] {
  const anomalies: AnomalyResult[] = [];

  const portScanCheck = detectPortScans(records);
  anomalies.push(...portScanCheck);

  const dataExfilCheck = detectDataExfiltration(records);
  anomalies.push(...dataExfilCheck);

  const unusualPortCheck = detectUnusualPorts(records);
  anomalies.push(...unusualPortCheck);

  return anomalies;
}

function detectPortScans(records: ZeekRecord[]): AnomalyResult[] {
  const anomalies: AnomalyResult[] = [];

  const srcToPorts = new Map<string, Set<number>>();
  const srcToTargets = new Map<string, Set<string>>();

  for (const record of records) {
    const src = String(record["id.orig_h"] ?? "");
    const dst = String(record["id.resp_h"] ?? "");
    const port = record["id.resp_p"] as number;
    const connState = String(record.conn_state ?? "");

    if (connState === "S0" || connState === "REJ") {
      if (!srcToPorts.has(src)) srcToPorts.set(src, new Set());
      srcToPorts.get(src)!.add(port);

      if (!srcToTargets.has(src)) srcToTargets.set(src, new Set());
      srcToTargets.get(src)!.add(dst);
    }
  }

  for (const [src, ports] of srcToPorts) {
    if (ports.size > 50) {
      const targets = srcToTargets.get(src)!;
      anomalies.push({
        type: "port_scan",
        severity: ports.size > 200 ? "high" : "medium",
        description: `${src} scanned ${ports.size} ports across ${targets.size} hosts`,
        details: {
          sourceIp: src,
          portsScanned: ports.size,
          uniqueTargets: targets.size,
          samplePorts: [...ports].slice(0, 20),
        },
      });
    }
  }

  return anomalies;
}

function detectDataExfiltration(records: ZeekRecord[]): AnomalyResult[] {
  const anomalies: AnomalyResult[] = [];

  const srcBytes = new Map<string, number>();

  for (const record of records) {
    const src = String(record["id.orig_h"] ?? "");
    const bytes = record.orig_bytes as number;

    if (typeof bytes === "number" && bytes > 0) {
      srcBytes.set(src, (srcBytes.get(src) ?? 0) + bytes);
    }
  }

  const allBytes = [...srcBytes.values()];
  if (allBytes.length < 3) return anomalies;

  allBytes.sort((a, b) => a - b);
  const q3 = allBytes[Math.floor(allBytes.length * 0.75)];
  const q1 = allBytes[Math.floor(allBytes.length * 0.25)];
  const iqr = q3 - q1;
  const threshold = q3 + 3 * iqr;

  for (const [src, bytes] of srcBytes) {
    if (bytes > threshold && bytes > 104857600) {
      anomalies.push({
        type: "data_exfiltration",
        severity: bytes > 1073741824 ? "critical" : "high",
        description: `${src} sent ${formatBytes(bytes)} - statistical outlier`,
        details: {
          sourceIp: src,
          bytesSent: bytes,
          threshold,
          iqr,
        },
      });
    }
  }

  return anomalies;
}

function detectUnusualPorts(records: ZeekRecord[]): AnomalyResult[] {
  const anomalies: AnomalyResult[] = [];

  const commonPorts = new Set([
    20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 161,
    162, 389, 443, 445, 465, 514, 587, 636, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888,
  ]);

  const unusualPortCounts = new Map<number, number>();

  for (const record of records) {
    const port = record["id.resp_p"] as number;
    const service = String(record.service ?? "");

    if (port && !commonPorts.has(port) && port > 0 && port < 65536 && !service) {
      unusualPortCounts.set(port, (unusualPortCounts.get(port) ?? 0) + 1);
    }
  }

  const highVolumePorts = [...unusualPortCounts.entries()]
    .filter(([, count]) => count > 20)
    .sort((a, b) => b[1] - a[1]);

  for (const [port, count] of highVolumePorts.slice(0, 10)) {
    anomalies.push({
      type: "unusual_port",
      severity: "low",
      description: `${count} connections to unusual port ${port} without identified service`,
      details: {
        port,
        connectionCount: count,
      },
    });
  }

  return anomalies;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}
