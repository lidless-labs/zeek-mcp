export interface ZeekConfig {
  logDir: string;
  logArchive: string;
  logFormat: "json" | "tsv";
  maxResults: number;
}

export function getConfig(): ZeekConfig {
  const logDir = process.env.ZEEK_LOG_DIR ?? "/opt/zeek/logs/current";
  const logArchive = process.env.ZEEK_LOG_ARCHIVE ?? "/opt/zeek/logs";
  const logFormat = (process.env.ZEEK_LOG_FORMAT ?? "json") as "json" | "tsv";
  const maxResults = parseInt(process.env.ZEEK_MAX_RESULTS ?? "1000", 10);

  if (logFormat !== "json" && logFormat !== "tsv") {
    throw new Error(
      `Invalid ZEEK_LOG_FORMAT: "${logFormat}". Must be "json" or "tsv".`,
    );
  }

  if (isNaN(maxResults) || maxResults < 1) {
    throw new Error(
      `Invalid ZEEK_MAX_RESULTS: "${process.env.ZEEK_MAX_RESULTS}". Must be a positive integer.`,
    );
  }

  return { logDir, logArchive, logFormat, maxResults };
}

/**
 * Suricata configuration is handled by getSuricataConfig() in tools/suricata.ts.
 * Environment variables:
 * - SURICATA_EVE_LOG: Path to eve.json (default: /opt/nids/suricata/logs/eve.json)
 * - SURICATA_FAST_LOG: Path to fast.log (default: /opt/nids/suricata/logs/fast.log)
 * - SURICATA_RULES_DIR: Path to rules directory (default: /opt/nids/suricata/rules)
 */
