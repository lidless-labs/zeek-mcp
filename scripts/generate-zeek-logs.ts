import * as fs from "node:fs";
import * as path from "node:path";

interface GeneratorConfig {
  outputDir: string;
  format: "json" | "tsv";
  startTime: number;
  durationHours: number;
  hostCount: number;
  connectionsPerHour: number;
  injectSuspicious: boolean;
}

const defaultConfig: GeneratorConfig = {
  outputDir: path.join(process.cwd(), "generated-logs"),
  format: "json",
  startTime: Math.floor(Date.now() / 1000) - 86400,
  durationHours: 24,
  hostCount: 20,
  connectionsPerHour: 100,
  injectSuspicious: true,
};

const internalNets = ["192.168.1", "10.0.0", "172.16.0"];
const externalIps = [
  "93.184.216.34", "151.101.1.140", "140.82.121.6", "8.8.8.8",
  "8.8.4.4", "1.1.1.1", "104.16.0.1", "13.107.42.14",
];
const suspiciousIps = ["45.33.32.156", "203.0.113.50", "198.51.100.99"];
const services = ["http", "ssl", "dns", "ssh", "smtp", "smb"];
const domains = [
  "www.example.com", "api.github.com", "cdn.cloudflare.com",
  "mail.company.com", "docs.google.com", "slack.com",
  "login.microsoftonline.com", "s3.amazonaws.com",
];
const userAgents = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
  "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)",
];
const suspiciousAgents = ["python-requests/2.28.0", "curl/7.68.0", "wget/1.21"];

function randomElement<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIp(internal = true): string {
  if (internal) {
    return `${randomElement(internalNets)}.${randomInt(1, 254)}`;
  }
  return randomElement(externalIps);
}

function uid(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "C";
  for (let i = 0; i < 17; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

function generateConnLog(config: GeneratorConfig): string[] {
  const lines: string[] = [];
  const totalConns = config.connectionsPerHour * config.durationHours;

  for (let i = 0; i < totalConns; i++) {
    const ts = config.startTime + Math.random() * config.durationHours * 3600;
    const origH = randomIp(true);
    const respH = randomIp(Math.random() > 0.3);
    const proto = randomElement(["tcp", "udp"]);
    const service = Math.random() > 0.2 ? randomElement(services) : undefined;

    const record: Record<string, unknown> = {
      ts,
      uid: uid(),
      "id.orig_h": origH,
      "id.orig_p": randomInt(1024, 65535),
      "id.resp_h": respH,
      "id.resp_p": randomElement([80, 443, 22, 25, 53, 445, 8080, 3389]),
      proto,
      service,
      duration: Math.random() * 300,
      orig_bytes: randomInt(0, 100000),
      resp_bytes: randomInt(0, 500000),
      conn_state: randomElement(["SF", "S0", "S1", "REJ", "RSTO"]),
      history: "ShADadFf",
      orig_pkts: randomInt(1, 1000),
      resp_pkts: randomInt(1, 2000),
    };

    lines.push(JSON.stringify(record));
  }

  if (config.injectSuspicious) {
    const beaconSrc = randomIp(true);
    const beaconDst = randomElement(suspiciousIps);
    for (let i = 0; i < 50; i++) {
      const ts = config.startTime + i * 300 + (Math.random() * 5 - 2.5);
      lines.push(JSON.stringify({
        ts,
        uid: uid(),
        "id.orig_h": beaconSrc,
        "id.orig_p": randomInt(40000, 60000),
        "id.resp_h": beaconDst,
        "id.resp_p": 443,
        proto: "tcp",
        service: "ssl",
        duration: 0.5 + Math.random() * 0.5,
        orig_bytes: randomInt(100, 300),
        resp_bytes: randomInt(200, 500),
        conn_state: "SF",
      }));
    }

    const longConnSrc = randomIp(true);
    lines.push(JSON.stringify({
      ts: config.startTime + 100,
      uid: uid(),
      "id.orig_h": longConnSrc,
      "id.orig_p": randomInt(40000, 60000),
      "id.resp_h": randomElement(suspiciousIps),
      "id.resp_p": 9999,
      proto: "tcp",
      duration: 86400,
      orig_bytes: 500000,
      resp_bytes: 600000,
      conn_state: "S1",
    }));

    const scanSrc = randomIp(true);
    const scanTarget = randomIp(false);
    for (let port = 1; port <= 100; port++) {
      lines.push(JSON.stringify({
        ts: config.startTime + 1000 + port * 0.1,
        uid: uid(),
        "id.orig_h": scanSrc,
        "id.orig_p": randomInt(40000, 60000),
        "id.resp_h": scanTarget,
        "id.resp_p": port,
        proto: "tcp",
        conn_state: "S0",
        duration: 0,
        orig_bytes: 0,
        resp_bytes: 0,
      }));
    }
  }

  return lines;
}

function generateDnsLog(config: GeneratorConfig): string[] {
  const lines: string[] = [];
  const totalQueries = config.connectionsPerHour * config.durationHours * 0.5;

  for (let i = 0; i < totalQueries; i++) {
    const ts = config.startTime + Math.random() * config.durationHours * 3600;
    const query = randomElement(domains);

    lines.push(JSON.stringify({
      ts,
      uid: uid(),
      "id.orig_h": randomIp(true),
      "id.orig_p": randomInt(1024, 65535),
      "id.resp_h": randomElement(["8.8.8.8", "8.8.4.4", "1.1.1.1"]),
      "id.resp_p": 53,
      proto: "udp",
      query,
      qtype_name: randomElement(["A", "AAAA", "CNAME"]),
      rcode_name: Math.random() > 0.05 ? "NOERROR" : "NXDOMAIN",
      answers: [randomIp(false)],
      TTLs: [randomInt(60, 86400)],
    }));
  }

  if (config.injectSuspicious) {
    const tunnelSrc = randomIp(true);
    for (let i = 0; i < 100; i++) {
      const ts = config.startTime + Math.random() * config.durationHours * 3600;
      const randomSubdomain = Array.from(
        { length: 40 },
        () => "abcdefghijklmnopqrstuvwxyz0123456789"[Math.floor(Math.random() * 36)],
      ).join("");

      lines.push(JSON.stringify({
        ts,
        uid: uid(),
        "id.orig_h": tunnelSrc,
        "id.orig_p": randomInt(1024, 65535),
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        proto: "udp",
        query: `${randomSubdomain}.tunneldomain.com`,
        qtype_name: randomElement(["TXT", "A", "NULL"]),
        rcode_name: "NOERROR",
        answers: [],
        TTLs: [],
      }));
    }

    const dgaSrc = randomIp(true);
    for (let i = 0; i < 50; i++) {
      const ts = config.startTime + Math.random() * config.durationHours * 3600;
      const randomDomain = Array.from(
        { length: randomInt(8, 15) },
        () => "abcdefghijklmnopqrstuvwxyz"[Math.floor(Math.random() * 26)],
      ).join("");

      lines.push(JSON.stringify({
        ts,
        uid: uid(),
        "id.orig_h": dgaSrc,
        "id.orig_p": randomInt(1024, 65535),
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        proto: "udp",
        query: `${randomDomain}.com`,
        qtype_name: "A",
        rcode_name: "NXDOMAIN",
        answers: [],
        TTLs: [],
      }));
    }
  }

  return lines;
}

function generateHttpLog(config: GeneratorConfig): string[] {
  const lines: string[] = [];
  const totalRequests = config.connectionsPerHour * config.durationHours * 0.3;

  for (let i = 0; i < totalRequests; i++) {
    const ts = config.startTime + Math.random() * config.durationHours * 3600;

    lines.push(JSON.stringify({
      ts,
      uid: uid(),
      "id.orig_h": randomIp(true),
      "id.orig_p": randomInt(1024, 65535),
      "id.resp_h": randomIp(false),
      "id.resp_p": randomElement([80, 443, 8080]),
      method: randomElement(["GET", "POST", "GET", "GET"]),
      host: randomElement(domains),
      uri: randomElement(["/", "/api/v1/data", "/index.html", "/login", "/assets/main.css"]),
      user_agent: randomElement(userAgents),
      status_code: randomElement([200, 200, 200, 301, 404, 500]),
      request_body_len: 0,
      response_body_len: randomInt(100, 50000),
      resp_mime_types: [randomElement(["text/html", "application/json", "image/png"])],
    }));
  }

  if (config.injectSuspicious) {
    const c2Src = randomIp(true);
    const c2Dst = randomElement(suspiciousIps);
    for (let i = 0; i < 10; i++) {
      lines.push(JSON.stringify({
        ts: config.startTime + i * 600,
        uid: uid(),
        "id.orig_h": c2Src,
        "id.orig_p": randomInt(40000, 60000),
        "id.resp_h": c2Dst,
        "id.resp_p": 8080,
        method: "POST",
        host: c2Dst,
        uri: "/beacon",
        user_agent: randomElement(suspiciousAgents),
        status_code: 200,
        request_body_len: randomInt(100000, 2000000),
        response_body_len: randomInt(50, 200),
        resp_mime_types: ["application/octet-stream"],
      }));
    }
  }

  return lines;
}

function generateSshLog(config: GeneratorConfig): string[] {
  const lines: string[] = [];

  for (let i = 0; i < 20; i++) {
    const ts = config.startTime + Math.random() * config.durationHours * 3600;
    lines.push(JSON.stringify({
      ts,
      uid: uid(),
      "id.orig_h": randomIp(true),
      "id.orig_p": randomInt(1024, 65535),
      "id.resp_h": randomIp(true),
      "id.resp_p": 22,
      auth_success: true,
      auth_attempts: 1,
      direction: "OUTBOUND",
      client: "SSH-2.0-OpenSSH_8.9",
      server: "SSH-2.0-OpenSSH_9.0",
    }));
  }

  if (config.injectSuspicious) {
    const bruteSrc = "203.0.113.100";
    const bruteTarget = randomIp(true);
    for (let i = 0; i < 20; i++) {
      lines.push(JSON.stringify({
        ts: config.startTime + 5000 + i * 2,
        uid: uid(),
        "id.orig_h": bruteSrc,
        "id.orig_p": randomInt(40000, 60000),
        "id.resp_h": bruteTarget,
        "id.resp_p": 22,
        auth_success: false,
        auth_attempts: 3,
        direction: "INBOUND",
        client: "SSH-2.0-libssh2_1.10.0",
        server: "SSH-2.0-OpenSSH_8.9",
      }));
    }
  }

  return lines;
}

function generateNoticeLog(config: GeneratorConfig): string[] {
  const lines: string[] = [];

  if (config.injectSuspicious) {
    lines.push(JSON.stringify({
      ts: config.startTime + 1000,
      note: "Scan::Port_Scan",
      msg: "Port scan detected from internal host",
      src: randomIp(true),
      dst: randomIp(false),
      actions: ["Notice::ACTION_LOG"],
    }));

    lines.push(JSON.stringify({
      ts: config.startTime + 2000,
      note: "SSL::Invalid_Server_Cert",
      msg: "Self-signed certificate on suspicious connection",
      src: randomIp(true),
      dst: randomElement(suspiciousIps),
      p: 443,
      actions: ["Notice::ACTION_LOG"],
    }));
  }

  return lines;
}

function main(): void {
  const config = { ...defaultConfig };

  const formatArg = process.argv.find((a) => a.startsWith("--format="));
  if (formatArg) {
    config.format = formatArg.split("=")[1] as "json" | "tsv";
  }

  const outArg = process.argv.find((a) => a.startsWith("--output="));
  if (outArg) {
    config.outputDir = outArg.split("=")[1];
  }

  if (!fs.existsSync(config.outputDir)) {
    fs.mkdirSync(config.outputDir, { recursive: true });
  }

  const logs: Record<string, string[]> = {
    "conn.log": generateConnLog(config),
    "dns.log": generateDnsLog(config),
    "http.log": generateHttpLog(config),
    "ssh.log": generateSshLog(config),
    "notice.log": generateNoticeLog(config),
  };

  for (const [filename, lines] of Object.entries(logs)) {
    const filepath = path.join(config.outputDir, filename);
    fs.writeFileSync(filepath, lines.join("\n") + "\n");
    console.log(`Generated ${filepath} (${lines.length} records)`);
  }

  console.log(`\nLog files written to ${config.outputDir}`);
  console.log(`Format: ${config.format}`);
  console.log(`Time range: ${new Date(config.startTime * 1000).toISOString()} to ${new Date((config.startTime + config.durationHours * 3600) * 1000).toISOString()}`);
}

main();
