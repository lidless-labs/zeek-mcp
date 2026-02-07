export function matchCidr(ip: string, cidr: string): boolean {
  if (!cidr.includes("/")) {
    return ip === cidr;
  }

  const [network, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr, 10);

  if (ip.includes(":") || network.includes(":")) {
    return matchCidr6(ip, network, prefix);
  }

  const ipNum = ipv4ToNum(ip);
  const netNum = ipv4ToNum(network);

  if (ipNum === null || netNum === null) return false;

  const mask = prefix === 0 ? 0 : ~0 << (32 - prefix);
  return (ipNum & mask) === (netNum & mask);
}

function ipv4ToNum(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;

  let num = 0;
  for (const part of parts) {
    const octet = parseInt(part, 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return null;
    num = (num << 8) | octet;
  }
  return num >>> 0;
}

function matchCidr6(ip: string, network: string, prefix: number): boolean {
  const ipBytes = ipv6ToBytes(ip);
  const netBytes = ipv6ToBytes(network);

  if (!ipBytes || !netBytes) return false;

  let remaining = prefix;
  for (let i = 0; i < 16; i++) {
    if (remaining >= 8) {
      if (ipBytes[i] !== netBytes[i]) return false;
      remaining -= 8;
    } else if (remaining > 0) {
      const mask = ~0 << (8 - remaining) & 0xff;
      if ((ipBytes[i] & mask) !== (netBytes[i] & mask)) return false;
      remaining = 0;
    } else {
      break;
    }
  }

  return true;
}

function ipv6ToBytes(ip: string): number[] | null {
  const expanded = expandIpv6(ip);
  if (!expanded) return null;

  const groups = expanded.split(":");
  if (groups.length !== 8) return null;

  const bytes: number[] = [];
  for (const group of groups) {
    const val = parseInt(group, 16);
    if (isNaN(val)) return null;
    bytes.push((val >> 8) & 0xff, val & 0xff);
  }
  return bytes;
}

function expandIpv6(ip: string): string | null {
  if (ip.includes("::")) {
    const [left, right] = ip.split("::");
    const leftGroups = left ? left.split(":") : [];
    const rightGroups = right ? right.split(":") : [];
    const missing = 8 - leftGroups.length - rightGroups.length;
    if (missing < 0) return null;
    const middle = Array(missing).fill("0000");
    const all = [...leftGroups, ...middle, ...rightGroups];
    return all.map((g) => g.padStart(4, "0")).join(":");
  }
  return ip;
}

export function matchWildcard(value: string, pattern: string): boolean {
  if (!pattern.includes("*")) {
    return value.toLowerCase() === pattern.toLowerCase();
  }

  const regex = new RegExp(
    "^" +
      pattern
        .split("*")
        .map(escapeRegex)
        .join(".*") +
      "$",
    "i",
  );

  return regex.test(value);
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function matchPartial(value: string, search: string): boolean {
  return value.toLowerCase().includes(search.toLowerCase());
}

export function inRange(
  value: number | undefined,
  min?: number,
  max?: number,
): boolean {
  if (value === undefined || value === null) return false;
  if (min !== undefined && value < min) return false;
  if (max !== undefined && value > max) return false;
  return true;
}

export function matchIp(recordIp: string, filterIp: string): boolean {
  if (filterIp.includes("/")) {
    return matchCidr(recordIp, filterIp);
  }
  return recordIp === filterIp;
}
