/**
 * Calculate Shannon entropy of a string.
 * Higher entropy indicates more randomness, which can suggest
 * encoded data (DNS tunneling, DGA domains, etc.)
 *
 * Typical values:
 * - English text: ~3.5-4.5
 * - Random alphanumeric: ~5.7
 * - Base64 encoded: ~5.5-6.0
 * - Hex encoded: ~3.5-4.0
 */
export function shannonEntropy(input: string): number {
  if (!input || input.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of input) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = input.length;

  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Calculate entropy of just the labels (subdomains) portion of a DNS query.
 * Strips the TLD and SLD to focus on the data-carrying portion.
 */
export function domainLabelEntropy(domain: string): number {
  const parts = domain.split(".");
  if (parts.length <= 2) {
    return shannonEntropy(parts[0]);
  }

  const labels = parts.slice(0, -2).join(".");
  return shannonEntropy(labels);
}

/**
 * Check if a string appears to be encoded (base64, hex, etc.)
 */
export function detectEncoding(input: string): string | null {
  if (/^[0-9a-fA-F]+$/.test(input) && input.length > 10 && input.length % 2 === 0) {
    return "hex";
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(input) && input.length > 10) {
    return "base64";
  }
  return null;
}
