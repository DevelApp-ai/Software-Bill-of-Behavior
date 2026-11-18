/**
 * Raw auditd saddr hex model (wazuh 4.14.6 lab finding, TDS 7.3.1).
 *
 * auditd emits connect telemetry only as the raw sockaddr bytes of the
 * SOCKADDR record: saddr=<hex>, UPPERCASE, AF_INET layout
 *
 *   family(2B) + port(2B, BE) + ip(4B, BE) + zero padding(8B)
 *   = "0200" + port(4 hex) + ip(8 hex) + 16 zero hex
 *
 * The stock Wazuh decoders never unpack saddr; the sbob bundle decodes the raw
 * hex into sbob.saddr (decoder tail-join) and the egress allowlist keys on the
 * SAME byte string (CDB is exact-match, case-sensitive), so drift evaluation
 * happens entirely in the raw-hex space:
 *
 *   - /32 (ip,port) pairs become exact CDB keys  (lists, cheapest, scalable)
 *   - wider CIDRs compile to a PCRE2 byte-class pattern on sbob.saddr
 *     (rule side; CDB has no CIDR semantics)
 *
 * IPv6 (AF_INET6, family 0A00) is out of scope for this milestone and is
 * reported by the bundle as a coverage note instead of silently matching.
 */

/** AF_INET family prefix as emitted by the kernel (big-endian sa_family). */
const AF_INET_PREFIX = "0200";

/** Shared zero padding of sockaddr_in (8 bytes = 16 zero hex). */
const PADDING = "0".repeat(16);

/** Uppercase big-endian hex of a byte. */
function hexByte(b: number): string {
  return b.toString(16).toUpperCase().padStart(2, "0");
}

/**
 * Uppercase 2-hex-digit alternation for a closed byte range
 * (base..base+step-1), used for CIDR octet enumeration.
 */
export function hexByteClass(from: number, to: number): string {
  if (from < 0 || to > 255 || from > to) {
    throw new Error(`invalid byte range ${from}..${to}`);
  }
  const parts: string[] = [];
  for (let b = from; b <= to; b++) parts.push(hexByte(b));
  return parts.length === 1 ? parts[0] : `(?:${parts.join("|")})`;
}

/** Raw saddr hex string of an AF_INET (IPv4, port) pair, uppercase. */
export function saddrHex(ip: string, port: number): string {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (m === null) throw new Error(`saddrHex: not an IPv4 literal: ${ip}`);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`saddrHex: invalid port ${port}`);
  }
  const ipHex = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])].map(hexByte).join("");
  return AF_INET_PREFIX + hexByte(port >> 8) + hexByte(port & 0xff) + ipHex + PADDING;
}

/** "10.96.0.10" (no mask) -> the parsed octets + mask, or null for IPv6/invalid. */
function parseIpv4(cidr: string): { octets: number[]; mask: number } | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d+)$/.exec(cidr);
  if (m === null) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((o) => o > 255)) return null;
  const mask = Number(m[5]);
  if (mask > 32) return null;
  return { octets, mask };
}

/**
 * PCRE2 byte pattern (without anchors) matching the raw saddr hex of any
 * address inside an IPv4 CIDR. `port` null/undefined = any port.
 * Enumerates the fixed octets and the covered range of the straddling octet
 * (base..base+step-1 at the CIDR boundary); free octets become [0-9A-F]{2}. Non-octet-aligned masks (e.g. /12) are supported: the straddling octet is enumerated.
 */
export function saddrCidrPattern(cidr: string, port?: number | null): string {
  const parsed = parseIpv4(cidr);
  if (parsed === null) {
    throw new Error(`saddrCidrPattern: not an IPv4 CIDR: ${cidr}`);
  }
  const { octets, mask } = parsed;
  const fixed = Math.floor(mask / 8); // fully fixed octets
  const rem = mask % 8;
  const bytes: string[] = [];
  for (let i = 0; i < 4; i++) {
    if (i < fixed) {
      bytes.push(hexByte(octets[i]!));
    } else if (i === fixed && rem > 0) {
      // straddling octet: enumerate network base..base+step-1
      const step = 1 << (8 - rem);
      const base = octets[i]! & ~(step - 1);
      bytes.push(hexByteClass(base, base + step - 1));
    } else {
      bytes.push("[0-9A-F]{2}");
    }
  }
  const portClass =
    port === null || port === undefined
      ? "[0-9A-F]{4}"
      : hexByte(port >> 8) + hexByte(port & 0xff);
  return AF_INET_PREFIX + portClass + bytes.join("") + PADDING;
}

/** Anchored full-match form of saddrCidrPattern for <field> conditions. */
export function saddrCidrRegex(cidr: string, port?: number | null): string {
  return `^${saddrCidrPattern(cidr, port)}$`;
}
