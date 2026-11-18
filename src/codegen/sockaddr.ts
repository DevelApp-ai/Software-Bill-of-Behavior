/**
 * Raw AF_INET sockaddr hex REM fragments (issue #42, TDS 7.3.1).
 *
 * The shipped Wazuh auditd decoders surface the raw kernel `saddr=` hex
 * (family, port, address network byte order, zero padding) in the static
 * `srcip` field via the generic unanchored `addr=(\S+)` regex. srcip is a
 * STATIC Wazuh field — <field>/pcre2 conditions on it are rejected by the
 * loader ("Field 'srcip' is static") — so egress conditions are expressed as
 * full-log pcre2 matches over the precomputed raw records.
 */

import type { NetCompiled } from "../types.ts";

function ipHex8(ip: string): string {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    throw new Error(`ERR_ADDR: cannot express "${ip}" as a raw AF_INET sockaddr fragment`);
  }
  return parts.map((p) => p.toString(16).toUpperCase().padStart(2, "0")).join("");
}

function portHex4(port: number): string {
  if (port < 1 || port > 65535) {
    throw new Error(`ERR_PORT: cannot express port ${port} as a raw AF_INET sockaddr fragment`);
  }
  return port.toString(16).toUpperCase().padStart(4, "0");
}

/** Hex digits allowed in one nybble when its low `bits` bits remain free. */
function partialNybbleClass(value: number, bits: number): string {
  const mask = (1 << bits) - 1;
  const chars: string[] = [];
  for (let d = 0; d <= 15; d++) {
    if ((d & ~mask) === (value & ~mask)) chars.push(d.toString(16).toUpperCase());
  }
  return chars.length === 1 ? chars[0]! : `[${chars.join("")}]`;
}

/** Address REM for ip/maskBits: fixed nybbles, optional partial-nybble class, free nybbles. */
function addrRem(ip: string, maskBits: number): string {
  const hex = ipHex8(ip);
  const fullNybbles = Math.floor(maskBits / 4);
  const remBits = maskBits % 4;
  if (fullNybbles >= 8) return hex;
  let out = hex.slice(0, fullNybbles);
  if (remBits > 0) {
    // the next nybble is partially fixed: its low (4 - remBits) bits remain free
    const nyb = parseInt(hex[fullNybbles]!, 16);
    out += partialNybbleClass(nyb, 4 - remBits);
  }
  const free = 8 - fullNybbles - (remBits > 0 ? 1 : 0);
  if (free > 0) out += `[0-9A-F]{${free}}`;
  return out;
}

/**
 * Raw AF_INET sockaddr REM for one allowed (addr, port) pair:
 * family (0200) + port + address (network byte order) + zero padding.
 * port === null means ANY port. Example: 10.96.100.10:11211 ->
 * 02002BCB0A60640A0000000000000000; 10.96.0.0/12 any port ->
 * 0200[0-9A-F]{4}0A6[0-9A-F]{5}0{16}.
 */
export function saddrAllowedFragment(ip: string, maskBits: number, port: number | null): string | null {
  const portPart = port === null ? "[0-9A-F]{4}" : portHex4(port);
  return `0200${portPart}${addrRem(ip, maskBits)}0{16}`;
}

/**
 * All allowed REM fragments for one egress entry: family+port+addr+padding
 * keep their fixed hex; the drift rule's negative lookahead then accepts any
 * AF_INET sockaddr NOT covered by an allowed fragment. Entries with no
 * explicit port produce any-port fragments.
 */
export function saddrEntryFragments(entry: NetCompiled): string[] {
  const out: string[] = [];
  for (const addr of entry.addrEntries) {
    let ip = addr;
    let mask = 32;
    const slash = addr.indexOf("/");
    if (slash > 0) {
      ip = addr.slice(0, slash);
      const m = Number(addr.slice(slash + 1));
      if (!Number.isNaN(m) && m >= 0 && m <= 32) mask = m;
    }
    const ports = entry.ports.filter((p): p is number => typeof p === "number");
    for (const p of ports) {
      const frag = saddrAllowedFragment(ip, mask, p);
      if (frag) out.push(frag);
    }
    if (ports.length === 0 || entry.ports.some((p) => p === null)) {
      const frag = saddrAllowedFragment(ip, mask, null);
      if (frag) out.push(frag);
    }
  }
  return out;
}
