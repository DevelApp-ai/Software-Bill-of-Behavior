/**
 * Deterministic rule-ID allocation (TDS 6.1).
 *
 *   rule_id = 100000 + workload_slot * 100 + section_code * 10 + variant
 *
 * Band 100000-199999. Slots are allocated once from a committed registry
 * (docs/sbob-registry.yaml) and never reused. Section codes: 0 base, 1 execs,
 * 2 opens, 3 egress, 4 ingress, 5 capabilities, 6 rulePolicies, 7 attribution.
 *
 * Variant digits (deviation from TDS 6.1, documented there):
 *   0-4 = Linux / k8s-node rule kinds: 0 base, 1 drift, 2 escalation, 3 informational, 4 exemption
 *   5-9 = Windows rule kinds:          5 base, 6 drift, 7 escalation, 8 informational, 9 exemption
 * Linux and k8s-node share variants because k8s nodes run the Linux agent.
 */
import { SbobError } from "./errors.ts";
import { parseYaml, type YamlValue } from "./yaml.ts";
import { asMap, asString } from "./types.ts";

export const ID_BAND_MIN = 100000;
export const ID_BAND_MAX = 199999;
export const MAX_SLOT = 999;

export const SECTION_CODES = {
  base: 0, execs: 1, opens: 2, egress: 3, ingress: 4,
  capabilities: 5, rulePolicies: 6, attribution: 7,
} as const;

export const LINUX_VARIANTS = { base: 0, drift: 1, escalation: 2, info: 3, exemption: 4 } as const;
export const WINDOWS_VARIANTS = { base: 5, drift: 6, escalation: 7, info: 8, exemption: 9 } as const;

export interface SlotRegistry {
  /** workload name -> slot */
  slots: Map<string, number>;
}

export function emptyRegistry(): SlotRegistry {
  return { slots: new Map() };
}

export function parseRegistry(source: string): SlotRegistry {
  const root = asMap(parseYaml(source));
  const workloads = asMap(root["workloads"]);
  const slots = new Map<string, number>();
  const seen = new Map<number, string>();
  for (const [name, v] of Object.entries(workloads)) {
    const m = asMap(v);
    // accept both `slot: 0` (number) and `slot: "0"` (string) spellings
    const raw = m["slot"];
    const slot = typeof raw === "number" ? String(raw) : asString(raw);
    if (!/^\d+$/.test(slot)) {
      throw new SbobError("ERR_ID_COLLISION", `registry: slot for "${name}" is not an integer ("${slot}")`);
    }
    const n = Number(slot);
    if (n > MAX_SLOT) throw new SbobError("ERR_ID_COLLISION", `registry: slot ${n} for "${name}" exceeds ${MAX_SLOT}`);
    const prev = seen.get(n);
    if (prev !== undefined && prev !== name) {
      throw new SbobError("ERR_ID_COLLISION", `registry: slot ${n} used by both "${prev}" and "${name}"`);
    }
    seen.set(n, name);
    slots.set(name, n);
  }
  return { slots };
}

export function registryToYaml(reg: SlotRegistry): string {
  const lines = ["# sbobctl workload slot registry (TDS 6.1). Slots are allocated once and never reused.", "workloads:"];
  const names = [...reg.slots.keys()].sort((a, b) => reg.slots.get(a)! - reg.slots.get(b)!);
  if (names.length === 0) lines.push("  {}");
  for (const n of names) lines.push(`  ${n}: {slot: ${reg.slots.get(n)}}`);
  return lines.join("\n") + "\n";
}

/** Allocate (and record) a slot for a workload, or return the existing one. */
export function slotFor(ir_name: string, reg: SlotRegistry): number {
  const existing = reg.slots.get(ir_name);
  if (existing !== undefined) return existing;
  let max = -1;
  for (const s of reg.slots.values()) if (s > max) max = s;
  const next = max + 1;
  if (next > MAX_SLOT) {
    throw new SbobError("ERR_ID_COLLISION", `registry exhausted (${MAX_SLOT + 1} slots); ID band ${ID_BAND_MIN}-${ID_BAND_MAX} is full`);
  }
  reg.slots.set(ir_name, next);
  return next;
}

export interface IdAllocator {
  slot: number;
  /** Track issued IDs to detect collisions within a bundle. */
  issued: Map<number, string>;
  linux(section: keyof typeof SECTION_CODES, kind: keyof typeof LINUX_VARIANTS): number;
  windows(section: keyof typeof SECTION_CODES, kind: keyof typeof WINDOWS_VARIANTS): number;
}

export function makeAllocator(workload: string, slot: number): IdAllocator {
  const issued = new Map<number, string>();
  const alloc = (section: number, variant: number): number => {
    const id = ID_BAND_MIN + slot * 100 + section * 10 + variant;
    if (id > ID_BAND_MAX) {
      throw new SbobError("ERR_ID_COLLISION", `derived rule id ${id} for ${workload} exceeds band max ${ID_BAND_MAX}`);
    }
    const prev = issued.get(id);
    if (prev !== undefined) {
      throw new SbobError("ERR_ID_COLLISION", `rule id ${id} already issued for ${workload} (${prev}); section/variant layout overflow`);
    }
    issued.set(id, `${workload}:${section}/${variant}`);
    return id;
  };
  return {
    slot,
    issued,
    linux(section, kind) {
      return alloc(SECTION_CODES[section], LINUX_VARIANTS[kind]);
    },
    windows(section, kind) {
      return alloc(SECTION_CODES[section], WINDOWS_VARIANTS[kind]);
    },
  };
}
