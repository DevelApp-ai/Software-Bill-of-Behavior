/**
 * IR v1 construction (TDS 5.1): validated SBoB -> engine-neutral IR with
 * compiled wildcard artifacts. All later codegen (Wazuh, Sigma, Velociraptor,
 * MDE, Falco) consumes this IR, never the raw SBoB.
 */
import { SBOB_SPEC_VERSION, type IR, type PathSeg } from "./types.ts";
import { compileArgsPattern, compileDnsPattern, compilePathSegs, parseIpEntry, parsePathPattern } from "./wildcards.ts";
import type { SbobDocumentLike } from "./schema.ts";
import type { YamlValue } from "./yaml.ts";

export function buildIR(doc: SbobDocumentLike, rawYaml?: YamlValue): IR {
  const name = doc.metadata.name;
  const coverageNotes: string[] = [];
  const sbobVersion = readSpecVersion(rawYaml) ?? SBOB_SPEC_VERSION;

  const ir: IR = {
    irVersion: 1,
    workload: {
      name,
      namespace: doc.metadata.namespace,
      imageID: doc.spec.imageID,
      sbobVersion,
      scope: {
        linuxGroups: [`sbob-${name}`],
        windowsGroups: [`sbob-${name}`],
        k8s: { namespace: doc.metadata.namespace, imageID: doc.spec.imageID },
      },
    },
    sections: {},
    rulePolicies: doc.spec.rulePolicies,
    coverageNotes,
  };

  const spec = doc.spec;

  if (spec.execs !== undefined) {
    const entries = spec.execs.map((e) => {
      const pathSegs: PathSeg[] = parsePathPattern(e.path, `execs[].path (${e.path})`);
      const pathRegex = compilePathSegs(pathSegs);
      const argsRegex = e.args === undefined ? null : compileArgsPattern(e.args, `execs[].args (${e.path})`);
      const isExact = pathSegs.every((s) => s.kind === "literal");
      return { pathSegs, pathRegex, argsRegex, isExact, source: e };
    });
    ir.sections.execs = {
      entries,
      exact: entries.filter((x) => x.isExact).map((x) => x.source.path),
      patterns: entries.filter((x) => !x.isExact).map((x) => x.pathRegex),
    };
  } else {
    coverageNotes.push("execs: section-absent");
  }

  if (spec.opens !== undefined) {
    const entries = spec.opens.map((e) => {
      const pathSegs = parsePathPattern(e.path, `opens[].path (${e.path})`);
      const pathRegex = compilePathSegs(pathSegs);
      const isExact = pathSegs.every((s) => s.kind === "literal");
      return { pathSegs, pathRegex, flagMask: flagMask(e.flags), isExact, source: e as any };
    });
    ir.sections.opens = {
      entries,
      exact: entries.filter((x) => x.isExact).map((x) => x.source.path),
      patterns: entries.filter((x) => !x.isExact).map((x) => x.pathRegex),
    };
  } else {
    coverageNotes.push("opens: section-absent");
  }

  for (const key of ["egress", "ingress"] as const) {
    const rawEntries = spec[key];
    if (rawEntries === undefined) {
      if (key === "egress") coverageNotes.push("egress: section-absent");
      continue;
    }
    const entries = rawEntries.map((e) => {
      const addrEntries: string[] = [];
      let anyIp = false;
      for (const ip of e.ipAddresses ?? []) {
        const parsed = parseIpEntry(ip, `${key}[].ipAddresses (${ip})`);
        if (parsed.any) anyIp = true;
        else addrEntries.push(parsed.cdb);
      }
      const dnsPatterns: string[] = [];
      const dnsExact: string[] = [];
      for (const d of e.dnsNames ?? []) {
        if (d.includes("*") || d.includes("\u22EF")) dnsPatterns.push(compileDnsPattern(d, `${key}[].dnsNames (${d})`));
        else dnsExact.push(d.toLowerCase());
      }
      const k8sPeer = e.podSelector !== undefined || e.namespaceSelector !== undefined;
      if (k8sPeer) {
        coverageNotes.push(
          `${key}: podSelector/namespaceSelector entry ("${e.identifier ?? "unnamed"}") recorded for Phase-3 NetworkPolicy diff; node telemetry evaluates only ipAddresses/dnsNames/ports`,
        );
      }
      return {
        addrEntries,
        anyIp,
        dnsPatterns,
        dnsExact,
        ports: e.ports.map((p) => p.port),
        k8sPeer,
        source: e as any,
      };
    });
    ir.sections[key] = {
      entries,
      exact: entries.flatMap((x) => x.addrEntries),
      patterns: entries.flatMap((x) => x.dnsPatterns),
    };
    if (key === "ingress") {
      coverageNotes.push("ingress: Linux accept() telemetry cannot attribute peers; drift rules emitted but require host-firewall or accept-path decoder validation (TDS 8)");
    }
  }
  if (spec.ingress === undefined) coverageNotes.push("ingress: section-absent");

  if (spec.capabilities !== undefined) ir.sections.capabilities = spec.capabilities;
  else coverageNotes.push("capabilities: section-absent");

  if (spec.endpoints !== undefined) {
    ir.sections.endpoints = spec.endpoints as any;
    coverageNotes.push("endpoints: HTTP-level sections are not observable from auditd/eventchannel telemetry; coverage deferred to Phase 2 L7 ingestion (TDS 8)");
  }

  // rulePolicies absence is semantic (spec 5.4): absent != NONE — the M4
  // signature pack is emitted with defaults when the section is missing.
  if (spec.rulePolicies === undefined) coverageNotes.push("rulePolicies: section-absent");

  return ir;
}

function flagMask(flags: string[]): number {
  // Internal bitmask; low bit is O_RDONLY so a mask is always non-zero.
  const order = ["O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_CLOEXEC", "O_NONBLOCK", "O_DIRECTORY", "O_NOFOLLOW", "O_PATH"];
  let m = 0;
  for (const f of flags) {
    const i = order.indexOf(f);
    if (i >= 0) m |= 1 << i;
  }
  return m;
}

function readSpecVersion(raw: YamlValue | undefined): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const ann = (raw as Record<string, any>)["metadata"];
  if (ann === undefined || ann === null) return undefined;
  const specV = (ann as Record<string, any>)["annotations"];
  if (specV === undefined || specV === null) return undefined;
  const v = (specV as Record<string, any>)["sbob.spec-version"];
  return typeof v === "string" ? v : undefined;
}
