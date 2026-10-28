/**
 * SBoB v0.0.4 structural validation (hand-rolled; no schema library available).
 * Produces typed SbobDocument or throws ERR_SCHEMA_INVALID with a path to the
 * offending field.
 */
import { SbobError } from "./errors.ts";
import {
  asArray, asMap, asString, describeYaml,
  OPEN_FLAGS, SBOB_API_VERSION, SBOB_KIND, type OpenFlag,
} from "./types.ts";
import type { YamlValue } from "./yaml.ts";

function fail(path: string, msg: string): never {
  throw new SbobError("ERR_SCHEMA_INVALID", `${path}: ${msg}`);
}

function reqString(v: YamlValue, path: string): string {
  if (typeof v !== "string" || v === "") fail(path, "expected non-empty string, got " + describeYaml(v));
  return v as string;
}

function optString(v: YamlValue, path: string): string | undefined {
  if (v === null || v === undefined) return undefined;
  return reqString(v, path);
}

function stringList(v: YamlValue, path: string): string[] {
  const arr = asArray(v);
  return arr.map((item, i) => reqString(item, `${path}[${i}]`));
}

export function validateSbob(doc: YamlValue): SbobDocumentLike {
  const root = asMap(doc);
  const apiVersion = reqString(root["apiVersion"], "apiVersion");
  if (apiVersion !== SBOB_API_VERSION) {
    fail("apiVersion", `expected "${SBOB_API_VERSION}", got "${apiVersion}"`);
  }
  const kind = reqString(root["kind"], "kind");
  if (kind !== SBOB_KIND) fail("kind", `expected "${SBOB_KIND}", got "${kind}"`);

  const meta = asMap(root["metadata"]);
  const name = reqString(meta["name"], "metadata.name");
  const namespace = reqString(meta["namespace"], "metadata.namespace");
  const annotations = meta["annotations"] === undefined || meta["annotations"] === null
    ? undefined
    : Object.fromEntries(Object.entries(asMap(meta["annotations"])).map(([k, v]) => [k, reqString(v, `metadata.annotations.${k}`)]));

  const spec = asMap(root["spec"]);
  const imageID = reqString(spec["imageID"], "spec.imageID");

  const out: SbobDocumentLike = {
    apiVersion,
    kind,
    metadata: { name, namespace, annotations },
    spec: { imageID },
  };

  if (spec["architectures"] !== undefined && spec["architectures"] !== null) {
    out.spec.architectures = stringList(spec["architectures"], "spec.architectures");
  }
  if (spec["capabilities"] !== undefined && spec["capabilities"] !== null) {
    const caps = asArray(spec["capabilities"]).map((c, i) => {
      const s = reqString(c, `spec.capabilities[${i}]`);
      if (!/^CAP_[A-Z_]+$/.test(s)) fail(`spec.capabilities[${i}]`, `"${s}" is not an upper-case capabilities(7) token`);
      return s;
    });
    out.spec.capabilities = caps;
  }

  // execs -------------------------------------------------------------------
  if (spec["execs"] !== undefined && spec["execs"] !== null) {
    out.spec.execs = asArray(spec["execs"]).map((e, i) => {
      const m = asMap(e);
      return {
        path: reqString(m["path"], `spec.execs[${i}].path`),
        args: m["args"] === undefined || m["args"] === null ? undefined : stringList(m["args"], `spec.execs[${i}].args`),
      };
    });
  }

  // opens -------------------------------------------------------------------
  if (spec["opens"] !== undefined && spec["opens"] !== null) {
    out.spec.opens = asArray(spec["opens"]).map((e, i) => {
      const m = asMap(e);
      const flags = asArray(m["flags"]).map((f, j) => {
        const s = reqString(f, `spec.opens[${i}].flags[${j}]`);
        if (!(OPEN_FLAGS as readonly string[]).includes(s)) {
          fail(`spec.opens[${i}].flags[${j}]`, `"${s}" is not one of ${OPEN_FLAGS.join(", ")}`);
        }
        return s as OpenFlag;
      });
      if (flags.length === 0) fail(`spec.opens[${i}].flags`, "must not be empty (flags is required per spec 4.6)");
      return { path: reqString(m["path"], `spec.opens[${i}].path`), flags };
    });
  }

  // ingress / egress ----------------------------------------------------------
  for (const key of ["egress", "ingress"] as const) {
    const raw = spec[key];
    if (raw === undefined || raw === null) continue;
    out.spec[key] = asArray(raw).map((e, i) => validateNetEntry(e, `spec.${key}[${i}]`));
  }

  // endpoints ----------------------------------------------------------------
  if (spec["endpoints"] !== undefined && spec["endpoints"] !== null) {
    out.spec.endpoints = asArray(spec["endpoints"]).map((e, i) => {
      const m = asMap(e);
      const direction = reqString(m["direction"], `spec.endpoints[${i}].direction`);
      if (direction !== "inbound" && direction !== "outbound") {
        fail(`spec.endpoints[${i}].direction`, `expected "inbound" or "outbound", got "${direction}"`);
      }
      const headersRaw = m["headers"];
      let headers: Record<string, string> | null | undefined;
      if (headersRaw === null) headers = null;
      else if (headersRaw !== undefined) {
        headers = Object.fromEntries(
          Object.entries(asMap(headersRaw)).map(([k, v]) => [k, optString(v, `spec.endpoints[${i}].headers.${k}`) ?? ""]),
        );
      }
      return {
        endpoint: reqString(m["endpoint"], `spec.endpoints[${i}].endpoint`),
        methods: m["methods"] === undefined || m["methods"] === null ? undefined : stringList(m["methods"], `spec.endpoints[${i}].methods`),
        headers,
        direction,
      };
    });
  }

  // rulePolicies --------------------------------------------------------------
  if (spec["rulePolicies"] !== undefined && spec["rulePolicies"] !== null) {
    const rp: Record<string, { processAllowed?: string[]; containerAllowed?: boolean }> = {};
    for (const [ruleName, value] of Object.entries(asMap(spec["rulePolicies"]))) {
      if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(ruleName)) {
        fail(`spec.rulePolicies.${ruleName}`, "keys must be kebab-case generalized rule names (spec 4.8)");
      }
      const m = asMap(value);
      const entry: { processAllowed?: string[]; containerAllowed?: boolean } = {};
      if (m["processAllowed"] !== undefined && m["processAllowed"] !== null) {
        entry.processAllowed = stringList(m["processAllowed"], `spec.rulePolicies.${ruleName}.processAllowed`);
      }
      if (m["containerAllowed"] !== undefined && m["containerAllowed"] !== null) {
        const b = m["containerAllowed"];
        if (typeof b !== "boolean") fail(`spec.rulePolicies.${ruleName}.containerAllowed`, "expected boolean");
        entry.containerAllowed = b as boolean;
      }
      rp[ruleName] = entry;
    }
    out.spec.rulePolicies = rp;
  }

  return out;
}

function validateNetEntry(e: YamlValue, path: string): NetEntryLike {
  const m = asMap(e);
  const portsRaw = asArray(m["ports"]);
  const ports = portsRaw.map((p, j) => {
    const pm = asMap(p);
    // narrowed by the fail() guard below to the three literal protocols
    const protocol = optString(pm["protocol"], `${path}.ports[${j}].protocol`) as "TCP" | "UDP" | "SCTP" | undefined;
    if (protocol !== undefined && protocol !== "TCP" && protocol !== "UDP" && protocol !== "SCTP") {
      fail(`${path}.ports[${j}].protocol`, `expected TCP, UDP or SCTP, got "${protocol}"`);
    }
    let port: number | null = null;
    const pv = pm["port"];
    if (pv !== undefined && pv !== null) {
      if (typeof pv !== "number" || !Number.isInteger(pv) || pv < 1 || pv > 65535) {
        fail(`${path}.ports[${j}].port`, "expected null (ANY) or integer 1-65535");
      }
      port = pv as number;
    }
    return {
      name: optString(pm["name"], `${path}.ports[${j}].name`),
      protocol,
      port,
    };
  });
  const entry: NetEntryLike = { ports };
  const identifier = optString(m["identifier"], `${path}.identifier`);
  if (identifier !== undefined) entry.identifier = identifier;
  const type = optString(m["type"], `${path}.type`);
  if (type !== undefined) {
    if (type !== "external" && type !== "internal") fail(`${path}.type`, `expected "external" or "internal", got "${type}"`);
    entry.type = type as "external" | "internal";
  }
  if (m["ipAddresses"] !== undefined && m["ipAddresses"] !== null) {
    entry.ipAddresses = stringList(m["ipAddresses"], `${path}.ipAddresses`);
  }
  if (m["dnsNames"] !== undefined && m["dnsNames"] !== null) {
    entry.dnsNames = stringList(m["dnsNames"], `${path}.dnsNames`);
  }
  for (const selKey of ["podSelector", "namespaceSelector"] as const) {
    const raw = m[selKey];
    if (raw === undefined || raw === null) continue;
    const sm = asMap(raw);
    const ml = asMap(sm["matchLabels"]);
    entry[selKey] = { matchLabels: Object.fromEntries(Object.entries(ml).map(([k, v]) => [k, reqString(v, `${path}.${selKey}.matchLabels.${k}`)])) };
  }
  return entry;
}

// Structural types local to this module (validated, pre-IR)
export interface NetEntryLike {
  identifier?: string;
  type?: "external" | "internal";
  ipAddresses?: string[];
  dnsNames?: string[];
  podSelector?: { matchLabels?: Record<string, string> };
  namespaceSelector?: { matchLabels?: Record<string, string> };
  ports: Array<{ name?: string; protocol?: "TCP" | "UDP" | "SCTP"; port: number | null }>;
}

export interface SbobDocumentLike {
  apiVersion: string;
  kind: string;
  metadata: { name: string; namespace: string; annotations?: Record<string, string> };
  spec: {
    imageID: string;
    architectures?: string[];
    capabilities?: string[];
    endpoints?: Array<{
      endpoint: string;
      methods?: string[];
      headers?: Record<string, string> | null;
      direction: "inbound" | "outbound";
    }>;
    execs?: Array<{ path: string; args?: string[] }>;
    opens?: Array<{ path: string; flags: string[] }>;
    ingress?: NetEntryLike[];
    egress?: NetEntryLike[];
    rulePolicies?: Record<string, { processAllowed?: string[]; containerAllowed?: boolean }>;
  };
}
