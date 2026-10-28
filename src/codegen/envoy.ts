/**
 * Envoy L7 endpoint-drift ingestion (TDS 13, M6 / issue #7): closes the §8
 * endpoints[] coverage gap by evaluating the documented Envoy JSON access-log
 * stream against the SBoB endpoints[] allowlist.
 *
 * Emitted into the k8s-node bundle when (and only when) the SBoB declares an
 * endpoints[] section:
 *   - wazuh/lists/sbob/<name>/endpoints_in   CDB allowlist of inbound paths
 *   - wazuh/lists/sbob/<name>/endpoints_out  CDB allowlist of outbound paths
 *   - wazuh/manager/sbob/<name>-envoy.md     the exact Envoy access_log format
 *                                             the proxy must emit + localfile
 *                                             ingestion snippet (json)
 *   - rules (9,x) in the k8s rules XML: (9,1) inbound endpoint drift, (9,2)
 *     outbound endpoint drift (level 9) — manager-side, same JSON-native
 *     pattern as the 100064 k8s-audit rule (TDS 4.4).
 *
 * Documented v1 limitations (coverage matrix reason ENVOY_L7):
 *   - drift is evaluated on (direction, path) pairs; endpoint methods are
 *     reported in the alert fields but not enforced in v1, and headers[] are
 *     not evaluated (never observable from access logs);
 *   - requires the documented access_log format — a stock Envoy format will
 *     not match the decoder fields.
 */
import type { IdAllocator } from "../ruleids.ts";
import type { IR } from "../types.ts";
import type { BundleFile } from "./linux.ts";
import type { XmlRule } from "./xml.ts";
import { xmlFileHeader } from "./xml.ts";

/** Envoy access_log format string the proxy side must configure. */
export function envoyAccessLogFormat(name: string): string {
  return JSON.stringify({
    sbob_workload: name,
    direction: "%DIRECTION%",
    method: "%REQ(:METHOD)%",
    path: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
    response_code: "%RESPONSE_CODE%",
  });
}

/** CDB list files for the per-direction path allowlists. */
export function envoyListFiles(ir: IR, name: string): BundleFile[] {
  const files: BundleFile[] = [];
  const header = (dir: string) =>
    `# sbobctl generated endpoints[] allowlist (${dir}bound; key=path)\n` +
    `# evaluated by the (9,${dir === "in" ? 1 : 2}) endpoint drift rule against the envoy JSON access log (TDS 13)\n`;
  const byDir = (dir: "inbound" | "outbound") =>
    [...new Set((ir.sections.endpoints ?? []).filter((e) => e.direction === dir).map((e) => e.endpoint))];
  const inbound = byDir("inbound");
  const outbound = byDir("outbound");
  if (inbound.length > 0) {
    files.push({
      path: `wazuh/lists/sbob/${name}/endpoints_in`,
      content: header("in") + inbound.map((p) => `${p}:1`).join("\n") + "\n",
    });
  }
  if (outbound.length > 0) {
    files.push({
      path: `wazuh/lists/sbob/${name}/endpoints_out`,
      content: header("out") + outbound.map((p) => `${p}:1`).join("\n") + "\n",
    });
  }
  return files;
}

/** Manager-side ingestion doc — the Envoy config contract. */
export function envoyIngestionDoc(ir: IR, name: string): BundleFile {
  return {
    path: `wazuh/manager/sbob/${name}-envoy.md`,
    content: [
      `# Envoy access-log ingestion for workload ${name} (TDS 13, M6)`,
      ``,
      `The endpoints[] section of the ${name} SBoB is evaluated against the`,
      `proxy access log. Configure the workload's Envoy sidecar / ingress with`,
      `exactly this JSON access_log format:`,
      ``,
      "```yaml",
      `access_log:`,
      `  - name: sbob_endpoint_drift`,
      `    filter:`,
      `      status_code_filter:`,
      `        comparison: {op: GE, value: 100}`,
      `    typed_config:`,
      `      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog`,
      `      log_format:`,
      `        json_format: ${envoyAccessLogFormat(name)}`,
      "```",
      ``,
      `Ship the container stdout to the Wazuh manager and ingest it as JSON`,
      `(the 100064 k8s-audit pattern, TDS 4.4):`,
      ``,
      "```xml",
      `<localfile>`,
      `  <location>/var/ossec/logs/sbob/${name}-envoy.json</location>`,
      `  <log_format>json</log_format>`,
      `</localfile>`,
      "```",
      ``,
      `The (9,1)/(9,2) endpoint drift rules in the bundle then alert on any`,
      `request whose \`path\` is not in the per-direction CDB allowlist`,
      `(\`endpoints_in\`/\`endpoints_out\`). Methods are reported in the alert but`,
      `not enforced in v1; headers[] are not evaluable from access logs`,
      `(coverage reason ENVOY_L7, TDS 8).`,
    ].join("\n") + "\n",
  };
}

/**
 * Endpoint drift rules (section code 9, TDS 6.1 amendment):
 *   (9,1) inbound  — direction=inbound AND path not in endpoints_in
 *   (9,2) outbound — direction=outbound AND path not in endpoints_out
 * Both level 9, manager-side, k8s target only (Envoy runs beside the workload).
 */
export function envoyRules(ir: IR, alloc: IdAllocator, name: string): XmlRule[] {
  const rules: XmlRule[] = [];
  const dirs: Array<{ dir: "inbound" | "outbound"; kind: "drift" | "escalation"; src: string }> = [
    { dir: "inbound", kind: "drift", src: "endpoints_in" },
    { dir: "outbound", kind: "escalation", src: "endpoints_out" },
  ];
  for (const d of dirs) {
    const has = (ir.sections.endpoints ?? []).some((e) => e.direction === d.dir);
    if (!has) continue;
    rules.push({
      id: alloc.linux("endpoints", d.kind), // (9,1) / (9,2)
      level: 9,
      fields: [{ name: "direction", regex: `^${d.dir}$` }],
      list: { field: "path", lookup: "not_match_key", src: `sbob/${name}/${d.src}` },
      description:
        `SBoB drift: ${d.dir} HTTP request to an endpoint not declared in endpoints[] of ${name} (method and response code travel on the alert; TDS 13)`,
      groups: [["sbob", name, "sbob-drift", "l7-endpoint"]],
      comment: `endpoints (${d.dir}) — evaluates the envoy JSON access log (${name}-envoy.md ingestion path; path-level v1: methods reported, not enforced)`,
    });
  }
  return rules;
}
