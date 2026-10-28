import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import {
  diffSbobs,
  formatDiffReport,
  ADVISORY_THRESHOLD_DEFAULT,
  MANDATORY_THRESHOLD_DEFAULT,
} from "../src/diffgate.ts";
import type { SbobDocumentLike } from "../src/schema.ts";

function load(path: string): SbobDocumentLike {
  const raw = readFileSync(new URL(path, import.meta.url), "utf8");
  return validateSbob(parseYaml(raw));
}

function fixture(name: string): SbobDocumentLike {
  return load("./diffgate-fixtures/" + name);
}

function fromYaml(yaml: string): SbobDocumentLike {
  return validateSbob(parseYaml(yaml));
}

const tinyOld = `
apiVersion: sbob.k8sstormcenter.io/v1
kind: SoftwareBillOfBehavior
metadata:
  name: tiny
  namespace: ns
spec:
  imageID: docker.io/x/tiny@sha256:aa
  execs:
  - path: /app/server
  - path: /app/helper
`;

const tinyNew = `
apiVersion: sbob.k8sstormcenter.io/v1
kind: SoftwareBillOfBehavior
metadata:
  name: tiny
  namespace: ns
spec:
  imageID: docker.io/x/tiny@sha256:bb
  execs:
  - path: /app/server
  - path: /app/helper
  - path: /tmp/x
  - path: /tmp/y
  - path: /tmp/z
  opens:
  - path: /etc/passwd
    flags: [O_RDONLY]
`;

test("identical SBoBs diff to zero (semantic, format-independent)", () => {
  const base = fixture("base.yaml");
  const result = diffSbobs(base, base);
  assert.equal(result.delta.length, 0);
  assert.equal(result.score, 0);
  assert.equal(result.verdict, "clean");
  assert.equal(result.immediateReview, false);
});

test("drifted fixture: every ladder weight class is represented", () => {
  const result = diffSbobs(fixture("base.yaml"), fixture("drifted.yaml"));
  const weights = new Set(result.delta.map((d) => d.weight));
  for (const w of [1, 2, 3, 4, 5]) assert.ok(weights.has(w), `expected weight class ${w} in fixture delta`);
  assert.ok(result.score >= MANDATORY_THRESHOLD_DEFAULT);
  assert.equal(result.verdict, "mandatory");
  assert.equal(result.immediateReview, true);
});

test("drifted fixture: representative entries carry the right weight", () => {
  const result = diffSbobs(fixture("base.yaml"), fixture("drifted.yaml"));
  const find = (section: string, entry: string) => result.delta.find((d) => d.section === section && d.entry === entry);
  assert.equal(find("capabilities", "CAP_SYS_PTRACE")?.weight, 5);
  assert.equal(find("execs", "/tmp/payload")?.weight, 4);
  assert.equal(find("egress", "peer id:stripe-api: dns *.cdn.example.com.")?.weight, 3);
  assert.equal(find("egress", "peer id:internal-metrics: dns metrics.internal.svc.")?.weight, 2);
  assert.equal(find("opens", "/data/*")?.change, "widened");
  assert.equal(find("opens", "/data/*")?.weight, 2);
  assert.equal(find("opens", "/etc/hosts")?.weight, 1);
  assert.equal(find("opens", "/etc/resolv.conf")?.change, "modified");
  assert.equal(find("execs", "/bin/sh")?.change, "removed");
  assert.equal(find("rulePolicies", "namespace-change: processAllowed nsjail")?.weight, 5);
});

test("endpoints[] changes are reported but unweighted (v1)", () => {
  const result = diffSbobs(fixture("base.yaml"), fixture("drifted.yaml"));
  assert.ok(result.unweighted.some((u) => u.includes(":8080/health")));
  assert.ok(result.delta.every((d) => d.section !== "endpoints"));
});

test("advisory verdict between the thresholds", () => {
  const result = diffSbobs(fromYaml(tinyOld), fromYaml(tinyNew));
  // three outside-namespace execs (4×3) + one read-only open (1) = 13
  assert.equal(result.score, 13);
  assert.equal(result.verdict, "advisory");
  assert.equal(result.immediateReview, false);
});

test("any +5 class forces immediate mandatory review below the advisory threshold", () => {
  const oldDoc = fromYaml(tinyOld);
  const yamlNew = tinyOld + "  capabilities:\n  - CAP_SYS_PTRACE\n";
  const result = diffSbobs(oldDoc, fromYaml(yamlNew));
  assert.equal(result.score, 5); // below advisory threshold...
  assert.equal(result.verdict, "mandatory"); // ...but immediate review regardless
  assert.equal(result.immediateReview, true);
});

test("workload mismatch is rejected loudly", () => {
  assert.throws(
    () => diffSbobs(fixture("base.yaml"), fromYaml(tinyOld)),
    /ERR_WORKLOAD_MISMATCH/,
  );
});

test("namespace override relocates exec scoring", () => {
  const result = diffSbobs(fixture("base.yaml"), fixture("drifted.yaml"), { namespaces: ["/tmp", "/usr/bin", "/bin"] });
  const payload = result.delta.find((d) => d.section === "execs" && d.entry === "/tmp/payload");
  assert.equal(payload?.weight, 1); // inside the declared namespace now
  assert.ok(result.score < 45);
});

test("internal-suffix option demotes external DNS to internal", () => {
  const result = diffSbobs(fixture("base.yaml"), fixture("drifted.yaml"), { internalSuffixes: ["cdn.example.com"] });
  const dns = result.delta.find((d) => d.entry.includes("*.cdn.example.com."));
  assert.equal(dns?.weight, 2); // internal by declaration now
  assert.equal(result.score, 44);
});

test("thresholds are optionable", () => {
  const result = diffSbobs(fromYaml(tinyOld), fromYaml(tinyNew), { advisoryThreshold: 20 });
  assert.equal(result.score, 13);
  assert.equal(result.verdict, "clean"); // 13 < custom advisory threshold 20
  assert.equal(ADVISORY_THRESHOLD_DEFAULT, 10);
  assert.equal(MANDATORY_THRESHOLD_DEFAULT, 25);
});

test("deterministic output: repeated diffs are byte-identical", () => {
  const a = diffSbobs(fixture("base.yaml"), fixture("drifted.yaml"));
  const b = diffSbobs(fixture("base.yaml"), fixture("drifted.yaml"));
  assert.equal(JSON.stringify(a), JSON.stringify(b));
  assert.equal(formatDiffReport(a), formatDiffReport(b));
});

test("golden report: fixture diff matches the committed JSON byte-for-byte", () => {
  const result = diffSbobs(fixture("base.yaml"), fixture("drifted.yaml"));
  const golden = readFileSync(new URL("./diffgate-fixtures/expected-report.json", import.meta.url), "utf8");
  assert.equal(JSON.stringify(result, null, 2) + "\n", golden);
});
