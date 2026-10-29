/**
 * Diff-gate scoring ladder (M8, TDS 16) — the delta classes the committed
 * base/drifted fixture pair does not reach: execs "covered" by a prior
 * pattern, exec pattern widening, the namespace-unknown fallback,
 * args-vector changes, the rulePolicies explicit-NONE regression, and
 * selector-only egress peers. Companion to test/diffgate.test.ts (which
 * pins the golden fixture and the threshold semantics).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { diffSbobs } from "../src/diffgate.ts";
import type { DiffResult } from "../src/diffgate.ts";
import type { SbobDocumentLike } from "../src/schema.ts";

function fromYaml(specYaml: string): SbobDocumentLike {
  return validateSbob(parseYaml(`
apiVersion: sbob.k8sstormcenter.io/v1
kind: SoftwareBillOfBehavior
metadata:
  name: probe
  namespace: ns
spec:
  imageID: docker.io/x/probe@sha256:aa
${specYaml}`));
}

function diffOf(oldYaml: string, newYaml: string, opts?: Parameters<typeof diffSbobs>[2]): DiffResult {
  return diffSbobs(fromYaml(oldYaml), fromYaml(newYaml), opts);
}

function findOne(result: DiffResult, section: string, entry: string) {
  return result.delta.find((d) => d.section === section && d.entry === entry);
}

// ---------------------------------------------------------------------------

test("execs: an exact path already covered by a prior pattern diffs as covered (weight 0)", () => {
  const result = diffOf(
    "  execs:\n  - path: /usr/bin/*\n",
    "  execs:\n  - path: /usr/bin/*\n  - path: /usr/bin/new-tool\n",
  );
  const covered = findOne(result, "execs", "/usr/bin/new-tool");
  assert.ok(covered, "covered delta present");
  assert.equal(covered!.change, "covered");
  assert.equal(covered!.weight, 0);
  assert.match(covered!.note ?? "", /already covered by a prior pattern/);
  assert.equal(result.score, 0); // covered entries never raise the gate
  assert.equal(result.verdict, "clean");
});

test("execs: a shorter pattern that widens a prior pattern is weighted 2, not 4", () => {
  const result = diffOf(
    "  execs:\n  - path: /usr/bin/redis-*\n",
    "  execs:\n  - path: /usr/bin/redis-*\n  - path: /usr/bin/*\n",
  );
  const widened = findOne(result, "execs", "/usr/bin/*");
  assert.ok(widened, "widened delta present");
  assert.equal(widened!.change, "widened");
  assert.equal(widened!.weight, 2);
  assert.match(widened!.note ?? "", /widens a prior pattern/);
});

test("execs: no prior exact execs means namespace unknown — new paths score outside with the fallback note", () => {
  const result = diffOf(
    "  execs:\n  - path: /opt/*\n", // pattern only: nothing to infer a namespace from
    "  execs:\n  - path: /opt/*\n  - path: /usr/bin/helper\n",
  );
  const added = findOne(result, "execs", "/usr/bin/helper");
  assert.ok(added, "added delta present");
  assert.equal(added!.change, "added");
  assert.equal(added!.weight, 4);
  assert.match(added!.note ?? "", /package namespace unknown/);
});

test("execs: args-vector change on an existing path is reported, unweighted", () => {
  const result = diffOf(
    "  execs:\n  - path: /app/server\n    args: [-d]\n",
    "  execs:\n  - path: /app/server\n    args: [-d, --verbose]\n",
  );
  assert.equal(result.delta.length, 0); // path identical, args not scored
  assert.ok(
    result.unweighted.some((u) => u === "execs: args vector changed for /app/server"),
    "args change reported unweighted",
  );
  assert.equal(result.score, 0);
  assert.equal(result.verdict, "clean");
});

test("rulePolicies: explicit NONE (removing all signature protection) is a weight-5 immediate-review regression", () => {
  const result = diffOf(
    "  rulePolicies:\n    module-load:\n      processAllowed: [modprobe]\n",
    "  rulePolicies: {}\n",
  );
  const regression = result.delta.find(
    (d) => d.section === "rulePolicies" && d.entry === "rulePolicies → explicit NONE",
  );
  assert.ok(regression, "NONE regression delta present");
  assert.equal(regression!.weight, 5);
  assert.match(regression!.note ?? "", /all signature protection removed/);
  // the gone policy itself is also recorded as a removal (weight 1):
  // the ladder scores the regression (5) plus the removal (1)
  const removedPolicy = result.delta.find((d) => d.entry === "module-load");
  assert.ok(removedPolicy, "removed policy delta present");
  assert.equal(removedPolicy!.weight, 1);
  assert.equal(result.score, 6); // below the advisory threshold...
  assert.equal(result.verdict, "mandatory"); // ...but any +5 class forces review
  assert.equal(result.immediateReview, true);
});

test("rulePolicies: containerAllowed true suppresses the whole signature rule — weight 5", () => {
  const result = diffOf(
    "  rulePolicies:\n    module-load:\n      processAllowed: [modprobe]\n",
    "  rulePolicies:\n    module-load:\n      processAllowed: [modprobe]\n      containerAllowed: true\n",
  );
  const suppressed = result.delta.find(
    (d) => d.section === "rulePolicies" && d.entry === "module-load: containerAllowed: true",
  );
  assert.ok(suppressed, "containerAllowed delta present");
  assert.equal(suppressed!.weight, 5);
  assert.match(suppressed!.note ?? "", /rule suppressed entirely/);
});

test("egress: a selector-only peer is scored 2 with the k8s peer note", () => {
  const result = diffOf(
    "  egress:\n  - identifier: old-peer\n    ipAddresses: [10.0.0.1/32]\n    ports: [{name: TCP-443, protocol: TCP, port: 443}]\n",
    "  egress:\n  - identifier: old-peer\n    ipAddresses: [10.0.0.1/32]\n    ports: [{name: TCP-443, protocol: TCP, port: 443}]\n"
      + "  - identifier: peers\n    podSelector: {matchLabels: {app: api}}\n"
      + "    ports: [{name: TCP-443, protocol: TCP, port: 443}]\n",
  );
  const peer = result.delta.find((d) => d.entry === "peer id:peers: k8s selector");
  assert.ok(peer, "selector peer delta present");
  assert.equal(peer!.weight, 2);
  assert.match(peer!.note ?? "", /podSelector\/namespaceSelector peer/);
});

test("egress: a removed peer scores 1 regardless of how much it used to allow", () => {
  const result = diffOf(
    "  egress:\n  - identifier: gone\n    ipAddresses: [10.0.0.1/32, 10.0.0.2/32]\n"
      + "    dnsNames: [\"*.api.stripe.com.\"]\n"
      + "    ports: [{name: TCP-443, protocol: TCP, port: 443}, {name: TCP-80, protocol: TCP, port: 80}]\n",
    "  egress: []\n",
  );
  const removed = result.delta.find((d) => d.entry === "peer id:gone");
  assert.ok(removed, "removed peer delta present");
  assert.equal(removed!.change, "removed");
  assert.equal(removed!.weight, 1);
  assert.equal(result.score, 1);
  assert.equal(result.verdict, "clean"); // removals tighten, never loosen
});

test("ingress: DNS names always score 2 — external or internal", () => {
  const result = diffOf(
    "  ingress:\n  - identifier: clients\n    ipAddresses: [10.0.0.0/8]\n    ports: [{name: TCP-6379, protocol: TCP, port: 6379}]\n",
    "  ingress:\n  - identifier: clients\n    ipAddresses: [10.0.0.0/8]\n    ports: [{name: TCP-6379, protocol: TCP, port: 6379}]\n"
      + "  - identifier: telemetry\n    dnsNames: [\"telemetry.vendor.io.\"]\n    ports: [{name: TCP-443, protocol: TCP, port: 443}]\n",
  );
  const dns = result.delta.find((d) => d.entry === "peer id:telemetry: dns telemetry.vendor.io.");
  assert.ok(dns, "ingress DNS delta present");
  assert.equal(dns!.weight, 2); // not the egress external weight of 3
  assert.equal(dns!.note, "external DNS name");
});
