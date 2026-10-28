import { test } from "node:test";
import assert from "node:assert/strict";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { SbobError } from "../src/errors.ts";

const VALID = `
apiVersion: sbob.k8sstormcenter.io/v1
kind: SoftwareBillOfBehavior
metadata:
  name: redis
  namespace: cache-tier
spec:
  imageID: docker.io/library/redis@sha256:e508c66a
  execs:
  - path: /usr/bin/redis-server
    args: ['/usr/bin/redis-server', '\u22EF\u22EF']
`;

function mustFail(source: string, pathNeedle: string): void {
  let caught: unknown;
  try {
    validateSbob(parseYaml(source));
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof SbobError, `expected SbobError for ${pathNeedle}`);
  assert.equal((caught as SbobError).code, "ERR_SCHEMA_INVALID");
  assert.ok(
    (caught as SbobError).message.includes(pathNeedle),
    `error path should mention "${pathNeedle}", got: ${(caught as SbobError).message}`,
  );
}

test("valid document passes validation", () => {
  const doc = validateSbob(parseYaml(VALID));
  assert.equal(doc.metadata.name, "redis");
  assert.equal(doc.spec.execs?.length, 1);
});

test("wrong apiVersion / kind fail with field paths", () => {
  mustFail(VALID.replace("sbob.k8sstormcenter.io/v1", "sbob.example.com/v9"), "apiVersion");
  mustFail(VALID.replace("SoftwareBillOfBehavior", "SomeOtherKind"), "kind");
});

test("missing metadata.name and namespace fail with field paths", () => {
  mustFail(VALID.replace("name: redis", "name: \"\""), "metadata.name");
  mustFail(VALID.replace("namespace: cache-tier", "namespace:"), "metadata.namespace");
});

test("missing imageID fails with field path", () => {
  mustFail(VALID.replace("imageID: docker.io/library/redis@sha256:e508c66a", "architectures: [amd64]"), "imageID");
});

test("execs entries require path; non-absolute paths rejected at IR build", () => {
  // path key missing entirely -> schema layer
  const noPath = VALID.replace(
    "  - path: /usr/bin/redis-server\n    args: ['/usr/bin/redis-server', '\u22EF\u22EF']\n",
    "  - args: [x]\n",
  );
  mustFail(noPath, "execs[0].path");
  // relative path passes schema but is rejected by the IR wildcard compiler
  const rel = VALID.replace("path: /usr/bin/redis-server", "path: relative/path");
  let caught: unknown;
  try {
    buildIR(validateSbob(parseYaml(rel)));
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof SbobError, "relative path rejected");
  assert.ok((caught as SbobError).message.includes("absolute"));
});

test("unknown open flags are rejected", () => {
  const src = VALID + `  opens:\n  - flags: [O_WEIRD]\n    path: /tmp/*\n`;
  mustFail(src, "O_WEIRD");
});

test("invalid DNS wildcard forms are rejected at IR build", () => {
  const src = VALID + "  egress:\n  - identifier: bad\n    dnsNames: [\"*a.stripe.com.\"]\n";
  let caught: unknown;
  try {
    buildIR(validateSbob(parseYaml(src)));
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof SbobError, "mid-label DNS wildcard rejected");
  assert.ok((caught as SbobError).message.includes("*a.stripe.com."));
});

test("selector-only egress entries defer to Phase 3 with a coverage note", () => {
  const src = VALID + "  egress:\n  - identifier: peers\n    podSelector: {matchLabels: {app: api}}\n    ports: [{name: TCP-443, protocol: TCP, port: 443}]\n";
  const ir = buildIR(validateSbob(parseYaml(src)));
  assert.ok(
    ir.coverageNotes.some((n) => n.includes("podSelector")),
    "podSelector deferral note present",
  );
});

test("port values are validated", () => {
  const src = VALID + `  egress:\n  - identifier: x\n    ipAddresses: [10.0.0.1/32]\n    ports: [{name: TCP-99999, protocol: TCP, port: 99999}]\n`;
  mustFail(src, "port");
});
