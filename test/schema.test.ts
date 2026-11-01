import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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

// ---- imageID extension: package purls (pkg:nuget / pkg:choco, version-pinned) ----

const PKG_BOUND = VALID.replace(
  "imageID: docker.io/library/redis@sha256:e508c66a",
  "imageID: pkg:nuget/develapp.minotaur@1.5.21",
).replace(
  "  name: redis\n",
  "  name: redis\n  annotations:\n    develapp.io/binding: package-purl\n",
);

test("package-purl imageID with binding annotation validates (nuget and choco)", () => {
  const doc = validateSbob(parseYaml(PKG_BOUND));
  assert.equal(doc.spec.imageID, "pkg:nuget/develapp.minotaur@1.5.21");
  const choco = PKG_BOUND.replace(
    "pkg:nuget/develapp.minotaur@1.5.21",
    "pkg:choco/develapp-minotaur@1.5.21",
  );
  assert.equal(validateSbob(parseYaml(choco)).spec.imageID, "pkg:choco/develapp-minotaur@1.5.21");
});

test("full package-purl ecosystem set validates (SBOB-Forge extraction matrix)", () => {
  const cases = [
    "pkg:nuget/develapp.minotaur@1.5.21",
    "pkg:choco/develapp-minotaur@1.5.21",
    "pkg:generic/example-bash-core@1.0.0",
    "pkg:generic/example/c-core@1.0.0",
    "pkg:golang/example.com/go-core@1.0.0",
    "pkg:maven/com.example/example-core@1.0.0",
    "pkg:npm/js-core@1.0.0",
    "pkg:npm/@develapp/js-core@1.0.0",
    "pkg:composer/example/php-core@1.0.0",
    "pkg:pypi/example-py-core@1.0.0",
  ];
  for (const purl of cases) {
    const doc = validateSbob(parseYaml(PKG_BOUND.replace("pkg:nuget/develapp.minotaur@1.5.21", purl)));
    assert.equal(doc.spec.imageID, purl, `purl must validate: ${purl}`);
  }
});

test("dogfood package-bound fixture validates (develapp-minotaur, issue #33)", () => {
  const raw = readFileSync(
    new URL("./package-fixtures/develapp-minotaur.linux.sbob.yaml", import.meta.url),
    "utf8",
  );
  const doc = validateSbob(parseYaml(raw));
  assert.equal(doc.metadata.annotations?.["develapp.io/binding"], "package-purl");
  assert.equal(doc.spec.opens?.length, 3);
});

test("malformed package purls are rejected with field paths", () => {
  // unpinned version
  mustFail(
    PKG_BOUND.replace("pkg:nuget/develapp.minotaur@1.5.21", "pkg:nuget/develapp.minotaur"),
    "spec.imageID",
  );
  // unsupported purl type
  mustFail(
    PKG_BOUND.replace("pkg:nuget/develapp.minotaur@1.5.21", "pkg:rpm/left-pad@1.0.0"),
    "spec.imageID",
  );
  // empty namespace segment in a multi-segment path
  mustFail(
    PKG_BOUND.replace("pkg:nuget/develapp.minotaur@1.5.21", "pkg:maven//example-core@1.0.0"),
    "spec.imageID",
  );
  // empty name
  mustFail(PKG_BOUND.replace("pkg:nuget/develapp.minotaur@1.5.21", "pkg:nuget/@1.0.0"), "spec.imageID");
  // empty version
  mustFail(PKG_BOUND.replace("pkg:nuget/develapp.minotaur@1.5.21", "pkg:nuget/develapp.minotaur@"), "spec.imageID");
  // whitespace is not a purl character
  mustFail(
    PKG_BOUND.replace("pkg:nuget/develapp.minotaur@1.5.21", "pkg:nuget/devel app@1.5.21"),
    "spec.imageID",
  );
  // scheme only
  mustFail(PKG_BOUND.replace("pkg:nuget/develapp.minotaur@1.5.21", "pkg:"), "spec.imageID");
});

test("package purl without package-purl binding annotation is rejected", () => {
  const noBinding = PKG_BOUND.replace("    develapp.io/binding: package-purl\n", "");
  mustFail(noBinding, "spec.imageID");
  const wrongBinding = PKG_BOUND.replace(
    "develapp.io/binding: package-purl",
    "develapp.io/binding: image-digest",
  );
  mustFail(wrongBinding, "spec.imageID");
});
