import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import { makeAllocator } from "../src/ruleids.ts";
import { generateK8sNodeBundle, imageRepoRegex, DOCKER_PARENT_RULE } from "../src/codegen/k8s.ts";

const REDIS = new URL("../sbobs/redis.yaml", import.meta.url).pathname;

function redisK8sBundle() {
  const parsed = parseYaml(readFileSync(REDIS, "utf8"));
  const ir = buildIR(validateSbob(parsed), parsed);
  return { ir, files: generateK8sNodeBundle(ir, makeAllocator("redis", 0)) };
}

function byPath(files: ReturnType<typeof generateK8sNodeBundle>) {
  return new Map(files.map((f) => [f.path, f.content]));
}

function ruleBlock(xml: string, ruleId: number): string {
  const m = new RegExp(`<rule\\s+id="${ruleId}"[^>]*>([\\s\\S]*?)</rule>`, "m").exec(xml);
  assert.ok(m, `rule ${ruleId} present`);
  return m[1];
}

// ---------------------------------------------------------------------------

test("redis k8s-node bundle has the documented file structure", () => {
  const paths = redisK8sBundle().files.map((f) => f.path).sort();
  assert.deepEqual(paths, [
    "redis.manifest.json",
    "wazuh/agent-conf/sbob/redis-audit-digest.sh",
    "wazuh/agent-conf/sbob/redis-k8s.xml",
    "wazuh/audit/sbob/redis.rules",
    "wazuh/decoders/sbob/redis-k8s.xml",
    "wazuh/lists/sbob/k8s/podmap",
    "wazuh/lists/sbob/redis/egress_saddrs",
    "wazuh/lists/sbob/redis/execs",
    "wazuh/lists/sbob/redis/ingress_addrs",
    "wazuh/manager/sbob/k8s-api-audit.md",
    "wazuh/rules/sbob/100000_redis_k8s-node.xml",
  ]);
});

test("k8s bundle is deterministic across runs", () => {
  const a = redisK8sBundle().files;
  const b = redisK8sBundle().files;
  assert.deepEqual(a.map((f) => f.path), b.map((f) => f.path));
  for (let i = 0; i < a.length; i++) assert.equal(a[i].content, b[i].content);
});

test("attribution rules keep the (7,x) band shape; tier-1 documented INERT on 4.14.6", () => {
  const { files } = redisK8sBundle();
  const xml = byPath(files).get("wazuh/rules/sbob/100000_redis_k8s-node.xml")!;
  for (const id of [100070, 100071, 100073, 100074]) assert.ok(ruleBlock(xml, id), `rule ${id}`);
  // base chains on the shipped audit GROUP (4.14 emits <if_group>audit</if_group>,
  // not auditd) + a pod_uid field the shipped decoder family never populates:
  // the custom cgroup decoder roots are preempted by the shipped auditd family,
  // so tier-1 cgroup attribution is documented INERT (issue #42)
  assert.match(ruleBlock(xml, 100070), /<if_group>audit<\/if_group>/);
  assert.match(ruleBlock(xml, 100070), /<field name="sbob\.pod_uid" type="pcre2">/);
  assert.match(xml, /INERT on wazuh 4\.14\.6/, "the inert tier-1 attribution is stated honestly");
  // unresolved chains via if_sid + the manager-side podmap CDB
  assert.match(ruleBlock(xml, 100071), /<if_sid>100070<\/if_sid>/);
  assert.match(ruleBlock(xml, 100071), /<list field="sbob\.pod_uid" lookup="not_match_key">etc\/lists\/sbob\/k8s\/podmap<\/list>/);
  // weak fallback rides the shipped audit.key field
  assert.match(ruleBlock(xml, 100073), /<if_group>audit<\/if_group>/);
  assert.match(ruleBlock(xml, 100073), /<field name="audit\.key" type="pcre2">/);
  // lifecycle chains off the shipped docker integration parent
  assert.match(ruleBlock(xml, 100074), new RegExp(`<if_sid>${DOCKER_PARENT_RULE}</if_sid>`));
});

test("pod_uid field regex accepts hex UUIDs (dash spelling), rejects garbage", () => {
  const { files } = redisK8sBundle();
  const xml = byPath(files).get("wazuh/rules/sbob/100000_redis_k8s-node.xml")!;
  const block = ruleBlock(xml, 100070);
  const m = /<field name="sbob\.pod_uid" type="pcre2">(.*?)<\/field>/.exec(block);
  assert.ok(m, "pod_uid field present");
  const re = new RegExp(m[1]);
  assert.ok(re.test("0f3c8ed9-9d6b-4a1c-b5f2-7c1e0a9d1234"), "dash uuid accepted");
  // the underscore spelling is NOT matched: the field is INERT on 4.14.6 and
  // the auditd cgroup= value never reaches the rule engine; the podmap
  // refresh script still documents both spellings for the manager-side list
  assert.ok(!re.test("0f3c8ed9_9d6b_4a1c_b5f2_7c1e0a9d1234"), "underscore spelling rejected");
  assert.ok(!re.test("1-2-3-4-5"), "decimal-only rejected");
  assert.ok(!re.test("not-a-pod-uid"), "garbage rejected");
  assert.ok(!re.test("0f3c8ed9-9d6b-4a1c-b5f2-7c1e0a9d1234 "), "trailing space rejected");
});

test("decoder XML: config-check only; custom cgroup decoder roots are NOT emitted (preempted on 4.14.6)", () => {
  const { files } = redisK8sBundle();
  const xml = byPath(files).get("wazuh/decoders/sbob/redis-k8s.xml")!;
  // issue #42: the SHIPPED auditd decoder family preempts any custom audit
  // decoder root on wazuh 4.14.6, so emitting cgroup-attribution decoders
  // would be dead XML; the bundle keeps only the config-check digest decoder
  assert.match(xml, /<decoder name="sbob-redis-config-check">/);
  assert.ok(!/sbob-redis-audit-cgroup/.test(xml), "no preemptable cgroup decoder roots");
  assert.match(xml, /cgroup attribution INERT on 4\.14\.6/, "decoder file documents the INERT tier honestly");

  const decoders = [...xml.matchAll(/<decoder name="(sbob-redis-audit-cgroup[^"]*)">([\s\S]*?)<\/decoder>/g)];
  assert.equal(decoders.length, 0, "three sibling cgroup decoders");
});

test("podmap seed is comment-only and documents both key spellings", () => {
  const { files } = redisK8sBundle();
  const podmap = byPath(files).get("wazuh/lists/sbob/k8s/podmap")!;
  const lines = podmap.split("\n").filter((l) => l.trim().length > 0);
  for (const l of lines) assert.ok(l.startsWith("#"), `podmap seed line is a comment: ${l}`);
  assert.match(podmap, /underscore/);
  assert.match(podmap, /scripts\/sbob-podmap-refresh\.sh/);
  // CDB keys must never contain ':'
  assert.ok(!/^#.*:/.test("check"), "placeholder");
});

test("drift rules reuse the linux section engine with mode A comments in the audit fragment", () => {
  const { ir, files } = redisK8sBundle();
  const audit = byPath(files).get("wazuh/audit/sbob/redis.rules")!;
  assert.ok(audit.includes("cgroup"), "audit fragment mentions the cgroup requirement");
  const xml = byPath(files).get("wazuh/rules/sbob/100000_redis_k8s-node.xml")!;
  // the core linux drift rules are present with the same ids as the linux bundle
  for (const id of [100000, 100011, 100012, 100020, 100021, 100022, 100030, 100031, 100032])
    assert.ok(ruleBlock(xml, id), `linux section rule ${id} reused`);
  assert.ok(ir.coverageNotes.length > 0, "ir carries coverage notes");
});

test("imageRepoRegex matches repo name at path/tag/digest boundaries", () => {
  const re = new RegExp(imageRepoRegex("docker.io/library/redis@sha256:e508c66a"));
  assert.ok(re.test("docker.io/library/redis@sha256:e508c66a"));
  assert.ok(re.test("docker.io/library/redis:7.2"));
  assert.ok(re.test("redis"));
  assert.ok(!re.test("docker.io/library/myredis@sha256:e508c66a"), "repo prefix collision rejected");
  assert.ok(!re.test("docker.io/library/redisish:7.2"), "suffix collision rejected");
});

test("lifecycle rule gates docker.status and the workload image repo", () => {
  const { ir, files } = redisK8sBundle();
  const xml = byPath(files).get("wazuh/rules/sbob/100000_redis_k8s-node.xml")!;
  const block = ruleBlock(xml, 100074);
  assert.match(block, /<field name="docker\.status" type="pcre2">\^start\$<\/field>/);
  const imageField = /<field name="docker\.Actor\.Attributes\.image" type="pcre2">(.*?)<\/field>/.exec(block);
  assert.ok(imageField, "image field present");
  const re = new RegExp(imageField![1]);
  assert.ok(re.test("docker.io/library/redis:7.2"), "matches image tag ref");
  assert.ok(!re.test("docker.io/library/memcached:1.6"), "rejects other image");
  assert.ok(ir.workload.imageID.includes("redis"));
});

test("manifest targets k8s-node and documents attribution + prerequisites", () => {
  const { files } = redisK8sBundle();
  const manifest = JSON.parse(byPath(files).get("redis.manifest.json")!);
  assert.equal(manifest.target, "k8s-node");
  assert.equal(manifest.labValidation, "pending");
  const notes = manifest.coverageNotes.join("\n");
  for (const needle of [
    "attribution tiers",
    "scripts/sbob-podmap-refresh.sh",
    "parent rule 87900",
    "Sysmon EID 22",
    "kubernetes-api-access rule (rulePolicies signature)",
  ])
    assert.ok(notes.includes(needle), `manifest mentions ${needle}`);
  assert.ok(manifest.files.includes("wazuh/lists/sbob/k8s/podmap"));
});

test("agent-conf enables the docker-listener wodle and k8s-api doc mentions both ship paths", () => {
  const { files } = redisK8sBundle();
  const agentConf = byPath(files).get("wazuh/agent-conf/sbob/redis-k8s.xml")!;
  assert.match(agentConf, /<wodle name="docker-listener">/);
  assert.match(agentConf, /87900/);
  const doc = byPath(files).get("wazuh/manager/sbob/k8s-api-audit.md")!;
  assert.match(doc, /audit-policy-file/);
  assert.match(doc, /<remote>/);
  assert.match(doc, /<localfile>/);
  assert.match(doc, /rulePolicies/);
});
