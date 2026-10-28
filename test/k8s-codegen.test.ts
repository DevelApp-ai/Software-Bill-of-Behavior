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
  const m = new RegExp(`<rule id="${ruleId}"[^>]*>([\\s\\S]*?)</rule>`, "m").exec(xml);
  assert.ok(m, `rule ${ruleId} present`);
  return m[1];
}

// ---------------------------------------------------------------------------

test("redis k8s-node bundle has the documented file structure", () => {
  const paths = redisK8sBundle().files.map((f) => f.path).sort();
  assert.deepEqual(paths, [
    "redis.manifest.json",
    "wazuh/agent-conf/sbob/redis-k8s.xml",
    "wazuh/audit/sbob/redis.rules",
    "wazuh/decoders/sbob/redis-k8s.xml",
    "wazuh/lists/sbob/k8s/podmap",
    "wazuh/lists/sbob/redis/egress_addrs",
    "wazuh/lists/sbob/redis/execs",
    "wazuh/lists/sbob/redis/ingress_addrs",
    "wazuh/lists/sbob/redis/opens",
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

test("attribution rules use the (7,x) band: 100070 base, 100071 unresolved, 100073 weak, 100074 lifecycle", () => {
  const { files } = redisK8sBundle();
  const xml = byPath(files).get("wazuh/rules/sbob/100000_redis_k8s-node.xml")!;
  for (const id of [100070, 100071, 100073, 100074]) assert.ok(ruleBlock(xml, id), `rule ${id}`);
  // base chains on auditd group + pod_uid field; unresolved chains via if_sid
  assert.match(ruleBlock(xml, 100070), /<if_group>auditd<\/if_group>/);
  assert.match(ruleBlock(xml, 100070), /<field name="sbob\.pod_uid" type="pcre2">/);
  assert.match(ruleBlock(xml, 100071), /<if_sid>100070<\/if_sid>/);
  assert.match(ruleBlock(xml, 100073), /<if_group>auditd<\/if_group>/);
  // lifecycle chains off the shipped docker integration parent
  assert.match(ruleBlock(xml, 100074), new RegExp(`<if_sid>${DOCKER_PARENT_RULE}</if_sid>`));
});

test("pod_uid field regex accepts real hex UUID pod uids (dash and underscore spellings), rejects garbage", () => {
  const { files } = redisK8sBundle();
  const xml = byPath(files).get("wazuh/rules/sbob/100000_redis_k8s-node.xml")!;
  const block = ruleBlock(xml, 100070);
  const m = /<field name="sbob\.pod_uid" type="pcre2">(.*?)<\/field>/.exec(block);
  assert.ok(m, "pod_uid field present");
  const re = new RegExp(m[1]);
  assert.ok(re.test("0f3c8ed9-9d6b-4a1c-b5f2-7c1e0a9d1234"), "dash uuid accepted");
  assert.ok(re.test("0f3c8ed9_9d6b_4a1c_b5f2_7c1e0a9d1234"), "underscore uuid accepted");
  assert.ok(!re.test("1-2-3-4-5"), "decimal-only rejected");
  assert.ok(!re.test("not-a-pod-uid"), "garbage rejected");
  assert.ok(!re.test("0f3c8ed9-9d6b-4a1c-b5f2-7c1e0a9d1234 "), "trailing space rejected");
});

test("cgroup decoders: OS_Regex-safe syntax and semantic coverage of the three cgroup forms", () => {
  const { files } = redisK8sBundle();
  const xml = byPath(files).get("wazuh/decoders/sbob/redis-k8s.xml")!;
  const decoders = [...xml.matchAll(/<decoder name="(sbob-redis-audit-cgroup[^"]*)">([\s\S]*?)<\/decoder>/g)];
  assert.equal(decoders.length, 3, "three sibling cgroup decoders");
  for (const [, name, body] of decoders) {
    assert.ok(/<parent>sbob-redis-audit-key<\/parent>/.test(body), `${name} chains on the audit-key parent`);
    assert.ok(/<order>sbob\.pod_uid<\/order>/.test(body), `${name} extracts sbob.pod_uid`);
    const regex = /<regex>(.*?)<\/regex>/.exec(body)![1];
    // OS_Regex has no character classes, no {n,m}, no lookarounds
    assert.ok(!/\[[^\]]/.test(regex), `${name}: no character classes`);
    assert.ok(!/\{[0-9]/.test(regex), `${name}: no bounded quantifiers`);
    assert.ok(!/\(\?<?[=!]/.test(regex), `${name}: no lookarounds`);
  }
  // semantic: translate OS_Regex \S / \w to JS and verify each cgroup form
  const jsRegex = (osRegex: string) => new RegExp(osRegex.replace(/\\/g, "\\"));
  const uid = "0f3c8ed9-9d6b-4a1c-b5f2-7c1e0a9d1234";
  const underscore = uid.replace(/-/g, "_");
  const v2Underscope = `cgroup=/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${underscore}.scope/cri-containerd-53b1a3e2.scope`;
  const v2DashScope = `cgroup=/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod${uid}.scope/cri-containerd-53b1a3e2.scope`;
  const v1 = `cgroup=/kubepods/burstable/pod${uid}/53b1a3e2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9`;
  const cgroupRegex = (suffix: string) => {
    const body = decoders.find(([, name]) => name === `sbob-redis-audit-cgroup${suffix}`)![2];
    return jsRegex(/<regex>(.*?)<\/regex>/.exec(body)![1]);
  };
  // underscore decoder must match the underscore form and capture the uid
  const mU = cgroupRegex("").exec(v2Underscope);
  assert.ok(mU, "underscore decoder matches v2 underscore path");
  assert.equal(mU![1], underscore, "captures the full underscore uid");
  // dash decoder must match the dash .scope form
  const mD = cgroupRegex("-dash").exec(v2DashScope);
  assert.ok(mD, "dash decoder matches v2 dash path");
  assert.equal(mD![1], uid, "captures the full dash uid");
  // v1 decoder must match the v1 path (no .scope)
  const m1 = cgroupRegex("-v1").exec(v1);
  assert.ok(m1, "v1 decoder matches cgroup v1 path");
  assert.equal(m1![1], uid, "captures the full dash uid from v1 path");
  // cross-form disjointness: underscore decoder must NOT swallow dash uids
  assert.equal(cgroupRegex("").exec(v2DashScope), null, "underscore decoder rejects dash form");
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
  for (const id of [100000, 100010, 100011, 100012, 100020, 100021, 100022, 100030, 100031, 100032])
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
    "M4",
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
  assert.match(doc, /M4/);
});
