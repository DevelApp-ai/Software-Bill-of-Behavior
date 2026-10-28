import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseYaml } from "../src/yaml.ts";
import { validateSbob } from "../src/schema.ts";
import { buildIR } from "../src/ir.ts";
import {
  parseEventStream,
  profileEvents,
  classifyFrequency,
  DEFAULT_WINDOW_DAYS,
  STEADY_CUTOFF_DEFAULT,
  SPORADIC_CUTOFF_DEFAULT,
  CADENCE_TOLERANCE_DEFAULT,
  type ProfileEvent,
  type DispositionFile,
  type EntryProvenance,
} from "../src/profiler.ts";


const FIX = "./profiler-fixtures/";
const IMAGE = "docker.io/legacy/cache@sha256:c0ffee00000000000000000000000000000000000000000000000000000000ff";

function fixtureText(name: string): string {
  return readFileSync(new URL(FIX + name, import.meta.url), "utf8");
}

function baseOpts(overrides: Partial<Parameters<typeof profileEvents>[1]> = {}) {
  return {
    workload: "legacy-cache",
    imageID: IMAGE,
    k8sNamespace: "legacy-tier",
    windowDays: 30,
    incidents: [],
    ...overrides,
  };
}

function fixtureProfile(overrides: Partial<Parameters<typeof profileEvents>[1]> = {}) {
  const stream = parseEventStream(fixtureText("events.jsonl"));
  const dispositions = JSON.parse(fixtureText("dispositions.json")) as DispositionFile;
  const baseline = validateSbob(parseYaml(fixtureText("baseline.yaml")));
  return profileEvents(stream, baseOpts({ dispositions, baseline, ...overrides }));
}

function entry(result: { entries: EntryProvenance[] }, key: string): EntryProvenance {
  const e = result.entries.find((x) => x.section + ":" + x.key === key);
  assert.ok(e !== undefined, `expected entry ${key} in provenance`);
  return e;
}

function ev(partial: Partial<ProfileEvent> & Pick<ProfileEvent, "ts" | "kind">): ProfileEvent {
  return { workload: "legacy-cache", source: "auditd", sbob: {}, ...partial };
}

// ---------------------------------------------------------------------------
// event stream ingestion
// ---------------------------------------------------------------------------

test("malformed event lines are rejected loudly with line numbers", () => {
  assert.throws(() => parseEventStream("not json\n"), /ERR_PROFILE_EVENT.*line 1/);
  assert.throws(
    () => parseEventStream('{"ts":"2026-09-01T00:00:00Z","workload":"w","source":"auditd","kind":"exec","sbob":{}}\n'),
    /ERR_PROFILE_EVENT.*sbob\.exe/,
  );
  assert.throws(
    () => parseEventStream('{"ts":"yesterday","workload":"w","source":"auditd","kind":"cap","sbob":{"cap":"CAP_SYS_ADMIN"}}\n'),
    /ERR_PROFILE_EVENT.*ts must be an ISO 8601 UTC/,
  );
  // raw logs are rejected by construction: no normalized sbob.* payload
  assert.throws(
    () => parseEventStream('{"ts":"2026-09-01T00:00:00Z","workload":"w","source":"auditd","kind":"connect","sbob":{"path":"/etc/passwd"}}\n'),
    /ERR_PROFILE_EVENT.*connect needs sbob\.dst_ip or sbob\.dns/,
  );
});

test("the stream is scoped to the requested workload; other workloads are excluded", () => {
  const result = fixtureProfile();
  assert.ok(result.entries.every((e) => e.sources.length > 0));
  const stream = parseEventStream(fixtureText("events.jsonl"));
  assert.ok(stream.some((e) => e.workload === "other-svc")); // the stream contains it…
  assert.throws(
    () => profileEvents(stream, baseOpts({ workload: "ghost" })),
    /ERR_PROFILE_SCOPE.*ghost/,
  );
  const scoped = profileEvents(stream, baseOpts({ workload: "other-svc", windowDays: 30 }));
  assert.equal(scoped.entries.length, 2); // …and profiling it yields only its own events
});

// ---------------------------------------------------------------------------
// frequency classification (chapter §3 taxonomy, calibratable defaults)
// ---------------------------------------------------------------------------

const TH = { steadyCutoff: STEADY_CUTOFF_DEFAULT, sporadicCutoff: SPORADIC_CUTOFF_DEFAULT, cadenceTolerance: CADENCE_TOLERANCE_DEFAULT };

test("one-off: a single observation", () => {
  const c = classifyFrequency(1, ["2026-09-03"], 30, TH);
  assert.equal(c.class, "one-off");
});

test("sporadic below the 5% day cutoff even when the few events cluster on one day", () => {
  const c = classifyFrequency(3, ["2026-09-09"], 30, TH);
  assert.equal(c.class, "sporadic");
  assert.ok(c.dayRatio < 0.05);
});

test("periodic: regular cadence carries its period; a period longer than daily", () => {
  const c = classifyFrequency(5, ["2026-09-01", "2026-09-08", "2026-09-15", "2026-09-22", "2026-09-29"], 30, TH);
  assert.equal(c.class, "periodic");
  assert.equal(c.periodDays, 7);
});

test("every-day recurrence is steady, not periodic", () => {
  const days = Array.from({ length: 30 }, (_, i) => `2026-09-${String(i + 1).padStart(2, "0")}`);
  const c = classifyFrequency(30, days, 30, TH);
  assert.equal(c.class, "steady");
});

test("irregular gaps stay sporadic even above the cutoff", () => {
  const c = classifyFrequency(3, ["2026-09-03", "2026-09-11", "2026-09-27"], 30, TH);
  assert.equal(c.class, "sporadic");
});

test("classification thresholds are calibratable", () => {
  // gaps 4 and 7 around a 5.5-day median: inside a ±0.5 band, outside ±0.25
  const days = ["2026-09-01", "2026-09-05", "2026-09-12"];
  assert.equal(classifyFrequency(3, days, 30, { ...TH, cadenceTolerance: 0.5 }).class, "periodic");
  assert.equal(classifyFrequency(3, days, 30, TH).class, "sporadic");
});

// ---------------------------------------------------------------------------
// fixture end-to-end: classes, provenance, dispositions, inclusion
// ---------------------------------------------------------------------------

test("fixture covers every frequency class with the right dispositions", () => {
  const result = fixtureProfile();
  assert.equal(result.status, "candidate");
  const byClass = new Set(result.entries.map((e) => e.class));
  for (const c of ["steady", "periodic", "sporadic", "one-off"]) {
    assert.ok(byClass.has(c as never), `fixture must exercise class ${c}`);
  }
  assert.equal(entry(result, "execs:/usr/bin/legacy-cache").class, "steady");
  assert.equal(entry(result, "opens:/var/backups/legacy-cache.bak").class, "periodic");
  assert.equal(entry(result, "opens:/var/backups/legacy-cache.bak").periodDays, 7);
  assert.equal(entry(result, "execs:/bin/sh").class, "sporadic");
  assert.equal(entry(result, "opens:/tmp/.cache-stamp").class, "sporadic");
  assert.equal(entry(result, "execs:/usr/bin/cache-migrate").class, "one-off");
  assert.equal(entry(result, "egress:ip:203.0.113.9").class, "one-off");
});

test("provenance: source, counts, first/last seen and frequency class on every entry", () => {
  const result = fixtureProfile();
  for (const e of result.entries) {
    assert.ok(e.sources.length > 0, "entry carries its sources");
    assert.ok(e.count >= 1, "entry carries a count");
    assert.match(e.firstSeen, /^2026-09-/);
    assert.match(e.lastSeen, /^2026-09-/);
    assert.ok(e.lastSeen >= e.firstSeen);
    // mandatory disposition: every entry has one — no "no decision" pipeline state
    assert.ok(["declare", "hold", "exempt-with-expiry", "investigate"].includes(e.disposition));
  }
});

test("no unexplained entry enters the contract as a plain allow", () => {
  // without reviewer dispositions, one-off/sporadic entries are held or investigated
  const result = fixtureProfile({ dispositions: undefined });
  assert.ok(!result.entries.some((e) => e.included && (e.class === "one-off" || e.class === "sporadic")));
  const candidate = result.candidate!;
  assert.ok(!candidate.spec.execs?.some((e) => e.path === "/usr/bin/cache-migrate"));
  assert.ok(!candidate.spec.opens?.some((e) => e.path === "/tmp/.cache-stamp"));

  // with dispositions, a declare override requires a written reason…
  const stream = parseEventStream(fixtureText("events.jsonl"));
  assert.throws(
    () => profileEvents(stream, baseOpts({
      dispositions: { entries: { "execs:/usr/bin/cache-migrate": { disposition: "declare" } } },
    })),
    /ERR_PROFILE_DISPOSITION.*requires a written reason/,
  );
  // …and an unknown key is a loud failure, not a silent no-op
  assert.throws(
    () => profileEvents(stream, baseOpts({
      dispositions: { entries: { "execs:/does/not/exist": { disposition: "hold", reason: "x" } } },
    })),
    /ERR_PROFILE_DISPOSITION.*unknown entry/,
  );
  // exempt-with-expiry requires a future expiry date
  assert.throws(
    () => profileEvents(stream, baseOpts({
      dispositions: { entries: { "opens:/tmp/.cache-stamp": { disposition: "exempt-with-expiry", reason: "x", expiry: "2026-09-15" } } },
    })),
    /ERR_PROFILE_DISPOSITION.*expiry/,
  );
});

test("reviewer dispositions move entries between the review queue and the contract", () => {
  const result = fixtureProfile();
  const candidate = result.candidate!;
  // reviewer declared the one-off migration tool with a written reason
  assert.ok(candidate.spec.execs?.some((e) => e.path === "/usr/bin/cache-migrate"));
  assert.equal(entry(result, "execs:/usr/bin/cache-migrate").dispositionOrigin, "reviewer");
  assert.match(entry(result, "execs:/usr/bin/cache-migrate").reason!, /INC-77/);
  // reviewer-held /bin/sh and the investigated external IP never enter the candidate
  assert.ok(!candidate.spec.execs?.some((e) => e.path === "/bin/sh"));
  assert.ok(!candidate.spec.egress?.some((e) => e.ipAddresses?.includes("203.0.113.9")));
  assert.equal(entry(result, "egress:ip:203.0.113.9").disposition, "investigate");
  // exempt-with-expiry is included and carries its expiry in the sidecar
  assert.ok(candidate.spec.opens?.some((e) => e.path === "/tmp/.cache-stamp"));
  assert.equal(entry(result, "opens:/tmp/.cache-stamp").expiry, "2026-12-31");
});

test("fidelity ladder: an entry never seen by a confirming source is unverified and excluded", () => {
  const result = fixtureProfile();
  const vendor = entry(result, "egress:dns:telemetry-vendor.io");
  assert.equal(vendor.confirmed, false);
  assert.deepEqual(vendor.sources, ["flow"]); // flow logs are partial, never confirming
  assert.equal(vendor.included, false);
  assert.ok(!result.candidate!.spec.egress?.some((e) => e.dnsNames?.includes("telemetry-vendor.io")));
  // annotations from non-confirming sources land in the review, never the contract
  assert.equal(result.annotations.length, 3);
  assert.ok(result.annotations.every((a) => a.source === "applog" || a.source === "metric"));
});

test("section-specific provenance: args variance and flag unions", () => {
  const result = fixtureProfile();
  assert.match(entry(result, "execs:/usr/bin/legacy-cache").detail!, /args stable/);
  assert.match(entry(result, "execs:/usr/bin/legacy-cache-check").detail!, /args vary/);
  assert.ok(!result.candidate!.spec.execs?.some((e) => e.path === "/usr/bin/legacy-cache-check"));
  assert.match(entry(result, "opens:/var/lib/legacy-cache/data.db").detail!, /O_RDWR\|O_CREAT/);
  assert.deepEqual(
    result.candidate!.spec.opens?.find((e) => e.path === "/var/lib/legacy-cache/data.db")?.flags,
    ["O_RDWR", "O_CREAT"],
  );
  // flagless open events default to read-only, noted in provenance
  assert.match(entry(result, "opens:/tmp/.cache-stamp").detail!, /no normalized flags/);
});

test("window honesty: a periodic entry whose period is not fully observed is held", () => {
  const stream: ProfileEvent[] = [];
  const mk = (day: string) => stream.push(ev({
    ts: `${day}T01:00:00Z`, kind: "open",
    sbob: { path: "/var/backups/monthly.bak", flags: ["O_WRONLY"] },
  }));
  mk("2026-09-02"); mk("2026-09-18"); mk("2026-10-04"); // 16-day cadence: 30 < 2*16 → held
  const result = profileEvents(stream, baseOpts({ windowDays: 30 }));
  const monthly = result.entries.find((e) => e.key === "/var/backups/monthly.bak")!;
  assert.equal(monthly.class, "periodic");
  assert.equal(monthly.disposition, "hold");
  assert.match(monthly.reason!, /not fully observed/);
  assert.equal(monthly.included, false);
});

// ---------------------------------------------------------------------------
// taint (chapter §4): open incident labels quarantine the workload
// ---------------------------------------------------------------------------

test("taint: a workload with an open incident is quarantined from the review queue", () => {
  const result = fixtureProfile({ incidents: ["legacy-cache"] });
  assert.equal(result.status, "quarantined");
  assert.equal(result.quarantined, true);
  assert.equal(result.candidate, undefined); // no candidate is emitted
  assert.match(result.reviewReport, /Quarantined — open incident/);
  assert.match(result.reviewReport, /crime-scene photo/);
});

test("untainted sibling workloads are unaffected by another workload's incident label", () => {
  const result = fixtureProfile({ incidents: ["some-other-workload"] });
  assert.equal(result.status, "candidate");
});

// ---------------------------------------------------------------------------
// the emitted artifact is a real SBoB (by construction verifiable)
// ---------------------------------------------------------------------------

test("candidate round-trips through the repo's own parser, schema and IR", () => {
  const result = fixtureProfile();
  const doc = validateSbob(parseYaml(result.candidateYaml!));
  assert.equal(doc.metadata.name, "legacy-cache");
  assert.equal(doc.spec.execs?.length, 2);
  const ir = buildIR(doc, parseYaml(result.candidateYaml!));
  assert.equal(ir.sections.execs?.exact.length, 2);
  assert.equal(ir.sections.opens?.exact.length, 4);
  // the drift detectors will enforce exactly what the window confirmed
  assert.deepEqual(ir.sections.execs?.exact.sort(), ["/usr/bin/cache-migrate", "/usr/bin/legacy-cache"]);
});

test("candidate metadata records the window (checklist §8: window length written on the candidate)", () => {
  const result = fixtureProfile();
  const ann = result.candidate!.metadata.annotations!;
  assert.equal(ann["sbob.develapp.io/derived"], "sbobctl-profile-v1");
  assert.equal(ann["sbob.develapp.io/window-days"], "30");
  assert.equal(ann["sbob.develapp.io/window-from"], "2026-09-01T02:30:00Z");
  assert.equal(ann["sbob.develapp.io/window-to"], "2026-09-30T06:00:05Z");
  assert.equal(ann["sbob.develapp.io/provenance"], "legacy-cache.provenance.json");
});

// ---------------------------------------------------------------------------
// M8 gate integration: the reviewed delta flows through the diff gate
// ---------------------------------------------------------------------------

test("baseline → candidate delta flows through the M8 diff gate", () => {
  const result = fixtureProfile();
  const gate = result.gate!;
  assert.equal(gate.verdict, "mandatory"); // a derived capability is a +5 class
  assert.equal(gate.immediateReview, true);
  assert.ok(gate.delta.some((d) => d.section === "capabilities" && d.entry === "CAP_NET_BIND_SERVICE" && d.weight === 5));
  assert.match(result.reviewReport, /Release-gate delta/);
  // without a baseline there is no gate result
  assert.equal(fixtureProfile({ baseline: undefined }).gate, undefined);
});

test("workload mismatch between baseline and stream is rejected by the gate", () => {
  const stream = parseEventStream(fixtureText("events.jsonl"));
  const baseline = validateSbob(parseYaml(
    fixtureText("baseline.yaml").replace("name: legacy-cache", "name: some-other-workload"),
  ));
  assert.throws(
    () => profileEvents(stream, baseOpts({ baseline })),
    /ERR_WORKLOAD_MISMATCH/,
  );
});

// ---------------------------------------------------------------------------
// determinism + goldens (org decision #26)
// ---------------------------------------------------------------------------

test("deterministic output: repeated profiles are byte-identical", () => {
  const a = fixtureProfile();
  const b = fixtureProfile();
  assert.equal(a.candidateYaml, b.candidateYaml);
  assert.equal(a.provenanceJson, b.provenanceJson);
  assert.equal(a.reviewReport, b.reviewReport);
  // event order in the stream must not matter either
  const lines = fixtureText("events.jsonl").split("\n").filter((l) => l.trim() !== "" && !l.startsWith("#"));
  const shuffled = parseEventStream([...lines].reverse().join("\n"));
  const c = profileEvents(shuffled, baseOpts({
    dispositions: JSON.parse(fixtureText("dispositions.json")),
    baseline: validateSbob(parseYaml(fixtureText("baseline.yaml"))),
  }));
  assert.equal(c.candidateYaml, a.candidateYaml);
  assert.equal(c.provenanceJson, a.provenanceJson);
});

test("golden: candidate YAML and provenance JSON match the committed fixtures byte-for-byte", () => {
  const result = fixtureProfile();
  assert.equal(result.candidateYaml, fixtureText("expected-candidate.yaml"));
  assert.equal(result.provenanceJson, fixtureText("expected-provenance.json"));
});

test("nothing-declarable: every entry held or unverified → no candidate, loud status", () => {
  const stream: ProfileEvent[] = [
    ev({ ts: "2026-09-04T00:00:00Z", kind: "exec", sbob: { exe: "/usr/bin/mystery" } }),
    ev({ ts: "2026-09-04T00:00:01Z", kind: "connect", source: "flow", sbob: { dns: "only-flow.example.com", dst_port: 443 } }),
  ];
  const result = profileEvents(stream, baseOpts());
  assert.equal(result.status, "nothing-declarable");
  assert.equal(result.candidate, undefined);
  assert.match(result.reviewReport, /Nothing declarable/);
});
