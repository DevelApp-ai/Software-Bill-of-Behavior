/**
 * Windows codegen (TDS sections 4.3, 6.1, 6.2, 7.2, 7.3.4, 8.2) — Sysmon targets.
 *
 * Emits, per workload:
 *   - wazuh/agent-conf/sbob/<name>.xml      eventchannel localfile fragment (TDS 4.3)
 *   - wazuh/lists/sbob/<name>/egress_addrs  CDB address allowlists (shared design
 *   - wazuh/lists/sbob/<name>/ingress_addrs   with the Linux bundle; manager-side)
 *   - wazuh/rules/sbob/<base>_<name>_windows.xml   base + drift + escalation rules
 *   - <name>.manifest.json                   workload bundle manifest + coverage notes
 *
 * Engine facts this codegen depends on (verified against wazuh/src/analysisd
 * and the shipped ruleset 0595-win-sysmon_rules.xml):
 *   - The shipped eventchannel decoder family normalizes Sysmon events to
 *     win.system.* (Event.System) and win.eventdata.* (EventData) — no custom
 *     decoders are needed, so none are emitted (TDS 3.2: custom decoders only).
 *   - The shipped ruleset routes Sysmon events under rule 61600
 *     (if_sid 60004, severityValue INFORMATION). Our rules chain off 61600 and
 *     carry their own win.system.eventID field conditions; the shipped ruleset
 *     covers EIDs 1-15 only, so EID 22 (DNS query) entries are self-defined.
 *   - <field> conditions are compiled with OS_Regex by default; PCRE2
 *     constructs (character classes, lookaheads) require type="pcre2"
 *     (Wazuh >= 4.4).
 *
 * ID layout (TDS 6.1, Windows variant digits 5-9):
 *   - Windows needs TWO drift rules for execs (image + args) and for egress
 *     (ip/port + DNS-name), but each section budget allows one rule per kind.
 *     The base section (code 0) digits 6 and 7 therefore carry the secondary
 *     drift rules: (0,6) execs args drift (TDS 7.3.4), (0,7) egress DNS-name
 *     drift (EID 22). Documented as an amendment in TDS 6.1.
 */
import { negatedAlternation, positiveAlternation } from "../regexp.ts";
import { compileDnsPattern, escapeRegExp, portAlternation } from "../wildcards.ts";
import type { IdAllocator } from "../ruleids.ts";
import type { ExecCompiled, IR } from "../types.ts";
import type { BundleFile } from "./linux.ts";
import { signatureCoverageNotes } from "./signatures.ts";
import { bundleVersion } from "./opshealth.ts";
import { buildCoverageMatrix, assertCoverageComplete } from "../coverage.ts";
import type { XmlRule } from "./xml.ts";
import { renderRule, xmlFileHeader } from "./xml.ts";

const LAB_NOTE_PENDING =
  "LAB VALIDATION PENDING (M2 exit criteria): replay scripts/logtest-corpus.sh corpus on a lab Windows host with Sysmon and a live wazuh manager";

/**
 * Banner line for generated XML headers (M2 exit criteria): LAB VALIDATED with
 * the committed evidence (docs/lab-validation.yaml, stamped via the
 * --lab-validation transpile flag) or the pending instruction.
 */
function labNote(alloc: IdAllocator): string {
  const lab = alloc.lab;
  return lab
    ? `LAB VALIDATED (${lab.date}, ${lab.manager}): evidence ${lab.evidence}`
    : LAB_NOTE_PENDING;
}

/** The shipped Sysmon eventchannel parent rule (0595-win-sysmon_rules.xml). */
export const SYSMON_PARENT_RULE = 61600;

export function generateWindowsBundle(ir: IR, alloc: IdAllocator): BundleFile[] {
  const name = ir.workload.name;
  const files: BundleFile[] = [];
  const s = ir.sections;

  // --------------------------------------------------------------------------
  // 1. agent configuration fragment (TDS 4.3)
  // --------------------------------------------------------------------------
  {
    const xml = [
      xmlFileHeader(
        `sbobctl generated agent configuration fragment — merge into the agent group's centralized agent.conf (or the agent's ossec.conf)`,
        name,
        "Sysmon (Sysinternals) with a curated config trimmed to EIDs 1/3/10/11/22 is a deployment prerequisite (TDS 4.3); verify with the ops runbook inventory check (M5)",
      ),
      "",
      "<localfile>",
      "  <location>Microsoft-Windows-Sysmon/Operational</location>",
      "  <log_format>eventchannel</log_format>",
      "  <query>Event/System[EventID=1 or EventID=3 or EventID=10 or EventID=11 or EventID=22]</query>",
      "</localfile>",
      "",
    ].join("\n");
    files.push({ path: `wazuh/agent-conf/sbob/${name}.xml`, content: xml });
  }

  // --------------------------------------------------------------------------
  // 2. CDB address allowlists (manager-side; identical design to the Linux
  //    bundle — TDS 6.4). Windows drive-letter paths cannot be CDB keys
  //    (the ':' is the key/value separator), so execs/opens allowlists are
  //    PCRE2 alternations in the rules XML on Windows instead of CDB lists.
  // --------------------------------------------------------------------------
  for (const dir of ["egress", "ingress"] as const) {
    const sec = s[dir];
    if (!sec || sec.exact.length === 0) continue;
    files.push({
      path: `wazuh/lists/sbob/${name}/${dir}_addrs`,
      content:
        `# ${dir} CDB address list: key=ip/mask (canonicalized), value=identifier; shared with the linux bundle (TDS 6.4)\n` +
        sec.entries
          .flatMap((e) => e.addrEntries.map((a) => `${a}:${e.source.identifier ?? "unnamed"}`))
          .join("\n") +
        "\n",
    });
  }

  // --------------------------------------------------------------------------
  // 3. rules XML
  // --------------------------------------------------------------------------
  {
    const rules: XmlRule[] = [];
    const groups = (extra: string[]) => ["sbob", name, ...extra];
    const workload = `${name} SBoB v${ir.workload.sbobVersion}`;

    // global base (0,5) — entry point into the workload's Windows rules
    const globalBaseId = alloc.windows("base", "base");
    rules.push({
      id: globalBaseId,
      level: 0,
      ifSid: SYSMON_PARENT_RULE,
      description: `SBoB base: Sysmon eventchannel event in sbob scope (${name})`,
      groups: [groups(["sbob-win"])],
      comment: `requires the shipped ruleset entry rule ${SYSMON_PARENT_RULE} (0595-win-sysmon_rules.xml) to be loaded by the manager`,
    });

    // execs (Sysmon EID 1) ------------------------------------------------------
    if (s.execs !== undefined && s.execs.entries.length > 0) {
      const baseId = alloc.windows("execs", "base");
      const driftId = alloc.windows("execs", "drift");
      const escId = alloc.windows("execs", "escalation");
      rules.push({
        id: baseId,
        level: 0,
        ifSid: globalBaseId,
        fields: [{ name: "win.system.eventID", regex: "^1$" }],
        description: `SBoB base: Sysmon EID 1 process create on sbob scope (${name})`,
        groups: [groups(["sbob-exec", "sysmon_event1"])],
      });
      // image drift: allowlist from the identical IR (TDS 7.2). Patterns are
      // compiled as declared — a Windows deployment must declare Windows-form
      // execs[] paths (e.g. C:\\... or \\Device\\HarddiskVolume...), POSIX-form
      // entries cannot match Sysmon's Image field.
      const allPaths = s.execs.entries.map((e) => e.pathRegex);
      const neg = negatedAlternation(allPaths);
      const drift: XmlRule = {
        id: driftId,
        level: 9,
        ifSid: baseId,
        fields: [],
        description: `SBoB drift: process image $(win.eventdata.image) not declared in execs[] of ${workload} (image ${ir.workload.imageID})`,
        groups: [groups(["sbob-drift", "process-execution"])],
        mitre: ["T1059"],
        options: ["no_full_log"],
        comment: "allowlist compiled from the identical IR (TDS 7.2); PCRE2 alternation instead of CDB (drive-letter ':' is the CDB key separator)",
      };
      if (neg !== null) drift.fields!.push({ name: "win.eventdata.image", regex: neg });
      rules.push(drift);
      rules.push({
        id: escId,
        level: 12,
        ifSid: driftId,
        frequency: 8,
        timeframe: 120,
        description: `SBoB sustained drift: repeated undeclared process execution on ${name} (8 in 120s)`,
        groups: [groups(["sbob-drift", "process-execution", "sustained"])],
      });

      // args drift (0,6) — TDS 7.3.4 token-aware command-line heuristic.
      // Fires when an allowlisted image is launched with an undeclared
      // argument vector. Declared-partial: quoted tokens and whitespace
      // variants are tolerated; argv[0] must match as typed.
      const withArgs = s.execs.entries.filter((e) => e.argsRegex !== null);
      if (withArgs.length > 0) {
        const argsDriftId = alloc.windows("base", "drift");
        const imageAlt = positiveAlternation(withArgs.map((e) => e.pathRegex));
        const cmdlineAlt = negatedAlternation(withArgs.map(commandLineRegex));
        if (imageAlt !== null && cmdlineAlt !== null) {
          rules.push({
            id: argsDriftId,
            level: 9,
            ifSid: baseId,
            fields: [
              { name: "win.eventdata.image", regex: imageAlt },
              { name: "win.eventdata.commandLine", regex: cmdlineAlt },
            ],
            description: `SBoB drift: declared process $(win.eventdata.image) launched with arguments not declared in execs[].args of ${workload}`,
            groups: [groups(["sbob-drift", "process-execution", "args-drift"])],
            mitre: ["T1059"],
            options: ["no_full_log"],
            comment:
              "token-aware command-line heuristic (TDS 7.3.4): Sysmon EID 1 carries CommandLine (one string), not argv; " +
              "quoting variants are tolerated, argv[0] is anchored at string start — flagged partial in the coverage manifest",
          });
        }
      }
    } else if (s.execs === undefined) {
      rules.push(sectionAbsentRule(globalBaseId, ir, alloc, "execs", "sysmon_event1", "^1$", "process-execution"));
    }

    // opens (Sysmon EID 11) ----------------------------------------------------
    if (s.opens !== undefined && s.opens.entries.length > 0) {
      const baseId = alloc.windows("opens", "base");
      const driftId = alloc.windows("opens", "drift");
      const escId = alloc.windows("opens", "escalation");
      rules.push({
        id: baseId,
        level: 0,
        ifSid: globalBaseId,
        fields: [{ name: "win.system.eventID", regex: "^11$" }],
        description: `SBoB base: Sysmon EID 11 file create observed on sbob scope (${name})`,
        groups: [groups(["sbob-open", "sysmon_event_11"])],
      });
      const allPaths = s.opens.entries.map((e) => e.pathRegex);
      const neg = negatedAlternation(allPaths);
      const drift: XmlRule = {
        id: driftId,
        level: 9,
        ifSid: baseId,
        fields: [],
        description: `SBoB drift: file target $(win.eventdata.targetFilename) not declared in opens[] of ${workload}`,
        groups: [groups(["sbob-drift", "file-access"])],
        mitre: ["T1005"],
        options: ["no_full_log"],
        comment:
          "path-level drift from EID 11 targetFilename; opens[].flags are NOT evaluated on Windows — Sysmon reports CreateFile-style events only (coverage partial, TDS 8.2)",
      };
      if (neg !== null) drift.fields!.push({ name: "win.eventdata.targetFilename", regex: neg });
      rules.push(drift);
      rules.push({
        id: escId,
        level: 12,
        ifSid: driftId,
        frequency: 8,
        timeframe: 120,
        description: `SBoB sustained drift: repeated undeclared file creates on ${name} (8 in 120s)`,
        groups: [groups(["sbob-drift", "file-access", "sustained"])],
      });
    } else if (s.opens === undefined) {
      rules.push(sectionAbsentRule(globalBaseId, ir, alloc, "opens", "sysmon_event_11", "^11$", "file-access"));
    }

    // egress (Sysmon EID 3 outbound; EID 22 DNS) ---------------------------------
    if (s.egress !== undefined && s.egress.entries.length > 0) {
      const baseId = alloc.windows("egress", "base");
      const driftId = alloc.windows("egress", "drift");
      const escId = alloc.windows("egress", "escalation");
      const anyIp = s.egress.entries.some((e) => e.anyIp);
      rules.push({
        id: baseId,
        level: 0,
        ifSid: globalBaseId,
        fields: [
          { name: "win.system.eventID", regex: "^3$" },
          { name: "win.eventdata.initiated", regex: "^[Tt]rue$" },
        ],
        description: `SBoB base: Sysmon EID 3 outbound connection observed (${name})`,
        groups: [groups(["sbob-connect", "sysmon_event3"])],
        comment: "Initiated=true scopes the rule to outbound connections; inbound listeners are host-firewall territory (TDS 8.3)",
      });
      const allAddrs = s.egress.entries.flatMap((e) => e.addrEntries);
      const ports = s.egress.entries.flatMap((e) => e.ports);
      const portAlt = portAlternation(ports);
      const drift: XmlRule = {
        id: driftId,
        level: 9,
        ifSid: baseId,
        fields: [],
        description: `SBoB drift: outbound connection to $(win.eventdata.destinationIp):$(win.eventdata.destinationPort) not declared in egress[] of ${workload}`,
        groups: [groups(["sbob-drift", "egress-traffic"])],
        mitre: ["T1071"],
        options: ["no_full_log"],
        comment: anyIp
          ? "'*' any-IP entry present: the address condition is omitted per TDS 6.4; k8sPeer entries remain partial (TDS 6.3)"
          : "k8sPeer entries remain partial (TDS 6.3)",
      };
      if (allAddrs.length > 0 && !anyIp) {
        drift.list = { field: "win.eventdata.destinationIp", lookup: "not_address_match_key", src: `sbob/${name}/egress_addrs` };
      }
      if (portAlt !== null && !anyIp) {
        drift.fields!.push({ name: "win.eventdata.destinationPort", regex: `^(?!(?:${portAlt})$)` });
      }
      if ((allAddrs.length > 0 && !anyIp) || portAlt !== null) {
        rules.push(drift);
        rules.push({
          id: escId,
          level: 12,
          ifSid: driftId,
          frequency: 8,
          timeframe: 120,
          description: `SBoB sustained drift: repeated undeclared egress on ${name} (8 in 120s)`,
          groups: [groups(["sbob-drift", "egress-traffic", "sustained"])],
        });
      }

      // DNS-name drift (0,7) — EID 22, unique Windows capability (the Linux
      // auditd path cannot evaluate dnsNames at all). Byte-exact and wildcard
      // DNS entries both compile to the PCRE2 alternation: CDB is never used
      // for DNS (TDS 7.2).
      //
      // SBoB dnsNames are canonical DNS zone forms with a trailing dot;
      // Sysmon's QueryName field carries the hostname WITHOUT the trailing
      // dot, so Windows fragments compile from the stripped form (the Linux
      // path keeps the canonical trailing-dot spelling for M4 ingestion).
      const dnsFragments = s.egress.entries.flatMap((e) =>
        (e.source.dnsNames ?? []).map((d) => {
          const stripped = d.toLowerCase().replace(/\.$/, "");
          return d.includes("*") || d.includes("⋯")
            ? compileDnsPattern(stripped, `egress[].dnsNames (${d}, windows QueryName form)`)
            : escapeRegExp(stripped);
        }),
      );
      if (dnsFragments.length > 0) {
        const dnsDriftId = alloc.windows("base", "escalation"); // (0,7) per the TDS 6.1 amendment
        const neg = negatedAlternation(dnsFragments);
        rules.push({
          id: dnsDriftId,
          level: 9,
          ifSid: globalBaseId,
          fields: [
            { name: "win.system.eventID", regex: "^22$" },
            { name: "win.eventdata.queryName", regex: neg! },
          ],
          description: `SBoB drift: DNS query for $(win.eventdata.queryName) not declared in egress[].dnsNames of ${workload}`,
          groups: [groups(["sbob-drift", "egress-traffic", "dns-query"])],
          mitre: ["T1071"],
          options: ["no_full_log"],
          comment:
            "the shipped ruleset routes EIDs 1-15 only, so the EID 22 condition is self-defined here (0595-win-sysmon_rules.xml carries no 22); " +
            "DNS wildcards never use CDB — byte-exact keys are only valid for plain FQDN entries (TDS 7.2)",
        });
      }
    } else if (s.egress === undefined) {
      rules.push(sectionAbsentRule(globalBaseId, ir, alloc, "egress", "sysmon_event3", "^3$", "egress-traffic"));
    }

    // ingress (Windows listener-side is host-FW territory — informational) -----
    if (s.ingress !== undefined) {
      const infoId = alloc.windows("ingress", "info");
      rules.push({
        id: infoId,
        level: 3,
        ifSid: globalBaseId,
        fields: [
          { name: "win.system.eventID", regex: "^3$" },
          { name: "win.eventdata.initiated", regex: "^[Ff]alse$" },
        ],
        description: `SBoB informational: ingress[] declared for ${name} but listener-side enforcement is host-firewall territory (TDS 8.3)`,
        groups: [groups(["sbob-info", "ingress-traffic"])],
      });
    }

    // Sysmon prerequisite health (0,8) — informational signal on Sysmon service
    // state changes; true absence detection (agent inventory) is the M5 runbook.
    {
      const prereqId = alloc.windows("base", "info");
      rules.push({
        id: prereqId,
        level: 2,
        ifSid: globalBaseId,
        fields: [{ name: "win.system.eventID", regex: "^4$" }],
        description: `SBoB informational: Sysmon service state changed on an agent in the sbob-${name} scope — verify the deployment prerequisite (TDS 4.3, M5 runbook inventory check)`,
        groups: [groups(["sbob-info", "sysmon-prereq"])],
        comment: "EID 4 (service state change) is a health signal; agents entirely lacking Sysmon emit no Sysmon events and must be caught by the inventory check",
      });
    }

    const xml = [
      xmlFileHeader(`sbob drift rules for workload ${name} — Windows / Sysmon target`, name, labNote(alloc)),
      "",
      ...rules.map(renderRule).join("\n\n").split("\n"),
      "",
    ].join("\n");
    files.push({
      path: `wazuh/rules/sbob/${ID_BAND_BASE(alloc)}_${name}_windows.xml`,
      content: xml,
    });
  }

  // --------------------------------------------------------------------------
  // 4. bundle manifest (machine-generated coverage matrix: TDS 8, M4)
  // --------------------------------------------------------------------------
  {
    const coverage = buildCoverageMatrix(ir);
    const problems = assertCoverageComplete(coverage);
    if (problems.length > 0) {
      throw new Error(`coverage gate failed for workload ${name}: ${problems.join("; ")}`);
    }
    files.push({
      path: `${name}.manifest.json`,
      content:
        JSON.stringify(
          {
            workload: ir.workload,
            target: "windows",
            sbobVersion: ir.workload.sbobVersion,
            imageID: ir.workload.imageID,
            bundleVersion: bundleVersion(ir),
            files: files.map((f) => f.path),
            coverage,
            coverageNotes: [
              ...ir.coverageNotes,
              ...signatureCoverageNotes(ir),
              "windows: execs[].args drift is heuristic-equivalent (CommandLine tokenization, TDS 7.3.4) — flagged partial",
              "windows: opens[].flags are not evaluable from Sysmon telemetry; EID 11 covers file-create only (TDS 8.2)",
              "windows: capabilities[] is N/A on Windows (TDS 8.2)",
              "windows: execs/opens allowlists compile to PCRE2 alternations (CDB keys cannot contain the drive-letter ':')",
              "windows: requires the shipped ruleset parent rule 61600 and Wazuh >= 4.4 (type=\"pcre2\" field attribute)",
              "windows: rulePolicies signature rules are deferred to a later milestone (auditd-keyed rules have no Sysmon equivalent yet; flagged partial SIG_WIN_DEFERRED in the coverage matrix)",
            ],
            labValidation: alloc.lab ? "validated" : "pending",
            ...(alloc.lab ? { labValidationEvidence: alloc.lab } : {}),
          },
          null,
          2,
        ) + "\n",
    });
  }

  return files;
}

// -----------------------------------------------------------------------------

/**
 * Token-aware command-line regex (TDS 7.3.4 heuristic, flagged partial).
 *
 * Sysmon EID 1 carries CommandLine — one string, as typed — not argv. The
 * SBoB args[] vector (which includes argv[0]) is compiled to a PCRE2
 * full-match over the CommandLine with:
 *   - argv[0] anchored at string start, optionally quoted
 *   - quoting variants tolerated for every token
 *   - ⋯      -> one token (quoted or bare)
 *   - ⋯⋯     -> zero or more trailing arguments, or zero tokens mid-vector
 *   - literal '*' in args stays a literal
 */
export function commandLineRegex(e: ExecCompiled): string {
  const args = e.source.args ?? [];
  // argv[0]: reuse the compiled path regex when the SBoB declares it as the
  // path (the common form); otherwise escape the declared argv[0] literally.
  let re: string;
  if (args.length > 0 && args[0] === e.source.path) {
    re = `"?${e.pathRegex}"?`;
  } else if (args.length > 0) {
    re = `"?${escapeRegExp(args[0])}"?`;
  } else {
    re = `"?${e.pathRegex}"?`;
  }
  const rest = args.slice(1);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const isLast = i === rest.length - 1;
    if (a === "⋯⋯") {
      re += isLast ? `(?:\\s.*)?` : `(?:\\s+(?:"[^"]*"|\\S+))*`;
    } else if (a === "⋯") {
      re += `\\s+(?:"[^"]*"|\\S+)`;
    } else {
      re += `\\s+(?:"${escapeRegExp(a)}"|${escapeRegExp(a)})`;
    }
  }
  return re;
}

function ID_BAND_BASE(alloc: IdAllocator): number {
  return 100000 + alloc.slot * 100;
}

function sectionAbsentRule(
  globalBaseId: number,
  ir: IR,
  alloc: IdAllocator,
  section: string,
  eidGroup: string,
  eid: string,
  group: string,
): XmlRule {
  const name = ir.workload.name;
  const infoId = alloc.windows(section as "execs" | "opens" | "egress", "info");
  return {
    id: infoId,
    level: 2,
    ifSid: globalBaseId,
    fields: [
      { name: "win.system.eventID", regex: eid },
    ],
    description: `SBoB informational: section ${section}[] is absent from the ${name} SBoB; any event of this class is under-specified (spec 5.4 absent != NONE)`,
    groups: [["sbob", name, "sbob-info", group, eidGroup]],
  };
}
