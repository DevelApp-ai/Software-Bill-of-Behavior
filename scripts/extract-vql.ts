/**
 * Engines-lab lane helper (M6 / issue #7): extract the VQL sweep queries from
 * a generated Velociraptor artifact (velociraptor/sbob/<name>.yaml) into
 * standalone .vql files that the pinned Velociraptor binary executes with
 * `velociraptor query -f <file>` — the CI live lane proves the generated
 * VQL parses and runs against live runner state.
 *
 *   node scripts/extract-vql.ts <artifact.yaml> <out-dir>
 *
 * The artifact embeds each query as an indented literal block under
 * `queries:` (8-space indent); this script dedents them into runnable VQL.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [artifact, outDir] = process.argv.slice(2) as [string?, string?];
if (!artifact || !outDir) {
  console.error("usage: node scripts/extract-vql.ts <artifact.yaml> <out-dir>");
  process.exit(2);
}

const lines = readFileSync(artifact, "utf8").split("\n");
mkdirSync(outDir, { recursive: true });

let current: string[] | null = null;
let count = 0;
const flush = (): void => {
  if (current !== null && current.length > 0) {
    count += 1;
    writeFileSync(join(outDir, `sbob-q${count}.vql`), current.join("\n") + "\n");
  }
  current = null;
};

for (const line of lines) {
  if (line === "      - |") {
    flush();
    current = [];
  } else if (current !== null && line.startsWith("        ")) {
    current.push(line.slice(8));
  } else if (current !== null && line !== "") {
    flush();
  }
}
flush();

if (count === 0) {
  console.error(`no VQL queries found in ${artifact}`);
  process.exit(1);
}
console.log(`extracted ${count} VQL queries to ${outDir}`);
