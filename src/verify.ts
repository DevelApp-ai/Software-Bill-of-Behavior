/**
 * Registry-entry verification (consumer-side trust primitive, TDS 7.2).
 *
 * `sbobctl verify` checks a signed SBoB registry entry in two stages:
 *
 *   Stage 1 — offline integrity (always, no cosign, no network):
 *     - the detached signature (<file>.sig) and the cosign Rekor bundle
 *       (<file>.bundle) must exist next to the entry;
 *     - the bundle is parsed (UTF-8 or UTF-16LE — the SBOB-Forge publish
 *       lane emits UTF-16LE bundles on windows runners, observed in
 *       production 2026-11-05), the Rekor entry body is extracted from
 *       `.rekorBundle.Payload.body` (older writers used `.bundle.Payload`),
 *       and the hashedrekord sha256 inside the Rekor entry must equal the
 *       sha256 of the shipped entry bytes.
 *     This is the class of defect that SBOB-Forge v1.5.39 exposed in
 *     production (signature bound pre-convert bytes while the registry
 *     carried converted bytes): a tampered or mis-bound artifact fails
 *     HERE, offline, before any cryptographic verification runs.
 *
 *   Stage 2 — keyless signature + identity pin (requires cosign on PATH):
 *     `cosign verify-blob --bundle <bundle> --signature <sig>
 *        --certificate-identity <id> --certificate-oidc-issuer <issuer> <file>`
 *     The workflow identity is REQUIRED explicitly — fail closed; a
 *     signature without a pinned identity is not a verified signature.
 *
 * Stage 1 alone proves byte-binding between the Rekor transparency entry
 * and the shipped artifact, NOT cryptographic authenticity: the CLI prints
 * an explicit note when stage 2 did not run.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { accessSync, constants, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { SbobError } from "./errors.ts";

const exec = promisify(execFile);

/** Default OIDC issuer for GitHub Actions keyless (cosign) identities. */
export const GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com";

export interface VerifyOptions {
  /** Required for stage 2: the workflow identity the certificate must pin (SAN). */
  certificateIdentity?: string;
  /** OIDC issuer of the certificate; defaults to the GitHub Actions issuer. */
  certificateOidcIssuer?: string;
}

export interface VerifyReport {
  ok: true;
  entryPath: string;
  /** sha256 of the shipped entry bytes (hex, lowercase). */
  entrySha256: string;
  /** Rekor entry hash extracted from the bundle (hex, lowercase). */
  rekorSha256: string;
  /** Stage 1 ran: bundle hash == shipped bytes hash. */
  byteBindingVerified: true;
  /** Stage 2 ran: cosign verify-blob with an identity pin passed. */
  identityVerified: boolean;
}

/** Applies VerifyOptions defaults: an identity without an issuer pins the
 *  GitHub Actions OIDC issuer (the dominant keyless producer of registry
 *  entries); an issuer without an identity is a usage error, not a guess. */
export function normalizeVerifyOptions(opts: VerifyOptions): VerifyOptions {
  const hasIdentity = opts.certificateIdentity !== undefined && opts.certificateIdentity !== "";
  const hasIssuer = opts.certificateOidcIssuer !== undefined && opts.certificateOidcIssuer !== "";
  if (hasIssuer && !hasIdentity) {
    throw new SbobError(
      "ERR_VERIFY_COSIGN_FAILED",
      "--certificate-oidc-issuer requires --certificate-identity: pin the workflow identity whose signature you expect",
    );
  }
  if (hasIdentity && !hasIssuer) {
    return { ...opts, certificateOidcIssuer: GITHUB_ACTIONS_OIDC_ISSUER };
  }
  return opts;
}

/**
 * Reads a file as text, decoding UTF-16LE when it carries a UTF-16LE BOM
 * (FF FE) and stripping a UTF-8 BOM otherwise. The SBOB-Forge publish lane
 * emitted UTF-16LE cosign bundles in production (2026-11-05); treating
 * them as UTF-8 yields garbage JSON, so the decode is content-sniffed.
 */
export function readTextAnyEncoding(path: string): string {
  const buf = readFileSync(path);
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    // UTF-16LE with BOM: Node decodes "utf16le" natively; a truncated
    // trailing unit is dropped by the decoder.
    return buf.subarray(2).toString("utf16le");
  }
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return buf.subarray(3).toString("utf8");
  }
  return buf.toString("utf8");
}

interface RekorBody {
  hashAlgorithm: string;
  hashValue: string;
}

/** Narrows an unknown JSON node to a record without chained cast syntax
 *  (Node 22 native type stripping rejects `a?.b as T | undefined` chains). */
function asRecord(node: unknown): Record<string, unknown> | undefined {
  if (node !== null && typeof node === "object" && !Array.isArray(node)) {
    return node as Record<string, unknown>;
  }
  return undefined;
}

/** Extracts the hashedrekord sha256 from a parsed cosign bundle JSON.
 *  Accepts the production layout (`.rekorBundle.Payload.body`) and the
 *  older flat layout (`.bundle.Payload.body`); anything else is malformed. */
export function extractRekorSha256(bundleText: string): RekorBody {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bundleText);
  } catch (e) {
    throw new SbobError(
      "ERR_VERIFY_BUNDLE_MALFORMED",
      `cosign bundle is not valid JSON: ${(e as Error).message}`,
    );
  }
  const root = parsed as Record<string, unknown>;
  const rekor = asRecord(root.rekorBundle ?? root.bundle);
  const payload = asRecord(rekor?.Payload ?? rekor?.payload);
  const bodyB64 = payload?.body;
  if (typeof bodyB64 !== "string" || bodyB64 === "") {
    throw new SbobError(
      "ERR_VERIFY_BUNDLE_MALFORMED",
      'cosign bundle has no Rekor entry body (expected ".rekorBundle.Payload.body"; older writers used ".bundle.Payload.body")',
    );
  }
  let entry: unknown;
  try {
    entry = JSON.parse(Buffer.from(bodyB64, "base64").toString("utf8"));
  } catch (e) {
    throw new SbobError(
      "ERR_VERIFY_BUNDLE_MALFORMED",
      `Rekor entry body is not valid JSON after base64 decoding: ${(e as Error).message}`,
    );
  }
  const hashedrekord = asRecord(asRecord(entry)?.body)?.hashedrekord;
  const data = asRecord(asRecord(hashedrekord)?.data);
  const hash = asRecord(data?.hash);
  const algorithm = hash?.algorithm;
  const value = hash?.value;
  if (typeof algorithm !== "string" || algorithm !== "sha256" || typeof value !== "string" || value === "") {
    throw new SbobError(
      "ERR_VERIFY_BUNDLE_MALFORMED",
      "Rekor entry does not carry a sha256 hashedrekord hash (expected body.body.hashedrekord.data.hash with algorithm=sha256)",
    );
  }
  return { hashAlgorithm: algorithm, hashValue: value.toLowerCase() };
}

function hasFile(p: string): boolean {
  try {
    accessSync(p, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Verifies one signed registry entry. Stage 1 (offline byte-binding) is
 * unconditional; stage 2 (cosign keyless verify-blob with an identity
 * pin) runs when `certificateIdentity` is provided.
 */
export async function verifyEntry(path: string, opts: VerifyOptions): Promise<VerifyReport> {
  const options = normalizeVerifyOptions(opts);
  if (!hasFile(path)) {
    throw new SbobError(
      "ERR_VERIFY_ENTRY_MISSING",
      `registry entry not found (or unreadable): "${path}"`,
    );
  }
  const sigPath = `${path}.sig`;
  if (!hasFile(sigPath)) {
    throw new SbobError(
      "ERR_VERIFY_SIG_MISSING",
      `no detached signature next to the entry: expected "${sigPath}"`,
    );
  }
  const bundlePath = `${path}.bundle`;
  if (!hasFile(bundlePath)) {
    throw new SbobError(
      "ERR_VERIFY_BUNDLE_MISSING",
      `no cosign Rekor bundle next to the entry: expected "${bundlePath}"`,
    );
  }

  const entryBytes = readFileSync(path);
  const entrySha256 = createHash("sha256").update(entryBytes).digest("hex");
  const { hashValue: rekorSha256 } = extractRekorSha256(readTextAnyEncoding(bundlePath));

  if (rekorSha256 !== entrySha256) {
    throw new SbobError(
      "ERR_VERIFY_HASH_MISMATCH",
      `signed bytes are not the shipped bytes: the Rekor entry commits sha256 ${rekorSha256} but "${path}" is sha256 ${entrySha256}. ` +
        "The signature (or the artifact) does not bind to this file — reject it.",
      { expected: rekorSha256, actual: entrySha256, entryPath: path },
    );
  }

  let identityVerified = false;
  if (options.certificateIdentity !== undefined && options.certificateIdentity !== "") {
    try {
      await exec("cosign", ["version"]);
    } catch {
      throw new SbobError(
        "ERR_VERIFY_COSIGN_UNAVAILABLE",
        `cannot verify the keyless signature of "${path}": no cosign binary on PATH and an identity pin was requested. ` +
          "Install cosign (sigstore/cosign installer action) or drop --certificate-identity for offline byte-binding checks only.",
      );
    }
    try {
      await exec("cosign", [
        "verify-blob",
        "--bundle", bundlePath,
        "--signature", sigPath,
        "--certificate-identity", options.certificateIdentity as string,
        "--certificate-oidc-issuer", options.certificateOidcIssuer as string,
        path,
      ]);
      identityVerified = true;
    } catch (e) {
      throw new SbobError(
        "ERR_VERIFY_COSIGN_FAILED",
        `cosign verify-blob failed for "${path}": ${(e as Error).message}`,
        { identity: options.certificateIdentity, issuer: options.certificateOidcIssuer },
      );
    }
  }

  return {
    ok: true,
    entryPath: path,
    entrySha256,
    rekorSha256,
    byteBindingVerified: true,
    identityVerified,
  };
}
