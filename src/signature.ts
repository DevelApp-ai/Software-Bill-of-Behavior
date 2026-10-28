/**
 * Signature verification interface (TDS 7.1 / spec section 8).
 *
 * The upstream SBoB signature envelope (spec section 8, "Signatures") is still
 * in development, so verification is pluggable:
 *   - --skip-signature-verify: development mode, records a coverage note
 *   - default: attempts `cosign verify-blob` against a detached signature
 *     (<file>.sig + optional <file>.bundle). If no cosign binary is on PATH,
 *     fails with ERR_SIGNATURE_UNAVAILABLE rather than silently skipping.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { accessSync, constants } from "node:fs";
import { SbobError } from "./errors.ts";

const exec = promisify(execFile);

export type VerifyResult =
  | { ok: true; method: "cosign" }
  | { ok: true; method: "skipped"; note: string };

export interface SignatureVerifier {
  verify(path: string): Promise<VerifyResult>;
}

export class SkipVerifier implements SignatureVerifier {
  private readonly note = "signature verification skipped (--skip-signature-verify); profile treated as unverified";
  async verify(_path: string): Promise<VerifyResult> {
    return { ok: true, method: "skipped", note: this.note };
  }
}

export class CosignVerifier implements SignatureVerifier {
  async verify(path: string): Promise<VerifyResult> {
    const sigPath = `${path}.sig`;
    const hasSig = hasFile(sigPath);
    try {
      await exec("cosign", ["version"]);
    } catch {
      throw new SbobError(
        "ERR_SIGNATURE_UNAVAILABLE",
        `cannot verify "${path}": no cosign binary on PATH and no --skip-signature-verify flag. ` +
          "The upstream signature envelope (spec section 8) is still in development; " +
          "use --skip-signature-verify for unsigned development profiles only.",
      );
    }
    if (!hasSig) {
      throw new SbobError(
        "ERR_SIGNATURE_INVALID",
        `cannot verify "${path}": no detached signature found at "${sigPath}"`,
      );
    }
    try {
      await exec("cosign", ["verify-blob", "--signature", sigPath, "--key", "sbob-trusted-keys", path]);
    } catch (e) {
      throw new SbobError(
        "ERR_SIGNATURE_INVALID",
        `signature verification failed for "${path}": ${(e as Error).message}`,
      );
    }
    return { ok: true, method: "cosign" };
  }
}

function hasFile(p: string): boolean {
  try {
    accessSync(p, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

export function makeVerifier(skip: boolean): SignatureVerifier {
  return skip ? new SkipVerifier() : new CosignVerifier();
}
