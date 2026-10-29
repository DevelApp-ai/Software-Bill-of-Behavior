/**
 * Error taxonomy for the sbobctl transpiler.
 * Codes mirror docs/TDS.md Appendix B (see that table for user-facing meaning).
 */
export type SbobErrorCode =
  | "ERR_SIGNATURE_INVALID"
  | "ERR_SIGNATURE_UNAVAILABLE"
  | "ERR_SCHEMA_INVALID"
  | "ERR_PCRE2_REQUIRED"
  | "ERR_ID_COLLISION"
  | "ERR_REGEX_BUDGET"
  | "ERR_NONE_UNCONFIRMED"
  | "ERR_MISSING_SCOPE"
  | "ERR_SECTION_CAP"
  | "ERR_YAML_PARSE"
  | "ERR_ENFORCE_STATE_INVALID"
  | "ERR_ENFORCE_NOT_AUDITED"
  | "ERR_PROFILE_EVENT"
  | "ERR_PROFILE_SCOPE"
  | "ERR_PROFILE_DISPOSITION"
  | "ERR_LAB_VALIDATION";

export class SbobError extends Error {
  readonly code: SbobErrorCode;
  readonly details?: Record<string, unknown>;
  constructor(code: SbobErrorCode, message: string, details?: Record<string, unknown>) {
    super(`${code}: ${message}`);
    this.name = "SbobError";
    this.code = code;
    this.details = details;
  }
}
