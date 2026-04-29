import type { ScanOptions, ScanSummary } from "@/lib/types";

export const DEFAULT_OPTIONS: ScanOptions = {
  mode: "bundle",

  read_rtdb: false,
  read_storage: false,
  read_config: false,
  read_firestore: false,
  read_functions: false,

  fuzz_collections: "off",
  fuzz_functions: "off",
  collection_name: null,

  skip_gcs_probing: false,

  function_name: null,
  function_region: null,

  write_storage: false,
  write_firestore: false,
  write_rtdb: false,
  write_firestore_value: "unauth_write_check",

  auth_enabled: false,
  auth_email: null,
  auth_password: null,
  google_id_token: null,

  service_account: null,
  private_key: null,

  project_ids: null,
  app_id: null,
  api_key: null,
  cert_sha1: null,
  package_name: null,
  referer: null,
  ios_bundle_id: null,
};

/** Returns null when auth credentials look usable, else a human-readable
 * reason. Authenticated retry can't possibly succeed without either an
 * email+password pair or a Google ID token. */
export function authCredentialError(o: ScanOptions): string | null {
  if (!o.auth_enabled) return null;
  const hasEmailPw = !!(o.auth_email && o.auth_password);
  const hasGoogle = !!o.google_id_token;
  if (hasEmailPw || hasGoogle) return null;
  return "Authenticated retry needs an email + password or a Google ID token.";
}

function projectIdCount(o: ScanOptions): number {
  if (!o.project_ids) return 0;
  return o.project_ids.split(/[\s,]+/).filter(Boolean).length;
}

/** Non-blocking advisory: Firebase API keys and App IDs are project-scoped
 * (App IDs encode the project number as ``1:PROJECT_NUMBER:PLATFORM:HASH``),
 * so spraying them over multiple project IDs only works for the one project
 * the credential actually belongs to. Returns a warning string or null. */
export function projectScopedCredWarning(
  o: ScanOptions,
  projectIdFile: File | null,
): string | null {
  const count = projectIdFile ? 2 : projectIdCount(o);
  if (count <= 1) return null;
  const fields: string[] = [];
  if (o.api_key) fields.push("API key");
  if (o.app_id) fields.push("App ID");
  if (fields.length === 0) return null;
  const countLabel = projectIdFile ? "multiple" : String(count);
  return `${fields.join(" and ")} ${fields.length > 1 ? "are" : "is"} project-scoped but you supplied ${countLabel} project IDs. The credential will only match one project; the others will likely fail with 403 / invalid-key responses.`;
}

/** Mirrors the hard rules in openfirebase/core/cli.py so we reject invalid
 * combinations before kicking off a scan. Returns the first violation or null. */
export function scanOptionError(o: ScanOptions): string | null {
  const auth = authCredentialError(o);
  if (auth) return auth;

  // Service account ↔ private key must come together.
  const hasSA = !!o.service_account;
  const hasPK = !!o.private_key;
  if (hasSA !== hasPK) {
    return "Service account email and private key must be provided together.";
  }

  if (o.mode === "manual") {
    const hasIds = projectIdCount(o) > 0;

    // --read-config + project IDs requires both --app-id and --api-key.
    if (o.read_config && hasIds && !(o.app_id && o.api_key)) {
      return "Remote Config (--read-config) with project IDs requires both App ID and API key. Disable Remote Config or fill both fields.";
    }

    // --read-functions + project IDs requires --function-name or fuzz wordlist.
    if (
      o.read_functions &&
      hasIds &&
      !o.function_name &&
      o.fuzz_functions === "off"
    ) {
      return "Cloud Functions (--read-functions) with project IDs requires either a function name or a function fuzzing wordlist.";
    }

    // Authenticated retry over project IDs requires an API key + single project.
    if (o.auth_enabled && hasIds) {
      if (!o.api_key) {
        return "Authenticated retry with project IDs requires an API key.";
      }
      if (projectIdCount(o) > 1) {
        return "Authenticated retry only supports a single project ID — each Firebase project needs its own API key.";
      }
    }
  }

  return null;
}

/** Reads a candidate RTDB payload and confirms it parses as JSON. Returns
 * a human-readable error string on failure, or null when the payload is OK. */
export async function validateRtdbJson(file: File): Promise<string | null> {
  try {
    const text = await file.text();
    if (!text.trim()) return "RTDB payload is empty.";
    JSON.parse(text);
    return null;
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    return `RTDB payload must be valid JSON: ${detail}`;
  }
}

export interface ScanSubjects {
  /** What each item represents in the UI — used for the tooltip label. */
  kind: "bundle" | "project";
  items: string[];
}

/** Canonical list of "what was scanned" for a given scan row: APK/IPA filenames
 * for bundle mode, or the pasted project IDs for manual mode. File-supplied
 * project IDs don't round-trip to the client, so those show an empty list. */
export function scanSubjects(scan: Pick<ScanSummary, "bundle_filenames" | "options">): ScanSubjects {
  if (scan.bundle_filenames && scan.bundle_filenames.length > 0) {
    return { kind: "bundle", items: scan.bundle_filenames };
  }
  const raw = scan.options?.project_ids;
  if (typeof raw === "string" && raw.trim()) {
    const ids = raw.split(/[\s,]+/).filter(Boolean);
    return { kind: "project", items: ids };
  }
  return { kind: "bundle", items: [] };
}
