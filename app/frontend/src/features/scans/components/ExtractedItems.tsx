import type { LeakedPrivateKey, ServiceAccountCred } from "@/lib/types";

interface Props {
  items: Record<string, unknown> | null;
  // From extraction.bundles[] (project-relevant subset). These are NOT in
  // ``items`` because the JSON schema keeps credentials in a separate paired
  // structure (extracted_items is unpaired strings only). The drawer renders
  // them inline so the operator sees everything that came out of the bundle.
  serviceAccounts?: ServiceAccountCred[];
  leakedKeys?: LeakedPrivateKey[];
  // Bundle-level identifiers attributed to this project (one bundle can
  // back several projects via package_name match).
  packageNames?: string[];
  sha1Signatures?: string[];
}

const LABELS: Record<string, string> = {
  // From the final scan.json (lowercase plural).
  firebase_project_ids: "Project IDs",
  google_api_keys: "Google API keys",
  google_app_ids: "Google App IDs",
  items: "Other items",
};

function humanize(key: string): string {
  if (LABELS[key]) return LABELS[key];
  // PascalCase / Snake_Case from the mid-run items-file parser
  // (Firebase_Project_ID → "Firebase project ID").
  const spaced = key.replace(/_/g, " ").trim();
  if (!spaced) return key;
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}

export function ExtractedItems({
  items,
  serviceAccounts,
  leakedKeys,
  packageNames,
  sha1Signatures,
}: Props) {
  const entries = items
    ? Object.entries(items).filter(
        ([, v]) => Array.isArray(v) && (v as unknown[]).length > 0,
      )
    : [];
  const sas = serviceAccounts ?? [];
  const leaks = leakedKeys ?? [];
  const pkgs = packageNames ?? [];
  const sha1s = sha1Signatures ?? [];
  if (
    entries.length === 0 &&
    sas.length === 0 &&
    leaks.length === 0 &&
    pkgs.length === 0 &&
    sha1s.length === 0
  )
    return null;

  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs">
      {pkgs.length > 0 && (
        <div className="contents">
          <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
            Package
          </dt>
          <dd className="space-y-0.5 font-mono text-ink-200">
            {pkgs.map((n, i) => (
              <div key={i} className="break-all">
                {n}
              </div>
            ))}
          </dd>
        </div>
      )}

      {sha1s.length > 0 && (
        <div className="contents">
          <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
            SHA-1
          </dt>
          <dd className="space-y-0.5 font-mono text-ink-200">
            {sha1s.map((s, i) => (
              <div key={i} className="break-all">
                {s}
              </div>
            ))}
          </dd>
        </div>
      )}

      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
            {humanize(k)}
          </dt>
          <dd className="space-y-0.5 font-mono text-ink-200">
            {(v as unknown[]).map((entry, i) => (
              <div key={i} className="break-all">
                {typeof entry === "string" ? entry : JSON.stringify(entry)}
              </div>
            ))}
          </dd>
        </div>
      ))}

      {sas.length > 0 && (
        <div className="contents">
          <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
            Service accounts
          </dt>
          <dd className="space-y-2 font-mono text-ink-200">
            {sas.map((sa, i) => (
              <details key={i} open>
                <summary className="cursor-pointer break-all marker:text-ink-500">
                  {sa.client_email}
                  {sa.project_id && (
                    <span className="ml-2 text-ink-500">({sa.project_id})</span>
                  )}
                </summary>
                <pre className="mt-1 whitespace-pre-wrap break-all text-[11px] text-ink-300">
                  {sa.private_key}
                </pre>
              </details>
            ))}
          </dd>
        </div>
      )}

      {leaks.length > 0 && (
        <div className="contents">
          <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
            Leaked private keys
          </dt>
          <dd className="space-y-2 font-mono text-ink-200">
            {leaks.map((k, i) => (
              <details key={i} open>
                <summary className="cursor-pointer break-all marker:text-ink-500">
                  <span className="text-ink-500">{k.pem_type}</span>
                </summary>
                <pre className="mt-1 whitespace-pre-wrap break-all text-[11px] text-ink-300">
                  {k.pem}
                </pre>
              </details>
            ))}
          </dd>
        </div>
      )}
    </dl>
  );
}
