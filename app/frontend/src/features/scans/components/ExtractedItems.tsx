interface Props {
  items: Record<string, unknown> | null;
}

const LABELS: Record<string, string> = {
  // From the final scan.json (lowercase plural).
  firebase_project_ids: "Project IDs",
  google_api_keys: "Google API keys",
  google_app_ids: "Google App IDs",
  items: "Other items",
  leaked_private_keys: "Leaked private keys",
};

function humanize(key: string): string {
  if (LABELS[key]) return LABELS[key];
  // PascalCase / Snake_Case from the mid-run items-file parser
  // (Firebase_Project_ID → "Firebase project ID").
  const spaced = key.replace(/_/g, " ").trim();
  if (!spaced) return key;
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}

export function ExtractedItems({ items }: Props) {
  if (!items) return null;
  const entries = Object.entries(items).filter(
    ([, v]) => Array.isArray(v) && (v as unknown[]).length > 0,
  );
  if (entries.length === 0) return null;

  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-xs">
      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
            {humanize(k)}
          </dt>
          <dd className="space-y-0.5 font-mono text-ink-200">
            {(v as unknown[]).map((entry, i) => (
              <div key={i} className="break-all">
                {typeof entry === "string"
                  ? entry
                  : JSON.stringify(entry)}
              </div>
            ))}
          </dd>
        </div>
      ))}
    </dl>
  );
}
