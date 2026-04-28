import { useEffect, useRef, useState, type ChangeEvent, type ReactNode } from "react";

import { cn } from "@/lib/cn";
import type { ScanOptions, WordlistChoice } from "@/lib/types";

import { Input } from "@/components/ui/Input";

export interface OptionsFormValue {
  options: ScanOptions;
  fuzzCollectionsFile: File | null;
  fuzzFunctionsFile: File | null;
  writeRtdbFile: File | null;
  writeStorageFile: File | null;
}

interface Props {
  value: OptionsFormValue;
  onChange: (next: OptionsFormValue) => void;
  disabled?: boolean;
  /** Hide the Google ID token field when batch-scanning — one token can't
   * authenticate to multiple distinct Firebase projects. */
  allowGoogleIdToken?: boolean;
  /** Manual mode reveals the Service account section. */
  showServiceAccount?: boolean;
  /** Optional private-key file upload (manual mode only). */
  privateKeyFile?: File | null;
  onPrivateKeyFileChange?: (f: File | null) => void;
}

const WORDLIST_CHOICES: { value: WordlistChoice; label: string }[] = [
  { value: "off", label: "Off" },
  { value: "top-50", label: "Top 50 (bundled)" },
  { value: "top-250", label: "Top 250 (bundled)" },
  { value: "top-500", label: "Top 500 (bundled)" },
  { value: "custom", label: "Custom upload…" },
];

// Mirrors openfirebase/payloads/ — shown read-only so users can see what the
// default write probe will attempt to upload. Keep in sync if those files change.
const DEFAULT_RTDB_PAYLOAD = '{"unauth_access":"OpenFirebase_write_check"}';
const DEFAULT_STORAGE_PAYLOAD =
  "OpenFirebase - Unauth Firebase write access found";

export function OptionsForm({
  value,
  onChange,
  disabled,
  allowGoogleIdToken = true,
  showServiceAccount = false,
  privateKeyFile,
  onPrivateKeyFileChange,
}: Props) {
  const { options } = value;
  const set = <K extends keyof ScanOptions>(key: K, v: ScanOptions[K]) =>
    onChange({ ...value, options: { ...options, [key]: v } });

  return (
    <div className="space-y-4">
      <Section
        title="Read testing"
        hint="Which Firebase services to probe for unauthenticated read access."
        action={
          <button
            type="button"
            onClick={() => {
              const allOn =
                options.read_rtdb &&
                options.read_storage &&
                options.read_config &&
                options.read_firestore &&
                options.read_functions;
              const next = !allOn;
              onChange({
                ...value,
                options: {
                  ...options,
                  read_rtdb: next,
                  read_storage: next,
                  read_config: next,
                  read_firestore: next,
                  read_functions: next,
                },
              });
            }}
            disabled={disabled}
            className="font-mono text-[10px] uppercase tracking-wider text-ink-400 hover:text-ink-100 disabled:opacity-50"
          >
            {options.read_rtdb &&
            options.read_storage &&
            options.read_config &&
            options.read_firestore &&
            options.read_functions
              ? "Deselect all"
              : "Select all"}
          </button>
        }
      >
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          <Toggle
            label="Realtime Database"
            checked={options.read_rtdb}
            onChange={(v) => set("read_rtdb", v)}
            disabled={disabled}
          />
          <Toggle
            label="Storage"
            checked={options.read_storage}
            onChange={(v) => set("read_storage", v)}
            disabled={disabled}
          />
          <Toggle
            label="Remote Config"
            checked={options.read_config}
            onChange={(v) => set("read_config", v)}
            disabled={disabled}
          />
          <Toggle
            label="Firestore"
            checked={options.read_firestore}
            onChange={(v) => set("read_firestore", v)}
            disabled={disabled}
          />
          <Toggle
            label="Cloud Functions"
            checked={options.read_functions}
            onChange={(v) => set("read_functions", v)}
            disabled={disabled}
          />
        </div>
      </Section>

      <Section
        title="Fuzzing"
        hint="Wordlist-based enumeration. Bundled lists are curated from real-world usage."
      >
        <Field label="Firestore collections">
          <WordlistSelect
            value={options.fuzz_collections}
            onChange={(v) => set("fuzz_collections", v)}
            disabled={disabled}
          />
        </Field>
        {options.fuzz_collections === "custom" && (
          <FilePicker
            label="Custom collections wordlist (.txt, ≤2MB)"
            accept=".txt"
            file={value.fuzzCollectionsFile}
            onChange={(f) => onChange({ ...value, fuzzCollectionsFile: f })}
            disabled={disabled}
          />
        )}

        <Field label="Cloud Functions">
          <WordlistSelect
            value={options.fuzz_functions}
            onChange={(v) => set("fuzz_functions", v)}
            disabled={disabled}
          />
        </Field>
        {options.fuzz_functions === "custom" && (
          <FilePicker
            label="Custom functions wordlist (.txt, ≤2MB)"
            accept=".txt"
            file={value.fuzzFunctionsFile}
            onChange={(f) => onChange({ ...value, fuzzFunctionsFile: f })}
            disabled={disabled}
          />
        )}

        <Field label="Firestore collection name override (optional)">
          <Input
            value={options.collection_name ?? ""}
            onChange={(e) =>
              set("collection_name", e.target.value.trim() || null)
            }
            placeholder="users,posts"
            disabled={disabled}
          />
        </Field>

        <Field label="Cloud Functions name(s) (optional)">
          <Input
            value={options.function_name ?? ""}
            onChange={(e) => set("function_name", e.target.value.trim() || null)}
            placeholder="helloWorld,onSignup"
            disabled={disabled}
          />
        </Field>

        <Field label="Cloud Functions region(s) (optional; default us-central1)">
          <Input
            value={options.function_region ?? ""}
            onChange={(e) => set("function_region", e.target.value.trim() || null)}
            placeholder="us-central1,europe-west1"
            disabled={disabled}
          />
        </Field>
      </Section>

      <Section
        title="Write testing"
        hint="Which Firebase services to probe for unauthenticated write access. Uses bundled OpenFirebase payloads unless you upload your own."
      >
        <Toggle
          label="Test Storage write"
          checked={options.write_storage}
          onChange={(v) =>
            onChange({
              ...value,
              options: { ...options, write_storage: v },
              writeStorageFile: v ? value.writeStorageFile : null,
            })
          }
          disabled={disabled}
        />
        {options.write_storage && (
          <>
            <FilePicker
              label="Custom storage payload (optional, ≤20MB)"
              file={value.writeStorageFile}
              onChange={(f) => onChange({ ...value, writeStorageFile: f })}
              disabled={disabled}
            />
            <PayloadPreview
              label={
                value.writeStorageFile
                  ? `Payload (${value.writeStorageFile.name})`
                  : "Bundled storage payload (.txt)"
              }
              file={value.writeStorageFile}
              fallback={DEFAULT_STORAGE_PAYLOAD}
              defaultFilename="storage_payload.txt"
              onChange={(f) => onChange({ ...value, writeStorageFile: f })}
              disabled={disabled}
            />
          </>
        )}

        <Toggle
          label="Test Realtime Database write"
          checked={options.write_rtdb}
          onChange={(v) =>
            onChange({
              ...value,
              options: { ...options, write_rtdb: v },
              writeRtdbFile: v ? value.writeRtdbFile : null,
            })
          }
          disabled={disabled}
        />
        {options.write_rtdb && (
          <>
            <FilePicker
              label="Custom RTDB payload JSON (optional, ≤20MB)"
              accept=".json"
              file={value.writeRtdbFile}
              onChange={(f) => onChange({ ...value, writeRtdbFile: f })}
              disabled={disabled}
            />
            <PayloadPreview
              label={
                value.writeRtdbFile
                  ? `Payload (${value.writeRtdbFile.name})`
                  : "Bundled RTDB payload (.json)"
              }
              file={value.writeRtdbFile}
              fallback={DEFAULT_RTDB_PAYLOAD}
              defaultFilename="rtdb_payload.json"
              onChange={(f) => onChange({ ...value, writeRtdbFile: f })}
              disabled={disabled}
              validateJson
            />
          </>
        )}

        <Toggle
          label="Test Firestore write"
          checked={options.write_firestore}
          onChange={(v) =>
            onChange({
              ...value,
              options: {
                ...options,
                write_firestore: v,
                ...(v ? {} : { write_firestore_value: "unauth_write_check" }),
              },
            })
          }
          disabled={disabled}
        />
        {options.write_firestore && (
          <Field label="Value written to firestore_unauthenticated_access">
            <Input
              value={options.write_firestore_value}
              onChange={(e) => set("write_firestore_value", e.target.value)}
              disabled={disabled}
            />
          </Field>
        )}
      </Section>

      <Section
        title="Authentication"
        hint="Retry 401/403 read and/or write responses as an authenticated user. This will create a new account if it doesn't exist and if email/password auth is enabled for the project."
      >
        <Toggle
          label="Enable authenticated retry"
          checked={options.auth_enabled}
          onChange={(v) =>
            onChange({
              ...value,
              options: v
                ? { ...options, auth_enabled: true }
                : {
                    ...options,
                    auth_enabled: false,
                    auth_email: null,
                    auth_password: null,
                    google_id_token: null,
                  },
            })
          }
          disabled={disabled}
        />
        {options.auth_enabled && (
          <div className="space-y-2">
            <Field label="Email">
              <Input
                type="email"
                value={options.auth_email ?? ""}
                onChange={(e) => set("auth_email", e.target.value.trim() || null)}
                placeholder="tester@example.com"
                autoComplete="off"
                disabled={disabled}
              />
            </Field>
            <Field label="Password">
              <Input
                type="password"
                value={options.auth_password ?? ""}
                onChange={(e) => set("auth_password", e.target.value || null)}
                autoComplete="new-password"
                disabled={disabled}
              />
            </Field>
            {allowGoogleIdToken ? (
              <Field label="Google ID token (optional — for signInWithIdp fallback)">
                <Input
                  value={options.google_id_token ?? ""}
                  onChange={(e) =>
                    set("google_id_token", e.target.value.trim() || null)
                  }
                  placeholder="eyJhbGciOi…"
                  autoComplete="off"
                  disabled={disabled}
                />
              </Field>
            ) : (
              <p className="rounded border border-ink-700/60 bg-ink-900/40 px-3 py-2 text-xs text-ink-400">
                Google ID tokens are tied to a single Firebase project, so
                they're unavailable when scanning multiple bundles.
              </p>
            )}
          </div>
        )}
      </Section>

      {showServiceAccount && (
        <Section
          title="Service account"
          hint="Authenticates via the Google OAuth2 JWT flow with the service account's RSA key. This may allow full control over the entire Firebase project."
        >
          <Field label="Service account email">
            <Input
              type="email"
              value={value.options.service_account ?? ""}
              onChange={(e) =>
                set("service_account", e.target.value.trim() || null)
              }
              placeholder="scanner@my-project.iam.gserviceaccount.com"
              autoComplete="off"
              disabled={disabled}
            />
          </Field>
          <Field label="Private key (PEM) — paste OR upload below">
            <textarea
              value={value.options.private_key ?? ""}
              onChange={(e) =>
                set("private_key", e.target.value || null)
              }
              placeholder={"-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----"}
              disabled={disabled || !!privateKeyFile}
              rows={5}
              className={cn(
                "block w-full rounded-md border border-ink-700 bg-ink-950/60 px-3 py-2 font-mono text-[11px] text-ink-100 placeholder:text-ink-500 focus:outline-none focus:border-accent",
                privateKeyFile && "opacity-50",
              )}
              autoComplete="off"
              spellCheck={false}
            />
          </Field>
          {onPrivateKeyFileChange && (
            <FilePicker
              label="Private key file (.pem / .json key) — overrides paste"
              accept=".pem,.json,.key"
              file={privateKeyFile ?? null}
              onChange={onPrivateKeyFileChange}
              disabled={disabled}
            />
          )}
        </Section>
      )}
    </div>
  );
}

function Section({
  title,
  hint,
  action,
  children,
}: {
  title: string;
  hint?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(true);
  return (
    <div className="rounded-lg border border-ink-700/80 bg-ink-900/40">
      <div className="flex w-full items-center justify-between gap-4 px-4 py-3">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex flex-1 items-center justify-between gap-4 text-left"
        >
          <div>
            <div className="text-sm font-medium tracking-tight text-ink-100">{title}</div>
            {hint && <div className="mt-0.5 text-xs text-ink-400">{hint}</div>}
          </div>
          <span
            className={cn(
              "font-mono text-[11px] uppercase tracking-wider text-ink-400 transition-transform",
              open ? "rotate-90" : "rotate-0",
            )}
          >
            ›
          </span>
        </button>
        {action}
      </div>
      {open && <div className="space-y-3 border-t border-ink-700/60 p-4">{children}</div>}
    </div>
  );
}

function PayloadPreview({
  label,
  file,
  fallback,
  defaultFilename,
  onChange,
  disabled,
  validateJson,
}: {
  label: string;
  file: File | null;
  fallback: string;
  defaultFilename: string;
  onChange: (f: File | null) => void;
  disabled?: boolean;
  validateJson?: boolean;
}) {
  const [content, setContent] = useState(fallback);
  const [locked, setLocked] = useState(false); // true for binary/oversize previews
  const [jsonError, setJsonError] = useState<string | null>(null);
  // Tracks Files this component synthesized from textarea edits so the
  // file-read effect below doesn't echo them back and stomp the user's typing.
  const ownFileRef = useRef<File | null>(null);

  useEffect(() => {
    if (!validateJson) {
      setJsonError(null);
      return;
    }
    try {
      JSON.parse(content);
      setJsonError(null);
    } catch (e) {
      setJsonError(e instanceof Error ? e.message : "invalid JSON");
    }
  }, [content, validateJson]);

  useEffect(() => {
    if (file && file === ownFileRef.current) return;
    if (!file) {
      setContent(fallback);
      setLocked(false);
      return;
    }
    let cancelled = false;
    const MAX_PREVIEW_BYTES = 4096;
    file
      .slice(0, MAX_PREVIEW_BYTES)
      .text()
      .then((text) => {
        if (cancelled) return;
        const hasBinaryBytes = /[\x00-\x08\x0E-\x1F]/.test(text);
        if (hasBinaryBytes) {
          setLocked(true);
          setContent(`(binary file, ${file.size.toLocaleString()} bytes — not editable here)`);
        } else if (file.size > MAX_PREVIEW_BYTES) {
          setLocked(true);
          setContent(
            `${text}\n\n… (truncated, showing first ${MAX_PREVIEW_BYTES} of ${file.size.toLocaleString()} bytes — edit the source file to change)`,
          );
        } else {
          setLocked(false);
          setContent(text);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setLocked(true);
          setContent(`(couldn't read ${file.name})`);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [file, fallback]);

  const handleEdit = (next: string) => {
    setContent(next);
    if (next === fallback) {
      ownFileRef.current = null;
      onChange(null);
      return;
    }
    const name = file?.name ?? defaultFilename;
    const type = file?.type || (name.endsWith(".json") ? "application/json" : "text/plain");
    const synthesized = new File([next], name, { type });
    ownFileRef.current = synthesized;
    onChange(synthesized);
  };

  return (
    <Field label={label}>
      <textarea
        value={content}
        readOnly={locked || disabled}
        onChange={(e) => handleEdit(e.target.value)}
        rows={Math.min(8, Math.max(3, content.split("\n").length))}
        className={cn(
          "block w-full rounded-md border bg-ink-950/40 px-3 py-2 font-mono text-[12px] text-ink-300 focus:outline-none",
          jsonError
            ? "border-severity-public/60 focus:border-severity-public"
            : "border-ink-700 focus:border-accent",
        )}
        spellCheck={false}
      />
      {jsonError && (
        <p className="mt-1 font-mono text-[11px] text-severity-public">
          Invalid JSON: {jsonError}
        </p>
      )}
    </Field>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block font-mono text-[11px] uppercase tracking-wider text-ink-400">
        {label}
      </span>
      {children}
    </label>
  );
}

function Toggle({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label
      className={cn(
        "flex cursor-pointer items-center gap-2.5 rounded-md border border-ink-700/60 bg-ink-950/40 px-3 py-2 text-sm",
        "hover:border-ink-600",
        disabled && "cursor-not-allowed opacity-60",
      )}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
        className="h-3.5 w-3.5 accent-accent"
      />
      <span className="text-ink-200">{label}</span>
    </label>
  );
}

function WordlistSelect({
  value,
  onChange,
  disabled,
}: {
  value: WordlistChoice;
  onChange: (v: WordlistChoice) => void;
  disabled?: boolean;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as WordlistChoice)}
      disabled={disabled}
      className="h-9 w-full rounded-md border border-ink-700 bg-ink-900/60 px-3 text-sm text-ink-100 focus-ring"
    >
      {WORDLIST_CHOICES.map((c) => (
        <option key={c.value} value={c.value}>
          {c.label}
        </option>
      ))}
    </select>
  );
}

function FilePicker({
  label,
  file,
  onChange,
  accept,
  disabled,
}: {
  label: string;
  file: File | null;
  onChange: (f: File | null) => void;
  accept?: string;
  disabled?: boolean;
}) {
  const handle = (e: ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.files?.[0] ?? null);
  };
  return (
    <Field label={label}>
      <div className="flex items-center gap-2">
        <input
          type="file"
          accept={accept}
          onChange={handle}
          disabled={disabled}
          className="block w-full text-xs text-ink-300 file:mr-3 file:rounded-md file:border file:border-ink-700 file:bg-ink-900 file:px-2.5 file:py-1.5 file:font-mono file:text-[11px] file:uppercase file:tracking-wider file:text-ink-200 hover:file:border-ink-600"
        />
        {file && (
          <button
            type="button"
            onClick={() => onChange(null)}
            className="font-mono text-[11px] uppercase tracking-wider text-ink-400 hover:text-ink-200"
          >
            clear
          </button>
        )}
      </div>
    </Field>
  );
}
