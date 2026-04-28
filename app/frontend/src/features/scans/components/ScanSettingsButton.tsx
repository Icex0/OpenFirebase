import * as RPopover from "@radix-ui/react-popover";
import { Settings } from "lucide-react";

import { cn } from "@/lib/cn";
import type { ScanOptions } from "@/lib/types";

const READ_LABEL: Record<string, string> = {
  read_rtdb: "RTDB",
  read_firestore: "Firestore",
  read_storage: "Storage",
  read_config: "Remote Config",
  read_functions: "Cloud Functions",
};
const WRITE_LABEL: Record<string, string> = {
  write_rtdb: "RTDB",
  write_firestore: "Firestore",
  write_storage: "Storage",
};

interface Props {
  options: Partial<ScanOptions> | Record<string, unknown> | null | undefined;
  size?: "sm" | "md";
  className?: string;
  // When true, render only the gear icon (used in dense table rows).
  iconOnly?: boolean;
}

export function ScanSettingsButton({ options, size = "md", className, iconOnly }: Props) {
  if (!options) return null;
  const opts = options as Record<string, unknown>;

  return (
    <RPopover.Root>
      <RPopover.Trigger asChild>
        <button
          type="button"
          aria-label="Scan settings"
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md font-mono uppercase tracking-wider text-ink-300 transition-colors hover:bg-ink-800/40 hover:text-ink-100 data-[state=open]:bg-ink-800/60 data-[state=open]:text-ink-100",
            size === "md" ? "px-2.5 py-1.5 text-[11px]" : "px-1.5 py-1 text-[10px]",
            iconOnly && "px-1.5",
            className,
          )}
          onClick={(e) => e.stopPropagation()}
        >
          <Settings size={13} strokeWidth={1.75} aria-hidden />
          {!iconOnly && <span>Settings</span>}
        </button>
      </RPopover.Trigger>
      <RPopover.Portal>
        <RPopover.Content
          side="bottom"
          align="end"
          sideOffset={6}
          collisionPadding={12}
          onClick={(e) => e.stopPropagation()}
          className={cn(
            "z-50 w-[min(420px,calc(100vw-24px))] overflow-hidden rounded-lg border border-ink-700/80 bg-ink-900/95 shadow-2xl shadow-black/50 backdrop-blur-sm",
            "data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95 data-[state=closed]:zoom-out-95",
          )}
        >
          <div className="flex items-center justify-between border-b border-ink-700/60 px-4 py-2.5">
            <span className="font-mono text-[11px] uppercase tracking-wider text-ink-300">
              Settings used
            </span>
            <RPopover.Close
              aria-label="Close"
              className="rounded p-0.5 font-mono text-[12px] text-ink-500 hover:bg-ink-800 hover:text-ink-200"
            >
              ✕
            </RPopover.Close>
          </div>
          <div className="max-h-[60vh] overflow-y-auto px-4 py-3">
            <SettingsBody opts={opts} />
          </div>
          <RPopover.Arrow className="fill-ink-700/80" width={12} height={6} />
        </RPopover.Content>
      </RPopover.Portal>
    </RPopover.Root>
  );
}

function SettingsBody({ opts }: { opts: Record<string, unknown> }) {
  const reads = Object.keys(READ_LABEL).filter((k) => opts[k]);
  const writes = Object.keys(WRITE_LABEL).filter((k) => opts[k]);
  const mode = (opts.mode as string | undefined) ?? "bundle";
  const fuzzC = opts.fuzz_collections as string | undefined;
  const fuzzF = opts.fuzz_functions as string | undefined;
  const showFuzz = (fuzzC && fuzzC !== "off") || (fuzzF && fuzzF !== "off");
  const fnName = opts.function_name as string | undefined;
  const fnRegion = opts.function_region as string | undefined;
  const showFunctions = !!(fnName || fnRegion);
  const authEnabled = !!opts.auth_enabled;
  const authEmail = opts.auth_email as string | undefined;
  const sa = opts.service_account as string | undefined;
  const showAuth = authEnabled || !!sa;

  const manualKeys = [
    ["project_ids", "Project IDs"],
    ["app_id", "App ID"],
    ["api_key", "API Key"],
    ["cert_sha1", "Cert SHA-1"],
    ["package_name", "Package"],
    ["ios_bundle_id", "iOS Bundle ID"],
    ["referer", "Referer"],
    ["collection_name", "Collection"],
  ] as const;
  const manuals = manualKeys
    .map(([k, label]) => [label, opts[k] as string | undefined] as const)
    .filter(([, v]) => !!v);

  const writeFsValue = opts.write_firestore_value as string | undefined;

  return (
    <dl className="space-y-3.5">
      <Field label="Mode">
        <Pill>{mode}</Pill>
      </Field>

      <Field label="Read scope">
        {reads.length === 0 ? (
          <Muted>none</Muted>
        ) : (
          <PillRow>
            {reads.map((k) => (
              <Pill key={k}>{READ_LABEL[k]}</Pill>
            ))}
          </PillRow>
        )}
      </Field>

      <Field label="Write scope">
        {writes.length === 0 ? (
          <Muted>none</Muted>
        ) : (
          <PillRow>
            {writes.map((k) => (
              <Pill key={k} tone="warn">
                {WRITE_LABEL[k]}
              </Pill>
            ))}
          </PillRow>
        )}
      </Field>

      {writes.includes("write_firestore") && writeFsValue && (
        <Field label="Firestore write value">
          <Code>{writeFsValue}</Code>
        </Field>
      )}

      {showFuzz && (
        <Field label="Fuzzing">
          <PillRow>
            {fuzzC && fuzzC !== "off" && <Pill>collections: {fuzzC}</Pill>}
            {fuzzF && fuzzF !== "off" && <Pill>functions: {fuzzF}</Pill>}
          </PillRow>
        </Field>
      )}

      {showFunctions && (
        <Field label="Cloud Functions">
          <div className="space-y-1">
            {fnName && <Code>name: {fnName}</Code>}
            {fnRegion && <Code>region: {fnRegion}</Code>}
          </div>
        </Field>
      )}

      {showAuth && (
        <Field label="Authentication">
          <div className="space-y-1.5">
            {authEnabled && (
              <div className="flex flex-wrap items-center gap-2">
                <Pill tone="accent">user</Pill>
                {authEmail && <Code>{authEmail}</Code>}
                <span className="font-mono text-[10px] uppercase tracking-wider text-ink-500">
                  credentials redacted
                </span>
              </div>
            )}
            {sa && (
              <div className="flex flex-wrap items-center gap-2">
                <Pill tone="accent">service-account</Pill>
                <Code>{sa}</Code>
                <span className="font-mono text-[10px] uppercase tracking-wider text-ink-500">
                  key redacted
                </span>
              </div>
            )}
          </div>
        </Field>
      )}

      {manuals.length > 0 && (
        <Field label="Identifiers">
          <div className="space-y-1">
            {manuals.map(([label, v]) => (
              <div key={label} className="flex items-baseline gap-2">
                <span className="w-24 shrink-0 font-mono text-[10px] uppercase tracking-wider text-ink-500">
                  {label}
                </span>
                <Code className="break-all">{v}</Code>
              </div>
            ))}
          </div>
        </Field>
      )}
    </dl>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="font-mono text-[10px] uppercase tracking-wider text-ink-500">{label}</dt>
      <dd className="mt-1.5">{children}</dd>
    </div>
  );
}

function PillRow({ children }: { children: React.ReactNode }) {
  return <div className="flex flex-wrap items-center gap-1.5">{children}</div>;
}

function Pill({
  children,
  tone = "default",
}: {
  children: React.ReactNode;
  tone?: "default" | "warn" | "accent";
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
        tone === "default" && "border-ink-700 bg-ink-900/40 text-ink-200",
        tone === "warn" && "border-severity-public/40 bg-severity-public/10 text-severity-public",
        tone === "accent" && "border-accent/40 bg-accent/10 text-accent",
      )}
    >
      {children}
    </span>
  );
}

function Code({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "rounded bg-ink-900/60 px-1.5 py-0.5 font-mono text-[11px] text-ink-100",
        className,
      )}
    >
      {children}
    </span>
  );
}

function Muted({ children }: { children: React.ReactNode }) {
  return (
    <span className="font-mono text-[11px] text-ink-500">{children}</span>
  );
}

