import { useCallback, useRef, useState, type DragEvent } from "react";

import { cn } from "@/lib/cn";

interface Props {
  onFiles: (files: File[]) => void;
  disabled?: boolean;
  accept?: string;
}

const APK_IPA = /\.(apk|ipa)$/i;

// Recursively walk a dropped folder via the (non-standard but ubiquitous)
// webkitGetAsEntry API. Returns only .apk/.ipa leaves.
async function readDataTransfer(items: DataTransferItemList): Promise<File[]> {
  const out: File[] = [];
  const walk = async (entry: any): Promise<void> => {
    if (!entry) return;
    if (entry.isFile) {
      const file: File = await new Promise((res) => entry.file(res));
      if (APK_IPA.test(file.name)) out.push(file);
      return;
    }
    if (entry.isDirectory) {
      const reader = entry.createReader();
      const readBatch = (): Promise<any[]> =>
        new Promise((res) => reader.readEntries(res));
      while (true) {
        const batch = await readBatch();
        if (batch.length === 0) break;
        for (const child of batch) await walk(child);
      }
    }
  };
  const entries: any[] = [];
  for (let i = 0; i < items.length; i++) {
    const e = items[i].webkitGetAsEntry?.();
    if (e) entries.push(e);
  }
  for (const e of entries) await walk(e);
  return out;
}

export function UploadDropzone({ onFiles, disabled, accept = ".apk,.ipa" }: Props) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dirInputRef = useRef<HTMLInputElement>(null);
  const [hover, setHover] = useState(false);

  const handleFiles = useCallback(
    (files: FileList | null) => {
      if (!files || files.length === 0) return;
      const list = Array.from(files).filter((f) => APK_IPA.test(f.name));
      if (list.length) onFiles(list);
    },
    [onFiles],
  );

  const onDrop = async (e: DragEvent) => {
    e.preventDefault();
    setHover(false);
    if (e.dataTransfer.items && e.dataTransfer.items.length) {
      const found = await readDataTransfer(e.dataTransfer.items);
      if (found.length) {
        onFiles(found);
        return;
      }
    }
    handleFiles(e.dataTransfer.files);
  };

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setHover(true);
      }}
      onDragLeave={() => setHover(false)}
      onDrop={onDrop}
      className={cn(
        "group relative flex min-h-[260px] flex-col items-center justify-center gap-4",
        "rounded-xl border border-dashed transition-colors",
        hover
          ? "border-accent/60 bg-accent-muted/20"
          : "border-ink-700 bg-ink-900/30 hover:border-ink-500",
        disabled && "cursor-not-allowed opacity-60",
      )}
    >
      <input
        ref={fileInputRef}
        type="file"
        accept={accept}
        multiple
        disabled={disabled}
        className="hidden"
        onChange={(e) => handleFiles(e.target.files)}
      />
      <input
        ref={dirInputRef}
        type="file"
        // @ts-expect-error — non-standard but supported in Chromium/WebKit/Firefox.
        webkitdirectory=""
        directory=""
        disabled={disabled}
        className="hidden"
        onChange={(e) => handleFiles(e.target.files)}
      />
      <UploadGlyph />
      <div className="text-center">
        <div className="text-sm font-medium text-ink-100">
          Drop APK / IPA files or a folder here
        </div>
        <div className="mt-3 flex items-center justify-center gap-2 font-mono text-[11px] uppercase tracking-wider">
          <button
            type="button"
            disabled={disabled}
            onClick={() => fileInputRef.current?.click()}
            className="rounded border border-ink-700 px-3 py-1 text-ink-300 hover:border-ink-500 hover:text-ink-100 disabled:opacity-50"
          >
            Browse files
          </button>
          <button
            type="button"
            disabled={disabled}
            onClick={() => dirInputRef.current?.click()}
            className="rounded border border-ink-700 px-3 py-1 text-ink-300 hover:border-ink-500 hover:text-ink-100 disabled:opacity-50"
          >
            Browse folder
          </button>
        </div>
      </div>
    </div>
  );
}

function UploadGlyph() {
  return (
    <div className="relative">
      <div className="absolute inset-0 rounded-full bg-accent/10 blur-xl group-hover:bg-accent/20" />
      <svg
        viewBox="0 0 24 24"
        className="relative h-10 w-10 text-accent"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M12 16V4" />
        <path d="m7 9 5-5 5 5" />
        <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
      </svg>
    </div>
  );
}
