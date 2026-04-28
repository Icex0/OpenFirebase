import { useEffect, useLayoutEffect, useRef, useState } from "react";

import { cn } from "@/lib/cn";
import type { LogLine, StreamEvent } from "@/lib/types";

import { scanStreamUrl } from "../api";

const MAX_LINES = 5000;

interface Props {
  scanId: string;
  /** Parent signals when the stream is known to be terminal (done/failed). */
  live: boolean;
  onStage?: (stage: string, status: string, error?: string) => void;
}

/**
 * Terminal-style live console for a scan.
 *
 * The server's ``/scans/{id}/stream`` endpoint replays all historical log
 * rows on subscribe, then pushes live events — so this component only needs
 * one data source. Dedupe by ``seq`` covers StrictMode double-mount and the
 * EventSource's auto-reconnect replay. Auto-scroll only when the user is
 * pinned to the bottom. All content rendered as text (React escapes); the
 * server strips ANSI so no HTML parsing happens here.
 */
export function LiveTerminal({ scanId, live, onStage }: Props) {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [connected, setConnected] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const viewportRef = useRef<HTMLDivElement>(null);
  const pinnedRef = useRef(true);

  useEffect(() => {
    const url = scanStreamUrl(scanId);
    if (!url) return;
    const es = new EventSource(url);
    // Local dedupe — survives StrictMode remount because it's per-effect.
    const seen = new Set<number>();

    es.onopen = () => setConnected(true);
    es.onmessage = (ev) => {
      let parsed: StreamEvent;
      try {
        parsed = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (parsed.type === "log") {
        if (seen.has(parsed.seq)) return;
        seen.add(parsed.seq);
        const log: LogLine = {
          seq: parsed.seq,
          ts: new Date().toISOString(),
          stream: parsed.stream,
          line: parsed.line,
        };
        setLines((prev) => {
          const merged = [...prev, log];
          return merged.length > MAX_LINES ? merged.slice(merged.length - MAX_LINES) : merged;
        });
      } else if (parsed.type === "stage" || parsed.type === "snapshot") {
        const err = "error" in parsed ? parsed.error : undefined;
        onStage?.(parsed.stage, parsed.status, err);
      } else if (parsed.type === "end") {
        es.close();
        setConnected(false);
      }
    };
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) setConnected(false);
    };
    return () => {
      es.close();
      setConnected(false);
    };
  }, [scanId, onStage]);

  // Auto-scroll when pinned to bottom.
  useLayoutEffect(() => {
    const el = viewportRef.current;
    if (el && pinnedRef.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [lines]);

  const onScroll = () => {
    const el = viewportRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    pinnedRef.current = atBottom;
  };

  return (
    <div className="overflow-hidden rounded-lg border border-ink-700/80 bg-ink-950">
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        aria-expanded={!collapsed}
        className="flex w-full items-center justify-between border-b border-ink-700/60 bg-ink-900/60 px-3 py-2 text-left hover:bg-ink-900/80"
      >
        <div className="flex items-center gap-2">
          <span className="inline-flex gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-ink-700" />
            <span className="h-2.5 w-2.5 rounded-full bg-ink-700" />
            <span className="h-2.5 w-2.5 rounded-full bg-ink-700" />
          </span>
          <span className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
            openfirebase · console
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span
            className={cn(
              "font-mono text-[10px] uppercase tracking-wider",
              connected ? "text-accent" : "text-ink-500",
            )}
          >
            {connected ? (live ? "● live" : "● replay") : "connecting…"}
          </span>
          <span className="font-mono text-[10px] text-ink-500">
            {collapsed ? "▸" : "▾"}
          </span>
        </div>
      </button>
      <div
        ref={viewportRef}
        onScroll={onScroll}
        className={cn(
          "max-h-[420px] min-h-[240px] overflow-y-auto px-4 py-3 font-mono text-[12px] leading-relaxed",
          collapsed && "hidden",
        )}
      >
        {lines.length === 0 && (
          <div className="text-ink-500">Waiting for output…</div>
        )}
        {lines.map((l) => (
          <div
            key={l.seq}
            className={cn(
              "whitespace-pre-wrap break-words",
              l.stream === "stderr" && "text-severity-public",
              l.stream === "system" && "text-accent",
              l.stream === "stdout" && "text-ink-200",
            )}
          >
            {l.line || "\u00A0"}
          </div>
        ))}
      </div>
    </div>
  );
}
