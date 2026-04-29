import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/Button";
import { api, setToken } from "@/lib/api";
import { cn } from "@/lib/cn";

const REPO_URL = "https://github.com/Icex0/OpenFirebase";
const COPYRIGHT_YEAR = "2026";
const COPYRIGHT_HOLDER = "Icex0";

interface AppInfo {
  version: string;
}

export function AppShell() {
  const navigate = useNavigate();
  const [info, setInfo] = useState<AppInfo | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.get<AppInfo>("/info").then(
      (res) => {
        if (!cancelled) setInfo(res);
      },
      () => {
        // Version is non-essential; silently degrade.
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  const logout = () => {
    setToken(null);
    navigate("/login");
  };

  return (
    <div className="flex min-h-screen flex-col bg-ink-950 bg-grid">
      <header className="sticky top-0 z-10 border-b border-ink-700/60 bg-ink-950/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-6">
          <div className="flex items-center gap-8">
            <div className="flex items-center gap-2">
              <LogoMark />
              <span className="font-mono text-[13px] uppercase tracking-[0.18em] text-ink-200">
                OpenFirebase
              </span>
              {info?.version && (
                <span className="font-mono text-[10px] text-ink-500">
                  v{info.version}
                </span>
              )}
            </div>
            <nav className="flex items-center gap-1 text-sm">
              <NavItem to="/scans">Scans</NavItem>
              <NavItem to="/storage">Storage</NavItem>
            </nav>
          </div>
          <Button variant="ghost" size="sm" onClick={logout}>
            Sign out
          </Button>
        </div>
      </header>
      <main className="mx-auto w-full max-w-7xl flex-1 px-6 py-8">
        <Outlet />
      </main>
      <footer className="border-t border-ink-700/60 bg-ink-950/60 py-3">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-2 px-6 text-[11px] text-ink-500">
          <span>
            © {COPYRIGHT_YEAR} {COPYRIGHT_HOLDER} · OpenFirebase
            {info?.version && ` v${info.version}`}
          </span>
          <a
            href={REPO_URL}
            target="_blank"
            rel="noreferrer"
            className="underline decoration-dotted hover:text-ink-300"
          >
            GitHub
          </a>
        </div>
      </footer>
    </div>
  );
}

function NavItem({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <NavLink
      to={to}
      end
      className={({ isActive }) =>
        cn(
          "rounded-md px-3 py-1.5 text-ink-300 transition-colors hover:text-ink-100",
          isActive && "bg-ink-800/60 text-ink-100",
        )
      }
    >
      {children}
    </NavLink>
  );
}

function LogoMark() {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-5 w-5 text-accent"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M5 18.5 10.5 4l4.5 9 3 5.5Z" />
      <path d="M5 18.5 15 13" opacity="0.6" />
    </svg>
  );
}
