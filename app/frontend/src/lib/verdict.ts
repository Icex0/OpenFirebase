import type { Verdict } from "./types";

export const VERDICT_LABEL: Record<Verdict, string> = {
  public: "Public",
  protected: "Protected",
  still_protected: "Protected (auth)",
  not_found: "Not found",
  rate_limited: "Rate limited",
  locked: "Locked",
  app_check: "App Check",
  error: "Error",
  unknown: "Unknown",
};

export const VERDICT_DOT: Record<Verdict, string> = {
  public: "bg-severity-public",
  protected: "bg-severity-protected",
  still_protected: "bg-severity-protected",
  not_found: "bg-severity-notFound",
  rate_limited: "bg-severity-rateLimited",
  locked: "bg-severity-locked",
  app_check: "bg-severity-appCheck",
  error: "bg-severity-error",
  unknown: "bg-severity-unknown",
};

export const VERDICT_PRIORITY: Record<Verdict, number> = {
  public: 0,
  app_check: 1,
  locked: 2,
  rate_limited: 3,
  still_protected: 4,
  protected: 5,
  not_found: 6,
  error: 7,
  unknown: 8,
};
