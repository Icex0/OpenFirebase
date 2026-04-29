export type ScanStatus = "queued" | "running" | "done" | "failed" | "cancelled";

export type ScanStage =
  | "queued"
  | "extracting"
  | "extracted"
  | "scanning"
  | "done"
  | "failed";

export type WordlistChoice = "off" | "top-50" | "top-250" | "top-500" | "custom";

export type ScanMode = "bundle" | "manual";

export interface ScanOptions {
  mode: ScanMode;

  read_rtdb: boolean;
  read_storage: boolean;
  read_config: boolean;
  read_firestore: boolean;
  read_functions: boolean;

  fuzz_collections: WordlistChoice;
  fuzz_functions: WordlistChoice;
  collection_name: string | null;

  skip_gcs_probing: boolean;

  function_name: string | null;
  function_region: string | null;

  write_storage: boolean;
  write_firestore: boolean;
  write_rtdb: boolean;
  write_firestore_value: string;

  auth_enabled: boolean;
  auth_email: string | null;
  auth_password: string | null;
  google_id_token: string | null;

  service_account: string | null;
  private_key: string | null;

  project_ids: string | null;
  app_id: string | null;
  api_key: string | null;
  cert_sha1: string | null;
  package_name: string | null;
  referer: string | null;
  ios_bundle_id: string | null;
}

export type Verdict =
  | "public"
  | "protected"
  | "still_protected"
  | "not_found"
  | "rate_limited"
  | "locked"
  | "app_check"
  | "error"
  | "unknown";

export interface ProbeResult {
  status: string;
  security: string;
  verdict: Verdict;
  message: string | null;
  has_body: boolean;
  identity?: { kind?: string; ref?: string } | null;
}

export interface ResponseBody {
  content: string;
  truncated: boolean;
}

export interface Finding {
  id: string;
  service: "rtdb" | "firestore" | "storage" | "remote_config" | "cloud_functions";
  probe: "read" | "write";
  url: string;
  unauth: ProbeResult;
  auth: ProbeResult | null;
  resource: Record<string, unknown> | null;
}

export interface Project {
  id: string;
  project_id: string;
  package_names: string[] | null;
  extracted_items: Record<string, unknown> | null;
  findings: Finding[];
}

export interface ScanSummary {
  id: string;
  filename: string;
  status: ScanStatus;
  stage: ScanStage;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  tool_version: string | null;
  error_message: string | null;
  bundle_filenames: string[];
  options: Partial<ScanOptions> | null;
}

export interface ScanDetail extends ScanSummary {
  schema_version: string | null;
  projects: Project[];
  raw_document: unknown;
}

export interface LogLine {
  seq: number;
  ts: string;
  stream: "stdout" | "stderr" | "system";
  line: string;
}

export type StreamEvent =
  | { type: "snapshot"; stage: ScanStage; status: ScanStatus }
  | { type: "stage"; stage: ScanStage; status: ScanStatus; error?: string }
  | { type: "log"; seq: number; stream: LogLine["stream"]; line: string }
  | { type: "end" };
