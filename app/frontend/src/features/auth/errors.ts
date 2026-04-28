import { ApiError } from "@/lib/api";

const MESSAGES: Record<string, string> = {
  REGISTER_USER_ALREADY_EXISTS: "An account with that email already exists.",
  REGISTER_INVALID_PASSWORD: "Password is too weak. Use at least 8 characters.",
  LOGIN_BAD_CREDENTIALS: "Incorrect email or password.",
  LOGIN_USER_NOT_VERIFIED: "Account is not verified. Check your inbox.",
  RESET_PASSWORD_BAD_TOKEN: "That reset link is invalid or has expired.",
  VERIFY_USER_BAD_TOKEN: "That verification link is invalid or has expired.",
  VERIFY_USER_ALREADY_VERIFIED: "This account is already verified.",
};

export function authErrorMessage(err: unknown, fallback: string): string {
  if (!(err instanceof ApiError)) return fallback;
  // FastAPI Users sometimes wraps the code in {code, reason}; we receive
  // ``detail`` from the api wrapper as a plain string.
  const raw = err.message?.trim() ?? "";
  return MESSAGES[raw] ?? (raw || fallback);
}
