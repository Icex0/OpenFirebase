import { api, setToken } from "@/lib/api";

interface LoginResponse {
  access_token: string;
  token_type: string;
}

export async function login(email: string, password: string): Promise<void> {
  const form = new URLSearchParams({ username: email, password });
  const res = await api.postForm<LoginResponse>("/auth/jwt/login", form);
  setToken(res.access_token);
}

export async function register(email: string, password: string): Promise<void> {
  await api.post("/auth/register", { email, password });
  await login(email, password);
}
