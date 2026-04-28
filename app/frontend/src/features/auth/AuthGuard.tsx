import { Navigate, Outlet, useLocation } from "react-router-dom";

import { getToken } from "@/lib/api";

export function AuthGuard() {
  const location = useLocation();
  if (!getToken()) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  return <Outlet />;
}
