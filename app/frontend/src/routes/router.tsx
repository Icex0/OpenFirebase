import { Navigate, createBrowserRouter } from "react-router-dom";

import { AppShell } from "@/components/layout/AppShell";
import { AuthGuard } from "@/features/auth/AuthGuard";
import { LoginPage } from "@/features/auth/LoginPage";
import { RegisterPage } from "@/features/auth/RegisterPage";
import { ManualScanPage } from "@/features/scans/ManualScanPage";
import { NewScanPage } from "@/features/scans/NewScanPage";
import { ScanDetailPage } from "@/features/scans/ScanDetailPage";
import { ScansListPage } from "@/features/scans/ScansListPage";
import { UploadPage } from "@/features/scans/UploadPage";
import { StoragePage } from "@/features/storage/StoragePage";

export const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  { path: "/register", element: <RegisterPage /> },
  {
    element: <AuthGuard />,
    children: [
      {
        element: <AppShell />,
        children: [
          { index: true, element: <Navigate to="/scans" replace /> },
          { path: "scans", element: <ScansListPage /> },
          { path: "scans/new", element: <NewScanPage /> },
          { path: "scans/new/bundle", element: <UploadPage /> },
          { path: "scans/new/manual", element: <ManualScanPage /> },
          { path: "scans/:id", element: <ScanDetailPage /> },
          { path: "storage", element: <StoragePage /> },
        ],
      },
    ],
  },
  { path: "*", element: <Navigate to="/scans" replace /> },
]);
