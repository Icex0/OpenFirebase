# OpenFirebase Web

Web companion for the OpenFirebase CLI. Upload APKs, run scans, view findings.

## Stack

- **Backend**: FastAPI, SQLAlchemy (async), Alembic, FastAPI-Users
- **Frontend**: React, Vite, TypeScript, Tailwind, TanStack Query, React Router
- **Infra**: Postgres, MinIO (S3-compatible blob storage)

## Quick start (local)

```bash
cp .env.example .env
docker compose up --build
```

> The defaults in `.env.example` are fine for localhost but **rotate every
> secret** (`APP_SECRET`, `POSTGRES_PASSWORD`, `S3_SECRET_KEY`,
> `SCANNER_DB_PASSWORD`, `SCANNER_S3_SECRET_KEY`) before exposing this stack
> beyond your machine.

- Frontend dev: http://localhost:8080
- Backend API: http://localhost:8000
- MinIO console: http://localhost:9001

## Layout

```
app/
├── backend/   # FastAPI service (API + scan runner)
├── frontend/  # Vite + React SPA
└── docker-compose.yml
```

See `backend/README.md` and `frontend/README.md` for details.
