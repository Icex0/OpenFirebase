from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version as _pkg_version

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request

try:
    APP_VERSION = _pkg_version("openfirebase-web-backend")
except PackageNotFoundError:
    APP_VERSION = "0.0.0+unknown"

from .auth.router import router as auth_router
from .config import get_settings
from .scans.pubsub import bus
from .scans.router import MAX_APK_BYTES
from .scans.router import router as scans_router
from .storage.minio_client import ensure_bucket
from .storage.router import router as storage_router

# Lift Starlette's multipart limits (max_files=1000, max_part_size=1 MiB).
# Patching __kwdefaults__ because FastAPI calls request.form() with no args.
for _fn in (Request.form, Request._get_form):
    _defaults = dict(_fn.__kwdefaults__ or {})
    _defaults["max_files"] = 10_000
    _defaults["max_part_size"] = MAX_APK_BYTES
    _fn.__kwdefaults__ = _defaults


@asynccontextmanager
async def lifespan(app: FastAPI):
    await ensure_bucket()
    # Attach the Postgres LISTEN connection up-front so NOTIFYs that arrive
    # before the first SSE subscriber aren't lost.
    await bus.start_listener()
    try:
        yield
    finally:
        await bus.stop()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="OpenFirebase Web",
        version=APP_VERSION,
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(auth_router)
    app.include_router(scans_router)
    app.include_router(storage_router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/info")
    async def info() -> dict[str, str]:
        return {"version": app.version}

    return app


app = create_app()
