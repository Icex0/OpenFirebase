from __future__ import annotations

import asyncio
import fcntl
import json
import os
import pty
import re
from collections.abc import Awaitable, Callable
from importlib.resources import files
from pathlib import Path
from typing import Any

from ..scans.schemas import ScanOptions

LineCallback = Callable[[str, str], Awaitable[None]]
"""``(stream, line) -> awaitable``. ``stream`` is 'stdout' or 'stderr'."""

MAX_LINE_LEN = 4096

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class ScannerError(RuntimeError):
    pass


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _set_nonblocking(fd: int) -> None:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def _bundled_wordlist(kind: str, choice: str) -> Path | None:
    if choice not in {"top-50", "top-250", "top-500"}:
        return None
    name = f"{kind}-{choice}.txt"
    try:
        path = files("openfirebase").joinpath("wordlist", name)
        p = Path(str(path))
        return p if p.is_file() else None
    except (ModuleNotFoundError, FileNotFoundError):
        return None


def _bundled_payload(name: str) -> Path | None:
    try:
        path = files("openfirebase").joinpath("payloads", name)
        p = Path(str(path))
        return p if p.is_file() else None
    except (ModuleNotFoundError, FileNotFoundError):
        return None


def _resolve_wordlist(
    kind: str, choice: str, custom_path: Path | None
) -> Path | None:
    if choice == "off":
        return None
    if choice == "custom":
        return custom_path
    return _bundled_wordlist(kind, choice)


def build_argv(
    *,
    input_dir: Path | None,
    output_dir: Path,
    options: ScanOptions,
    fuzz_collections_custom: Path | None = None,
    fuzz_functions_custom: Path | None = None,
    write_rtdb_custom: Path | None = None,
    write_storage_custom: Path | None = None,
    project_id_file: Path | None = None,
    private_key_file: Path | None = None,
) -> list[str]:
    # The CLI always writes ``<output_dir>/<timestamp>_results/<timestamp>_scan.json``
    # — we discover the produced file via a glob after the run finishes.
    argv: list[str] = [
        "openfirebase",
        "-o", str(output_dir),
    ]

    if options.mode == "manual":
        # Project IDs come from a file (multiple) or inline (single/few).
        if project_id_file is not None:
            argv.extend(["--project-id-file", str(project_id_file)])
        elif options.project_ids:
            argv.extend(["--project-id", options.project_ids])
        else:
            raise ScannerError("manual mode requires at least one project ID")
        if options.app_id:
            argv.extend(["--app-id", options.app_id])
        if options.api_key:
            argv.extend(["--api-key", options.api_key])
        if options.cert_sha1:
            argv.extend(["--cert-sha1", options.cert_sha1])
        if options.package_name:
            argv.extend(["--package-name", options.package_name])
        if options.referer:
            argv.extend(["--referer", options.referer])
        if options.ios_bundle_id:
            argv.extend(["--ios-bundle-id", options.ios_bundle_id])
        if options.service_account:
            argv.extend(["--service-account", str(options.service_account)])
        if private_key_file is not None:
            argv.extend(["--private-key", str(private_key_file)])
    else:
        # App mode: a single uploaded APK/IPA goes through --file so it stays
        # compatible with flags that the CLI rejects against --app-dir
        # (e.g. --google-id-token). Multi-file bundles still use --app-dir.
        if input_dir is None:
            raise ScannerError("app mode requires an input directory")
        bundle_files = sorted(p for p in input_dir.iterdir() if p.is_file())
        if len(bundle_files) == 1:
            argv.extend(["--file", str(bundle_files[0])])
        else:
            argv.extend(["--app-dir", str(input_dir)])

    if options.read_rtdb:
        argv.append("--read-rtdb")
    if options.read_storage:
        argv.append("--read-storage")
    if options.read_config:
        argv.append("--read-config")
    if options.read_firestore:
        argv.append("--read-firestore")
    if options.read_functions:
        argv.append("--read-functions")

    if options.collection_name:
        argv.extend(["--collection-name", options.collection_name])

    if options.function_name:
        argv.extend(["--function-name", options.function_name])
    if options.function_region:
        argv.extend(["--function-region", options.function_region])

    fc = _resolve_wordlist(
        "firestore-collections", options.fuzz_collections, fuzz_collections_custom
    )
    if fc is not None:
        argv.extend(["--fuzz-collections", str(fc)])

    ff = _resolve_wordlist(
        "cloud-functions", options.fuzz_functions, fuzz_functions_custom
    )
    if ff is not None:
        argv.extend(["--fuzz-functions", str(ff)])

    if options.skip_gcs_probing:
        argv.append("--skip-gcs-probing")

    if options.write_rtdb:
        payload = write_rtdb_custom or _bundled_payload("openfirebase.json")
        if payload is not None:
            argv.extend(["--write-rtdb", str(payload)])

    if options.write_storage:
        payload = write_storage_custom or _bundled_payload(
            "openfirebase_storage_write_check.txt"
        )
        if payload is not None:
            argv.extend(["--write-storage", str(payload)])

    if options.write_firestore:
        argv.extend(["--write-firestore", options.write_firestore_value])

    if options.auth_enabled:
        argv.append("--check-with-auth")
        if options.auth_email:
            argv.extend(["--email", str(options.auth_email)])
        if options.auth_password:
            argv.extend(["--password", options.auth_password])
        if options.google_id_token:
            argv.extend(["--google-id-token", options.google_id_token])

    return argv


async def run_scan(
    *,
    input_dir: Path | None,
    output_dir: Path,
    options: ScanOptions,
    on_line: LineCallback,
    fuzz_collections_custom: Path | None = None,
    fuzz_functions_custom: Path | None = None,
    write_rtdb_custom: Path | None = None,
    write_storage_custom: Path | None = None,
    project_id_file: Path | None = None,
    private_key_file: Path | None = None,
    cancel_event: asyncio.Event | None = None,
) -> dict[str, Any]:
    """Run OpenFirebase once against an APK, streaming stdout/stderr line by
    line to ``on_line``. Returns the parsed scan document.

    The caller is responsible for reacting to stage markers in the streamed
    lines (e.g. flipping the scan's ``stage`` when the tool logs that it's
    starting the testing phase).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    argv = build_argv(
        input_dir=input_dir,
        output_dir=output_dir,
        options=options,
        fuzz_collections_custom=fuzz_collections_custom,
        fuzz_functions_custom=fuzz_functions_custom,
        write_rtdb_custom=write_rtdb_custom,
        write_storage_custom=write_storage_custom,
        project_id_file=project_id_file,
        private_key_file=private_key_file,
    )

    env = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        "NO_COLOR": "1",
        "TQDM_DISABLE": "1",
    }

    # Allocate a PTY so the child (and any multiprocessing workers it spawns)
    # sees stdout as a TTY and switches from block-buffering to line-buffering.
    # This is the only reliable way to get live output out of tools that use
    # tqdm / ProcessPoolExecutor / anything that re-opens stdout internally.
    # stdout and stderr share the same PTY — distinguishing the two isn't
    # worth the complexity of managing two PTYs.
    pty_master, pty_slave = pty.openpty()
    _set_nonblocking(pty_master)

    proc = await asyncio.create_subprocess_exec(
        *argv,
        cwd=str(output_dir),
        env=env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=pty_slave,
        stderr=pty_slave,
        start_new_session=True,
    )
    os.close(pty_slave)  # Child holds the only remaining handle.

    # Single consumer drains the line queue serially so ``on_line`` callbacks
    # (and therefore DB seq assignment) stay in produce order.
    line_q: asyncio.Queue[bytes | None] = asyncio.Queue()

    async def pump() -> None:
        loop = asyncio.get_running_loop()
        buf = bytearray()
        reader_closed = asyncio.Event()

        def _on_readable() -> None:
            try:
                chunk = os.read(pty_master, 4096)
            except BlockingIOError:
                return
            except OSError:
                reader_closed.set()
                return
            if not chunk:
                reader_closed.set()
                return
            buf.extend(chunk)
            while True:
                nl = buf.find(b"\n")
                cr = buf.find(b"\r")
                if nl == -1 and cr == -1:
                    break
                idx = nl if cr == -1 else cr if nl == -1 else min(nl, cr)
                line = bytes(buf[:idx])
                # Swallow \r\n (PTY ONLCR) as a single delimiter so we don't
                # emit a phantom blank line after every real line.
                consume = idx + 1
                if (
                    buf[idx : idx + 1] == b"\r"
                    and len(buf) > idx + 1
                    and buf[idx + 1 : idx + 2] == b"\n"
                ):
                    consume = idx + 2
                del buf[:consume]
                line_q.put_nowait(line)

        try:
            loop.add_reader(pty_master, _on_readable)
            await reader_closed.wait()
        finally:
            try:
                loop.remove_reader(pty_master)
            except Exception:
                pass
            if buf:
                line_q.put_nowait(bytes(buf))
            line_q.put_nowait(None)  # consumer sentinel

    async def consume() -> None:
        while True:
            item = await line_q.get()
            if item is None:
                return
            text = _strip_ansi(item.decode("utf-8", errors="replace"))
            if len(text) > MAX_LINE_LEN:
                text = text[:MAX_LINE_LEN] + "…"
            await on_line("stdout", text)

    async def _watch_cancel() -> None:
        if cancel_event is None:
            return
        await cancel_event.wait()
        # `start_new_session=True` put the child in its own process group, so
        # killpg reaches any multiprocessing workers it spawned too.
        try:
            import signal as _signal
            os.killpg(proc.pid, _signal.SIGKILL)
        except ProcessLookupError:
            pass

    cancel_task = asyncio.create_task(_watch_cancel())
    try:
        await asyncio.gather(pump(), consume())
        code = await proc.wait()
    finally:
        cancel_task.cancel()
        try:
            os.close(pty_master)
        except OSError:
            pass

    if cancel_event is not None and cancel_event.is_set():
        raise ScannerError("cancelled by user")

    if code != 0:
        raise ScannerError(f"scan failed (exit {code})")
    # CLI writes to ``<output_dir>/<timestamp>_results/<timestamp>_scan.json``;
    # the timestamp is generated at run time so we discover the file by glob.
    matches = sorted(output_dir.glob("*_results/*_scan.json"))
    if not matches:
        raise ScannerError("scan produced no JSON document")
    if len(matches) > 1:
        # Pick the newest if for some reason multiple show up.
        matches.sort(key=lambda p: p.stat().st_mtime)
    json_path = matches[-1]
    try:
        return json.loads(json_path.read_text())
    except json.JSONDecodeError as exc:
        raise ScannerError(f"scan JSON invalid: {exc}") from exc
