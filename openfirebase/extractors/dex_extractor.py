"""Android DEX Extractor Module

Stateless helpers for pulling Firebase items out of an Android ``.apk``
*without* spawning JADX. The Java/Kotlin string literals OpenFirebase's
regex pipeline cares about (Firebase URLs, API keys, Firestore
collection names, hardcoded credentials) live in the DEX **string
pool**, which androguard exposes via ``DEX.get_strings()``. Walking
that table is roughly 5x faster than a full JADX decompile and
needs no JVM dependency.

Coverage equivalence with the JADX path:

* **Compile-time string literals** — every Java/Kotlin string constant
  ends up in ``string_ids``. Catches Firebase URLs, API keys,
  Firestore collection names, ``gserviceaccount.com`` emails, and full
  PEM blocks (Java compile-time concat folds them into one entry).
* **Resource-bundled strings** — handled separately by walking
  ``assets/`` and ``res/raw/`` for ``*.json``/``*.xml``/``*.txt``
  content and feeding them through the same regex pipeline. (Mirrors
  what JADX's ``rglob('*.json')`` over decompile output catches by
  accident.)
* **Service-account JSON** — already handled by
  :class:`FirebaseExtractor._extract_service_accounts_from_apk` via
  ``apk.get_files()``; this module does not duplicate that.

What it does NOT recover (matches the JADX path's failure modes):

* Strings encrypted by DexGuard / Allatori / Stringer / paid R8 plugins
  — only the ciphertext is in the string pool.
* Strings concatenated at runtime from multiple fragments via
  ``StringBuilder`` or ``String.format``.
* Strings embedded in native ``lib/*.so`` libraries.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

# Bytecode-walk targets: DEX method refs whose first ``String`` argument
# is a Firestore collection / document path, etc. The string-pool walk
# alone can't recover these because the call expression
# ``...collection("users")`` only exists in the string pool as the bare
# token ``"users"`` — the ``collection(`` text lives in the method-ref
# table, not adjacent to the literal. Walking ``invoke-*`` opcodes lets
# us pair the two and synthesize the missing source-shaped literal.
_INVOKE_TARGETS = (
    "Lcom/google/firebase/firestore/FirebaseFirestore;->collection(",
    "Lcom/google/firebase/firestore/CollectionReference;->document(",
    "Lcom/google/firebase/firestore/DocumentReference;->collection(",
)
_CONST_STRING_RE = re.compile(r'(v\d+),\s*"(.*)"$', re.S)

from androguard.core.apk import APK
from androguard.core.dex import DEX

from ._patterns import (
    GSERVICEACCOUNT_EMAIL_RE,
    PEM_PRIVATE_KEY_RE_STR,
)

# Soft caps. Some apps ship multi-MB JSON catalogs in ``assets/`` (ML
# models, translation tables); skip individual files larger than this
# and stop appending once the aggregate exceeds the total cap. Sized
# generously vs. anything a Firebase config could plausibly hide in.
_MAX_RESOURCE_FILE_BYTES = 5 * 1024 * 1024
_MAX_TOTAL_RESOURCE_BYTES = 50 * 1024 * 1024

# Resource extensions worth scanning for Firebase regex matches. Binary
# formats (images, fonts, audio) and bytecode (.dex, .arsc, .so) are
# excluded — those don't carry literal Firebase URLs / API keys.
_RESOURCE_TEXT_EXTS = (".json", ".xml", ".txt", ".properties", ".cfg", ".conf", ".js", ".html")

# Where in the .apk we look for resource files. Anything outside these
# trees (META-INF, classes*.dex, resources.arsc, lib/) is skipped.
_RESOURCE_PREFIXES = ("assets/", "res/raw")


class DexExtractor:
    """Stateless container of Android .apk DEX-pool parsing helpers.

    Mirrors :class:`IpaExtractor`'s shape so :class:`FirebaseExtractor`
    can call it as a drop-in source of synthetic ``<resources>`` blobs.
    """

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    # Per-path cache of (grouped_strings, flat_deduped_strings) so the
    # regex-pipeline walk and the PEM-pairing walk share one DEX parse.
    # Keyed by resolved path string; cleared via :meth:`clear_cache` once
    # the orchestrator is done with a given APK.
    _cache: Dict[str, Tuple[List[List[str]], List[str], List[Tuple[str, str]]]] = {}

    @classmethod
    def clear_cache(cls, apk_path: Optional[Path] = None) -> None:
        """Drop cached DEX strings for ``apk_path`` (or everything)."""
        if apk_path is None:
            cls._cache.clear()
            return
        cls._cache.pop(str(apk_path), None)

    @classmethod
    def _walk_dex(
        cls,
        apk_path: Path,
        on_dex: Optional[Callable[[], None]] = None,
    ) -> Tuple[List[List[str]], List[str], List[Tuple[str, str]]]:
        """Walk every ``classes*.dex`` once and return three views.

        Returns ``(grouped, flat, invoke_args)``:

        * ``grouped`` — per-DEX string-pool lists (PEM↔email pairing)
        * ``flat`` — deduped union of every string (regex pipeline)
        * ``invoke_args`` — string literals passed as the first arg to
          one of :data:`_INVOKE_TARGETS`, recovered by walking
          ``invoke-*`` opcodes and back-resolving the source register
          to its most recent ``const-string``. These would otherwise be
          invisible to a pure string-pool scan because the call site
          (``...collection(``) and the literal (``"users"``) live in
          separate DEX tables.

        Result is cached per path so the second caller is free.
        """
        key = str(apk_path)
        cached = cls._cache.get(key)
        if cached is not None:
            if on_dex is not None:
                for _ in cached[0]:
                    try:
                        on_dex()
                    except Exception:
                        pass
            return cached

        apk = cls._load_apk(apk_path)
        if apk is None:
            empty: Tuple[List[List[str]], List[str], List[Tuple[str, str]]] = ([], [], [])
            cls._cache[key] = empty
            return empty

        groups: List[List[str]] = []
        seen: set = set()
        flat: List[str] = []
        invoke_args: List[Tuple[str, str]] = []
        invoke_seen: set = set()
        try:
            for dex_bytes in apk.get_all_dex():
                try:
                    dex = DEX(dex_bytes)
                    group = [s for s in dex.get_strings() if s]
                except Exception:
                    group = []
                groups.append(group)
                for s in group:
                    if s in seen:
                        continue
                    seen.add(s)
                    flat.append(s)

                # Bytecode walk for tracked invoke targets.
                try:
                    for em in dex.get_encoded_methods():
                        try:
                            code = em.get_code()
                            if not code:
                                continue
                            regs: Dict[str, str] = {}
                            for ins in code.get_bc().get_instructions():
                                name = ins.get_name()
                                op = ins.get_output()
                                if name.startswith("const-string"):
                                    m = _CONST_STRING_RE.match(op)
                                    if m:
                                        regs[m.group(1)] = m.group(2)
                                elif "invoke" in name:
                                    matched = next(
                                        (t for t in _INVOKE_TARGETS if t in op),
                                        None,
                                    )
                                    if matched is None:
                                        continue
                                    # Method name sits between ``;->`` and ``(``.
                                    method = matched.rsplit(";->", 1)[1].rstrip("(")
                                    head = op.split(", L", 1)[0]
                                    rs = [r.strip() for r in head.split(",")]
                                    if len(rs) >= 2:
                                        arg = regs.get(rs[1])
                                        key2 = (method, arg)
                                        if arg and key2 not in invoke_seen:
                                            invoke_seen.add(key2)
                                            invoke_args.append((method, arg))
                        except Exception:
                            continue
                except Exception:
                    pass

                if on_dex is not None:
                    try:
                        on_dex()
                    except Exception:
                        pass
        except Exception:
            pass

        cls._cache[key] = (groups, flat, invoke_args)
        return groups, flat, invoke_args

    @classmethod
    def count_dex_files(cls, apk_path: Path) -> int:
        """Return how many ``classes*.dex`` files this APK ships.

        Used by callers (e.g. the single-file orchestrator) to
        pre-size a progress bar before driving extraction.
        """
        apk = cls._load_apk(apk_path)
        if apk is None:
            return 0
        try:
            # ``get_dex_names()`` returns a filter object on recent
            # androguard versions, so materialize before counting.
            return sum(1 for _ in apk.get_dex_names())
        except Exception:
            return 0

    @classmethod
    def build_strings_blob(
        cls,
        apk_path: Path,
        on_dex: Optional[Callable[[], None]] = None,
    ) -> str:
        """Return a synthetic ``<resources>`` document containing every
        DEX string-pool entry plus every text resource bundled in the
        APK's ``assets/`` and ``res/raw/`` trees.

        Wrapped in the same ``<string name="...">value</string>`` shape
        the APK strings.xml path produces, so the existing Firebase
        regex loop in :class:`FirebaseExtractor` matches without
        modification.

        ``on_dex`` is an optional zero-arg callback invoked once per
        ``classes*.dex`` after its strings have been read, so callers
        can drive a per-DEX progress bar.
        """
        lines: List[str] = []
        found_any = False

        groups, flat, invoke_args = cls._walk_dex(apk_path, on_dex=on_dex)
        for value in flat:
            lines.append(f'<string name="dex_string">{value}</string>')
            found_any = True

        # Synthesize source-shaped literals for bytecode-recovered call
        # arguments (e.g. ``collection("users")``) so the existing
        # Firestore_Collection_Name regex matches without modification.
        for method, arg in invoke_args:
            # Only ``collection(...)`` is currently surfaced as a
            # finding by the regex pipeline. ``document(...)`` args are
            # tracked but not synthesized — they're document paths, not
            # collection names, and would mislabel if emitted as
            # ``collection("...")``.
            if method != "collection":
                continue
            lines.append(f'<string name="dex_invoke">collection("{arg}")</string>')
            found_any = True

        resource_fragment = cls._extract_resource_files(apk_path)
        if resource_fragment:
            lines.append(resource_fragment)
            found_any = True

        if not found_any:
            return ""
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # DEX string pool
    # ------------------------------------------------------------------

    @staticmethod
    def _load_apk(apk_path: Path) -> Optional[APK]:
        try:
            return APK(str(apk_path))
        except Exception:
            return None

    @classmethod
    def _iter_dex_strings_grouped(cls, apk_path: Path) -> List[List[str]]:
        """Return per-DEX string-pool lists (one inner list per ``classes*.dex``)."""
        return cls._walk_dex(apk_path)[0]

    # ------------------------------------------------------------------
    # Resource scan
    # ------------------------------------------------------------------

    @classmethod
    def _extract_resource_files(cls, apk_path: Path) -> str:
        """Walk ``assets/`` and ``res/raw/`` for text resources and emit
        a synthetic strings.xml fragment.

        This compensates for what the DEX string pool can't see:
        Firebase URLs / config blobs that ship as ``firebase.json``,
        ``rtdb_config.xml``, etc., rather than as Java string literals.
        """
        lines: List[str] = []
        total_bytes = 0
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    name = info.filename
                    lower = name.lower()
                    if not any(lower.startswith(p) for p in _RESOURCE_PREFIXES):
                        continue
                    if not lower.endswith(_RESOURCE_TEXT_EXTS):
                        continue
                    if info.file_size > _MAX_RESOURCE_FILE_BYTES:
                        continue
                    if total_bytes + info.file_size > _MAX_TOTAL_RESOURCE_BYTES:
                        break
                    try:
                        with zf.open(info) as fp:
                            raw = fp.read()
                    except Exception:
                        continue
                    total_bytes += len(raw)
                    try:
                        text = raw.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    # Wrap as one synthetic string per file. The
                    # downstream regex loop runs across the value
                    # contents directly, so a single wrapper element
                    # per file is enough — the regex doesn't care
                    # about XML structure, only the joined text body.
                    lines.append(f'<string name="apk_resource">{text}</string>')
        except (zipfile.BadZipFile, OSError):
            return ""
        except Exception:
            return ""

        if not lines:
            return ""
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Hardcoded PEM private keys
    # ------------------------------------------------------------------

    @classmethod
    def extract_hardcoded_pem_keys(
        cls, apk_path: Path,
    ) -> List[Tuple[str, Optional[str]]]:
        """Recover full PEM private-key blocks hardcoded in the DEX
        string pool, optionally paired with a ``gserviceaccount.com``
        email if both appear in the same DEX file.

        Returns a list of ``(pem, email_or_none)`` tuples.
        """
        results: List[Tuple[str, Optional[str]]] = []
        seen_pems: set = set()
        for dex_strings in cls._iter_dex_strings_grouped(apk_path):
            pems_in_dex: List[str] = []
            emails_in_dex: List[str] = []
            for s in dex_strings:
                # PEM literals come out of the DEX pool with embedded
                # newlines (Java compile-time concat collapses
                # ``"...\n" + "..."`` into one entry).
                for m in PEM_PRIVATE_KEY_RE_STR.finditer(s):
                    pems_in_dex.append(m.group(0))
                for m in GSERVICEACCOUNT_EMAIL_RE.finditer(s):
                    emails_in_dex.append(m.group(0))

            # Pair only when there is exactly one of each in the same
            # DEX. Anything else is too ambiguous — emit each PEM
            # standalone and let the operator investigate.
            paired_email: Optional[str] = None
            if len(pems_in_dex) == 1 and len(emails_in_dex) == 1:
                paired_email = emails_in_dex[0]

            for pem in pems_in_dex:
                if pem in seen_pems:
                    continue
                seen_pems.add(pem)
                results.append((pem, paired_email if len(pems_in_dex) == 1 else None))
        return results
