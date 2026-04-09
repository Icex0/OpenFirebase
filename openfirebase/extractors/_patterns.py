"""Shared regex constants used by multiple extractors.

Kept in its own module so :mod:`ipa_extractor` and :mod:`dex_extractor`
can both import the same compiled patterns without forming an import
cycle through :mod:`extractor`.
"""

from __future__ import annotations

import re

# Multi-line PEM private key block, used to recover keys hardcoded as
# string literals in compiled mobile binaries (Mach-O on iOS, the DEX
# string pool on Android). The body must contain at least 100 bytes of
# base64-ish content (RSA/EC keys are ~600–1700 chars in PEM form) to
# filter out the common false positive where a crypto library ships
# the BEGIN/END marker strings as adjacent constants with nothing real
# between them.
PEM_PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    rb"[A-Za-z0-9+/=\r\n\\ ]{100,}?"
    rb"-----END [A-Z ]*PRIVATE KEY-----",
)

# Same pattern, str form, for matching against decoded DEX strings
# (where literals appear with ``\n`` escapes already collapsed by the
# Java compiler into a single string-pool entry).
PEM_PRIVATE_KEY_RE_STR = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"[A-Za-z0-9+/=\r\n\\ ]{100,}?"
    r"-----END [A-Z ]*PRIVATE KEY-----",
)

# Service-account email pattern. Matches any address under
# ``*.gserviceaccount.com`` (covers ``@*.iam.gserviceaccount.com``,
# ``@appspot.gserviceaccount.com``, ``@system.gserviceaccount.com``).
GSERVICEACCOUNT_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.gserviceaccount\.com",
)
