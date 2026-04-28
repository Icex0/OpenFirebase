from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..scans.models import Finding, Scan, ScanProject


def _extracted_items_for(project_payload: dict[str, Any]) -> dict[str, Any]:
    nested = project_payload.get("extracted_items")
    if not isinstance(nested, dict):
        return {}
    return {k: v for k, v in nested.items() if isinstance(v, list) and v}


def import_extracted_projects(*, scan: Scan, doc: dict[str, Any]) -> None:
    """Sync projects/package_names/extracted_items from an extraction-only doc.

    Called mid-run after phase 1 so the UI can show projects before findings
    exist. Idempotent: clears prior projects on this scan first (extraction
    is always run fresh before scanning).
    """
    scan.schema_version = doc.get("schema_version") or scan.schema_version
    scan.tool_version = doc.get("tool_version") or scan.tool_version

    scan.projects.clear()
    for project_payload in doc.get("projects", []):
        scan.projects.append(
            ScanProject(
                project_id=project_payload["project_id"],
                package_names=project_payload.get("package_names"),
                extracted_items=_extracted_items_for(project_payload),
            )
        )


async def import_scan_document(
    session: AsyncSession, *, scan: Scan, doc: dict[str, Any]
) -> None:
    """Persist the final scan document, merging findings into already-persisted
    projects (created in phase 1 by :func:`import_extracted_projects`).

    The raw document is retained on ``Scan.raw_document`` for forensic / re-export use.
    """
    scan.schema_version = doc.get("schema_version") or scan.schema_version
    scan.tool_version = doc.get("tool_version") or scan.tool_version
    scan.raw_document = doc

    existing: dict[str, ScanProject] = {p.project_id: p for p in scan.projects}

    for project_payload in doc.get("projects", []):
        pid = project_payload["project_id"]
        project = existing.get(pid)
        if project is None:
            project = ScanProject(
                scan=scan,
                project_id=pid,
                package_names=project_payload.get("package_names"),
                extracted_items=_extracted_items_for(project_payload),
            )
            session.add(project)
            existing[pid] = project
        else:
            # Extraction already populated these — keep them in sync.
            project.package_names = project_payload.get("package_names") or project.package_names
            project.extracted_items = (
                _extracted_items_for(project_payload) or project.extracted_items
            )

        # Wipe any findings from a prior attempt on the same project, then reinsert.
        project.findings.clear()
        for finding_payload in project_payload.get("findings", []):
            unauth = finding_payload["unauth"]
            auth = finding_payload.get("auth")
            project.findings.append(
                Finding(
                    service=finding_payload["service"],
                    probe=finding_payload["probe"],
                    url=finding_payload["url"],
                    unauth_status=str(unauth["status"]),
                    unauth_security=unauth["security"],
                    unauth_verdict=unauth["verdict"],
                    unauth_message=unauth.get("message"),
                    auth_status=str(auth["status"]) if auth else None,
                    auth_security=auth["security"] if auth else None,
                    auth_verdict=auth["verdict"] if auth else None,
                    auth_message=(auth or {}).get("message"),
                    resource=finding_payload.get("resource"),
                    raw=finding_payload,
                )
            )
