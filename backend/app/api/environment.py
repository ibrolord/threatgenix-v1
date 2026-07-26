from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Header, UploadFile
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.environment_evidence import (
    EnvironmentEvidenceResponse,
    GitHubRepositoryImportRequest,
    GitHubRepositoryRefreshRequest,
    RepositoryConnection,
    RepositoryEvidence,
)
from app.services.auth import get_current_user
from app.services.environment_evidence import (
    CLOUD_SCAN_EVIDENCE_MAX_BYTES,
    IAC_EVIDENCE_MAX_BYTES,
    REPOSITORY_EVIDENCE_MAX_BYTES,
    EvidenceValidationError,
    build_github_repository_reference,
    compose_environment_context_summary,
    fetch_github_repository_archive,
    parse_cloud_scan_evidence,
    parse_iac_evidence,
    parse_repository_evidence,
)
from app.services.model_collaboration import require_model_permission
from app.services.threat_model import get_threat_model

router = APIRouter(
    prefix="/api/threat-models/{threat_model_id}/environment",
    tags=["environment-evidence"],
)


async def _read_bounded_upload(
    file: UploadFile,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"{label} exceeds the {max_bytes}-byte upload limit.",
        )
    return content


async def _load_owned_threat_model(
    db: AsyncSession,
    threat_model_id: UUID,
    current_user: User,
    permission: str = "write",
):
    threat_model = await get_threat_model(db, threat_model_id)
    return require_model_permission(threat_model, current_user, permission)  # type: ignore[arg-type]


def _response_for_model(threat_model) -> EnvironmentEvidenceResponse:
    return EnvironmentEvidenceResponse(
        repository_evidence=threat_model.repository_evidence,
        cloud_scan_evidence=threat_model.cloud_scan_evidence,
        iac_evidence=threat_model.iac_evidence,
        environment_context_summary=threat_model.environment_context_summary,
    )


def _store_repository_evidence(threat_model, repository_evidence: RepositoryEvidence) -> None:
    threat_model.repository_evidence = repository_evidence.model_dump(mode="json")
    threat_model.environment_context_summary = compose_environment_context_summary(
        threat_model.repository_evidence,
        threat_model.cloud_scan_evidence,
        threat_model.iac_evidence,
    )


def _github_connection_for_import(
    data: GitHubRepositoryImportRequest,
    *,
    repository_slug: str,
    resolved_ref: str | None,
) -> RepositoryConnection:
    now = datetime.now(timezone.utc)
    return RepositoryConnection(
        provider="github",
        repository=repository_slug,
        transport=data.transport,
        ref=resolved_ref,
        reference=(data.reference or "").strip() or None,
        connected_at=now,
        last_synced_at=now,
    )


def _load_github_connection(threat_model) -> RepositoryConnection:
    if not threat_model.repository_evidence:
        raise HTTPException(
            status_code=400,
            detail="No GitHub repository connection is saved for this threat model.",
        )

    try:
        repository_evidence = RepositoryEvidence.model_validate(threat_model.repository_evidence)
    except ValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail="Saved repository evidence cannot be refreshed because its GitHub connection metadata is invalid.",
        ) from exc
    connection = repository_evidence.connection
    if connection is None or connection.provider != "github":
        raise HTTPException(
            status_code=400,
            detail="No GitHub repository connection is saved for this threat model.",
        )
    return connection


@router.get("", response_model=EnvironmentEvidenceResponse)
async def get_environment_evidence(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnvironmentEvidenceResponse:
    threat_model = await _load_owned_threat_model(
        db,
        threat_model_id,
        current_user,
        permission="read",
    )
    return _response_for_model(threat_model)


@router.post("/repository", response_model=EnvironmentEvidenceResponse)
async def upload_repository_evidence(
    threat_model_id: UUID,
    file: UploadFile = File(...),
    reference: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnvironmentEvidenceResponse:
    threat_model = await _load_owned_threat_model(db, threat_model_id, current_user)
    content = await _read_bounded_upload(
        file,
        max_bytes=REPOSITORY_EVIDENCE_MAX_BYTES,
        label="Repository evidence",
    )
    try:
        repository_evidence = parse_repository_evidence(
            content,
            file.filename or "repository-evidence",
            reference=reference,
        )
    except EvidenceValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    _store_repository_evidence(threat_model, repository_evidence)
    await db.commit()
    await db.refresh(threat_model)
    return _response_for_model(threat_model)


@router.post("/repository/github", response_model=EnvironmentEvidenceResponse)
async def import_repository_evidence_from_github(
    threat_model_id: UUID,
    data: GitHubRepositoryImportRequest,
    github_token: str | None = Header(default=None, alias="X-GitHub-Token"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnvironmentEvidenceResponse:
    threat_model = await _load_owned_threat_model(db, threat_model_id, current_user)
    try:
        archive_bytes, repository_slug, resolved_ref = await fetch_github_repository_archive(
            data.repository,
            ref=data.ref,
            transport=data.transport,
            github_token=github_token,
            ssh_private_key=data.ssh_private_key,
        )
        repository_evidence = parse_repository_evidence(
            archive_bytes,
            f"{repository_slug}.zip",
            reference=build_github_repository_reference(
                repository_slug,
                resolved_ref,
                data.reference,
            ),
        )
        repository_evidence.connection = _github_connection_for_import(
            data,
            repository_slug=repository_slug,
            resolved_ref=resolved_ref,
        )
    except EvidenceValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    _store_repository_evidence(threat_model, repository_evidence)
    await db.commit()
    await db.refresh(threat_model)
    return _response_for_model(threat_model)


@router.post("/repository/github/refresh", response_model=EnvironmentEvidenceResponse)
async def refresh_repository_evidence_from_github(
    threat_model_id: UUID,
    data: GitHubRepositoryRefreshRequest | None = None,
    github_token: str | None = Header(default=None, alias="X-GitHub-Token"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnvironmentEvidenceResponse:
    threat_model = await _load_owned_threat_model(db, threat_model_id, current_user)
    connection = _load_github_connection(threat_model)
    try:
        archive_bytes, repository_slug, resolved_ref = await fetch_github_repository_archive(
            connection.repository,
            ref=connection.ref,
            transport=connection.transport,
            github_token=github_token,
            ssh_private_key=data.ssh_private_key if data else None,
        )
        repository_evidence = parse_repository_evidence(
            archive_bytes,
            f"{repository_slug}.zip",
            reference=build_github_repository_reference(
                repository_slug,
                resolved_ref,
                connection.reference,
            ),
        )
        repository_evidence.connection = RepositoryConnection(
            provider="github",
            repository=repository_slug,
            transport=connection.transport,
            ref=resolved_ref,
            reference=connection.reference,
            connected_at=connection.connected_at,
            last_synced_at=datetime.now(timezone.utc),
        )
    except EvidenceValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    _store_repository_evidence(threat_model, repository_evidence)
    await db.commit()
    await db.refresh(threat_model)
    return _response_for_model(threat_model)


@router.delete("/repository", response_model=EnvironmentEvidenceResponse)
async def clear_repository_evidence(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnvironmentEvidenceResponse:
    threat_model = await _load_owned_threat_model(db, threat_model_id, current_user)
    threat_model.repository_evidence = None
    threat_model.environment_context_summary = compose_environment_context_summary(
        None,
        threat_model.cloud_scan_evidence,
        threat_model.iac_evidence,
    )
    await db.commit()
    await db.refresh(threat_model)
    return _response_for_model(threat_model)


@router.post("/cloud-scan", response_model=EnvironmentEvidenceResponse)
async def upload_cloud_scan_evidence(
    threat_model_id: UUID,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnvironmentEvidenceResponse:
    threat_model = await _load_owned_threat_model(db, threat_model_id, current_user)
    content = await _read_bounded_upload(
        file,
        max_bytes=CLOUD_SCAN_EVIDENCE_MAX_BYTES,
        label="Cloud scan evidence",
    )
    try:
        cloud_scan_evidence = parse_cloud_scan_evidence(
            content,
            file.filename or "cloud-scan-evidence",
        )
    except EvidenceValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    threat_model.cloud_scan_evidence = cloud_scan_evidence.model_dump(mode="json")
    threat_model.environment_context_summary = compose_environment_context_summary(
        threat_model.repository_evidence,
        threat_model.cloud_scan_evidence,
        threat_model.iac_evidence,
    )
    await db.commit()
    await db.refresh(threat_model)
    return _response_for_model(threat_model)


@router.delete("/cloud-scan", response_model=EnvironmentEvidenceResponse)
async def clear_cloud_scan_evidence(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnvironmentEvidenceResponse:
    threat_model = await _load_owned_threat_model(db, threat_model_id, current_user)
    threat_model.cloud_scan_evidence = None
    threat_model.environment_context_summary = compose_environment_context_summary(
        threat_model.repository_evidence,
        None,
        threat_model.iac_evidence,
    )
    await db.commit()
    await db.refresh(threat_model)
    return _response_for_model(threat_model)
@router.post("/iac", response_model=EnvironmentEvidenceResponse)
async def upload_iac_evidence(
    threat_model_id: UUID,
    file: UploadFile = File(...),
    reference: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnvironmentEvidenceResponse:
    threat_model = await _load_owned_threat_model(db, threat_model_id, current_user)
    content = await _read_bounded_upload(
        file,
        max_bytes=IAC_EVIDENCE_MAX_BYTES,
        label="IaC evidence",
    )
    try:
        iac_evidence = parse_iac_evidence(
            content,
            file.filename or "iac-evidence",
            reference=reference,
        )
    except EvidenceValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    threat_model.iac_evidence = iac_evidence.model_dump(mode="json")
    threat_model.environment_context_summary = compose_environment_context_summary(
        threat_model.repository_evidence,
        threat_model.cloud_scan_evidence,
        threat_model.iac_evidence,
    )
    await db.commit()
    await db.refresh(threat_model)
    return _response_for_model(threat_model)


@router.delete("/iac", response_model=EnvironmentEvidenceResponse)
async def clear_iac_evidence(
    threat_model_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EnvironmentEvidenceResponse:
    threat_model = await _load_owned_threat_model(db, threat_model_id, current_user)
    threat_model.iac_evidence = None
    threat_model.environment_context_summary = compose_environment_context_summary(
        threat_model.repository_evidence,
        threat_model.cloud_scan_evidence,
        None,
    )
    await db.commit()
    await db.refresh(threat_model)
    return _response_for_model(threat_model)
