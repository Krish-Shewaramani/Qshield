"""Export local public keys as a contact bundle, and validate incoming bundles.

Neither endpoint touches private keys or the trusted-key store. A previewed
bundle is always reported as untrusted and is not persisted.
"""

from fastapi import APIRouter, Depends, HTTPException

from backend.app.api.dependencies import get_key_service
from backend.app.api.schemas.keys import (
    ContactBundleExportRequest,
    ContactBundleKeyPreview,
    ContactBundlePreviewRequest,
    ContactBundlePreviewResponse,
)
from backend.app.key_management.contact_bundle import (
    ContactBundleError,
    build_bundle,
    parse_bundle,
)
from backend.app.key_management.errors import KeyManagementError, KeyNotFoundError
from backend.app.key_management.key_service import KeyService

router = APIRouter(prefix="/contact-bundles", tags=["contact bundles"])


@router.post("/export")
def export_contact_bundle(
    request: ContactBundleExportRequest,
    service: KeyService = Depends(get_key_service),
) -> dict[str, object]:
    if len(set(request.key_ids)) != len(request.key_ids):
        raise HTTPException(status_code=400, detail="each key may appear only once")
    try:
        records = [service.get_public_record(identifier) for identifier in request.key_ids]
        return build_bundle(request.label, records)
    except KeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail="selected key was not found") from exc
    except ContactBundleError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyManagementError as exc:
        raise HTTPException(status_code=400, detail="key record is invalid") from exc


@router.post("/preview", response_model=ContactBundlePreviewResponse)
def preview_contact_bundle(request: ContactBundlePreviewRequest) -> ContactBundlePreviewResponse:
    try:
        preview = parse_bundle(request.bundle_json)
    except ContactBundleError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ContactBundlePreviewResponse(
        label=preview.label,
        keys=[
            ContactBundleKeyPreview(
                purpose=entry.purpose,
                algorithm=entry.algorithm,
                key_id=entry.key_id,
                public_key_pem=entry.public_key_pem,
            )
            for entry in preview.entries
        ],
        trusted=False,
    )
