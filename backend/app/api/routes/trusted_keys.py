"""Preview, explicitly trust, list, and remove imported public keys."""

from fastapi import APIRouter, Depends, HTTPException, Response, status

from backend.app.api.dependencies import get_trust_store
from backend.app.api.schemas.keys import (
    PublicKeyPreviewRequest,
    PublicKeyPreviewResponse,
    TrustedKeyImportRequest,
    TrustedKeyRecordResponse,
)
from backend.app.key_management.errors import (
    FingerprintMismatchError,
    KeyNotFoundError,
    KeyRecordError,
    PublicKeyImportError,
    TrustConfirmationError,
)
from backend.app.key_management.models import TrustedKeyRecord
from backend.app.key_management.trust_store import TrustStore

router = APIRouter(prefix="/trusted-keys", tags=["trusted keys"])


def _response(record: TrustedKeyRecord) -> TrustedKeyRecordResponse:
    return TrustedKeyRecordResponse(
        algorithm=record.algorithm,
        key_id=record.key_id,
        label=record.label,
        public_key_pem=record.public_key_pem,
        trusted=record.trusted,
    )


@router.post("/preview", response_model=PublicKeyPreviewResponse)
def preview_public_key(
    request: PublicKeyPreviewRequest,
    store: TrustStore = Depends(get_trust_store),
) -> PublicKeyPreviewResponse:
    try:
        candidate = store.preview(request.public_key_pem.encode("ascii"))
    except (UnicodeEncodeError, PublicKeyImportError) as exc:
        raise HTTPException(status_code=400, detail="invalid or unsupported public key") from exc
    return PublicKeyPreviewResponse(
        algorithm=candidate.algorithm,
        key_id=candidate.key_id,
        public_key_pem=candidate.public_key_pem,
    )


@router.post("", response_model=TrustedKeyRecordResponse, status_code=status.HTTP_201_CREATED)
def import_trusted_key(
    request: TrustedKeyImportRequest,
    store: TrustStore = Depends(get_trust_store),
) -> TrustedKeyRecordResponse:
    try:
        record = store.add(
            request.public_key_pem.encode("ascii"),
            request.label,
            request.confirmed_fingerprint,
        )
    except (UnicodeEncodeError, PublicKeyImportError) as exc:
        raise HTTPException(status_code=400, detail="invalid or unsupported public key") from exc
    except TrustConfirmationError as exc:
        raise HTTPException(status_code=400, detail="matching fingerprint confirmation is required") from exc
    return _response(record)


@router.get("", response_model=list[TrustedKeyRecordResponse])
def list_trusted_keys(store: TrustStore = Depends(get_trust_store)) -> list[TrustedKeyRecordResponse]:
    try:
        return [_response(record) for record in store.list_records()]
    except (KeyRecordError, FingerprintMismatchError) as exc:
        raise HTTPException(status_code=500, detail="trust store record is invalid") from exc


@router.delete("/{identifier}", status_code=status.HTTP_204_NO_CONTENT)
def delete_trusted_key(identifier: str, store: TrustStore = Depends(get_trust_store)) -> Response:
    try:
        store.delete(identifier)
    except KeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail="trusted key not found") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
