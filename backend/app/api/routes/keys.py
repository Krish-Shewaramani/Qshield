"""Key generation and public-key import/export routes."""

from fastapi import APIRouter, Depends, HTTPException, Response, status

from backend.app.api.dependencies import get_key_service
from backend.app.api.schemas.keys import GenerateKeyRequest, KeyRecordResponse
from backend.app.key_management.errors import (
    KeyManagementError,
    KeyNotFoundError,
)
from backend.app.key_management.key_service import KeyService
from backend.app.key_management.models import KeyRecord

router = APIRouter(prefix="/keys", tags=["keys"])


def _response(record: KeyRecord) -> KeyRecordResponse:
    return KeyRecordResponse(
        algorithm=record.algorithm,
        key_id=record.key_id,
        label=record.label,
        public_key_pem=record.public_key_pem,
    )


@router.post("/kem", response_model=KeyRecordResponse, status_code=status.HTTP_201_CREATED)
def generate_kem_key(
    request: GenerateKeyRequest,
    service: KeyService = Depends(get_key_service),
) -> KeyRecordResponse:
    return _response(service.generate_kem_key(request.label, request.passphrase))


@router.post("/sig", response_model=KeyRecordResponse, status_code=status.HTTP_201_CREATED)
def generate_signature_key(
    request: GenerateKeyRequest,
    service: KeyService = Depends(get_key_service),
) -> KeyRecordResponse:
    return _response(service.generate_signature_key(request.label, request.passphrase))


@router.get("", response_model=list[KeyRecordResponse])
def list_keys(service: KeyService = Depends(get_key_service)) -> list[KeyRecordResponse]:
    return [_response(record) for record in service.list_keys()]


@router.get("/{identifier}/public")
def export_public_key(
    identifier: str,
    service: KeyService = Depends(get_key_service),
) -> Response:
    try:
        pem = service.export_public_key(identifier)
    except KeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail="key not found") from exc
    except KeyManagementError as exc:
        raise HTTPException(status_code=400, detail="key record is invalid") from exc
    return Response(content=pem, media_type="application/x-pem-file")


@router.delete("/{identifier}", status_code=status.HTTP_204_NO_CONTENT)
def delete_key(identifier: str, service: KeyService = Depends(get_key_service)) -> Response:
    try:
        service.delete_key(identifier)
    except KeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail="key not found") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
