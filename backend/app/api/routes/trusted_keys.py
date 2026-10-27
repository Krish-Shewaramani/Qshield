"""Preview, explicitly trust, list, and remove imported public keys."""

from fastapi import APIRouter, Depends, HTTPException, Response, status

from backend.app.api.dependencies import get_contact_service, get_trust_store
from backend.app.api.routes.contacts import contact_http_error
from backend.app.api.schemas.keys import (
    PublicKeyPreviewRequest,
    PublicKeyPreviewResponse,
    TrustedKeyImportRequest,
    TrustedKeyReauthorizeRequest,
    TrustedKeyRecordResponse,
)
from backend.app.key_management.errors import (
    FingerprintMismatchError,
    KeyNotFoundError,
    KeyRecordError,
    PublicKeyImportError,
    TrustConfirmationError,
)
from backend.app.key_management.contacts import (
    ContactError,
    ContactManagedKeyError,
    ContactService,
    TrustLink,
)
from backend.app.key_management.models import TrustedKeyRecord
from backend.app.key_management.trust_store import TrustStore

router = APIRouter(prefix="/trusted-keys", tags=["trusted keys"])


def _response(record: TrustedKeyRecord, link: TrustLink | None = None) -> TrustedKeyRecordResponse:
    return TrustedKeyRecordResponse(
        algorithm=record.algorithm,
        key_id=record.key_id,
        label=record.label,
        public_key_pem=record.public_key_pem,
        trusted=record.trusted,
        usage=record.usage,
        contact_id=link.contact_id if link else None,
        contact_label=link.contact_label if link else None,
        contact_key_state=link.key_state if link else None,
        trust_origin=link.trust_origin if link else None,
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
    contacts: ContactService = Depends(get_contact_service),
) -> TrustedKeyRecordResponse:
    try:
        # Refuses keys a contact manages, so this cannot widen a retired contact key's trust.
        record = contacts.add_standalone_trust(
            request.public_key_pem.encode("ascii"),
            request.label,
            request.confirmed_fingerprint,
        )
    except (UnicodeEncodeError, PublicKeyImportError) as exc:
        raise HTTPException(status_code=400, detail="invalid or unsupported public key") from exc
    except TrustConfirmationError as exc:
        raise HTTPException(status_code=400, detail="matching fingerprint confirmation is required") from exc
    except ContactError as exc:
        raise contact_http_error(exc) from exc
    return _response(record)


@router.get("", response_model=list[TrustedKeyRecordResponse])
def list_trusted_keys(
    store: TrustStore = Depends(get_trust_store),
    contacts: ContactService = Depends(get_contact_service),
) -> list[TrustedKeyRecordResponse]:
    # Contact annotations are display-only; a contact-store problem must not hide
    # the trust store that file exchange depends on.
    try:
        contacts.tighten_retired_keys()
        links = contacts.trust_links()
    except (ContactError, OSError):
        links = {}
    try:
        return [_response(record, links.get(record.key_id)) for record in store.list_records()]
    except (KeyRecordError, FingerprintMismatchError) as exc:
        raise HTTPException(status_code=500, detail="trust store record is invalid") from exc


@router.post("/{identifier}/reauthorize", response_model=TrustedKeyRecordResponse)
def reauthorize_trusted_key(
    identifier: str,
    request: TrustedKeyReauthorizeRequest,
    contacts: ContactService = Depends(get_contact_service),
) -> TrustedKeyRecordResponse:
    """Restore a suspended ML-KEM key after the user re-confirms its full fingerprint."""
    try:
        record = contacts.reauthorize_suspended_key(identifier, request.confirmed_fingerprint)
    except KeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail="trusted key not found") from exc
    except TrustConfirmationError as exc:
        raise HTTPException(status_code=400, detail="the typed fingerprint does not match this key") from exc
    except ContactError as exc:
        raise contact_http_error(exc) from exc
    except (KeyRecordError, FingerprintMismatchError, OSError, ValueError) as exc:
        raise HTTPException(status_code=500, detail="trust store record is invalid") from exc
    return _response(record)


@router.delete("/{identifier}", status_code=status.HTTP_204_NO_CONTENT)
def delete_trusted_key(
    identifier: str, contacts: ContactService = Depends(get_contact_service)
) -> Response:
    try:
        # Refuses contact-managed keys with a recovery path instead of desynchronizing a contact.
        contacts.remove_standalone_trust(identifier)
    except KeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail="trusted key not found") from exc
    except ContactManagedKeyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ContactError as exc:
        raise contact_http_error(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
