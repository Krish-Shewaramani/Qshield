"""Contact pairing: analyze a bundle, stage untrusted keys, verify, confirm,
restore, reconcile, and delete.

Trust is written only through the existing TrustStore, so file exchange keeps
a single trust authority.
"""

from fastapi import APIRouter, Depends, HTTPException, Response, status

from backend.app.api.dependencies import get_contact_service
from backend.app.api.schemas.contacts import (
    ConfirmResponse,
    ContactKeyResponse,
    ContactResponse,
    ContactStorageResponse,
    KeyAssessmentResponse,
    MatchingContactResponse,
    PairingAnalysisResponse,
    PairingRequest,
    ReconcileResponse,
    ReinitializeStorageRequest,
    StageRequest,
    StageResponse,
    VerifyKeyRequest,
)
from backend.app.key_management.contact_bundle import ContactBundleError
from backend.app.key_management.contacts import (
    ContactConflictError,
    ContactError,
    ContactIncompleteError,
    ContactManagedKeyError,
    ContactNotFoundError,
    ContactRecordError,
    STORAGE_MISSING_MESSAGE,
    STORAGE_READY,
    ContactService,
    ContactView,
    PairingAnalysis,
)
from backend.app.key_management.errors import KeyManagementError, TrustConfirmationError

router = APIRouter(prefix="/contacts", tags=["contacts"])


def contact_response(view: ContactView) -> ContactResponse:
    record = view.record
    return ContactResponse(
        contact_id=record.contact_id,
        label=record.label,
        claimed_label=record.claimed_label,
        confirmed=record.confirmed,
        deletion_pending=record.deletion_pending,
        needs_reconcile=view.needs_reconcile,
        created_at=record.created_at,
        keys=[
            ContactKeyResponse(
                fingerprint=item.key.fingerprint,
                algorithm=item.key.algorithm,
                purpose=item.key.purpose,
                public_key_pem=item.key.public_key_pem,
                state=item.key.state,
                key_version=item.key.key_version,
                trust_origin=item.key.trust_origin,
                trust_status=item.trust_status,
                trust_usage=item.trust_usage,
                added_at=item.key.added_at,
                verified_at=item.key.verified_at,
                activated_at=item.key.activated_at,
                retired_at=item.key.retired_at,
                in_trusted_keys=item.in_trusted_keys,
                usable_for_exchange=item.usable_for_exchange,
                usable_for_encryption=item.usable_for_encryption,
                usable_for_verification=item.usable_for_verification,
            )
            for item in view.keys
        ],
    )


def _analysis(analysis: PairingAnalysis) -> PairingAnalysisResponse:
    return PairingAnalysisResponse(
        claimed_label=analysis.claimed_label,
        target_contact_id=analysis.target_contact_id,
        keys=[KeyAssessmentResponse(**item.__dict__) for item in analysis.keys],
        matching_contacts=[
            MatchingContactResponse(contact_id=contact_id, label=label)
            for contact_id, label in analysis.matching_contacts
        ],
        can_stage=analysis.can_stage,
    )


def contact_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ContactNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (ContactConflictError, ContactIncompleteError, ContactManagedKeyError)):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, ContactRecordError):
        return HTTPException(status_code=500, detail="a stored contact record is invalid")
    if isinstance(exc, TrustConfirmationError):
        return HTTPException(status_code=400, detail="the typed fingerprint does not match this key")
    if isinstance(exc, (ContactError, ContactBundleError)):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail="the contact operation could not be completed")


_HANDLED = (KeyManagementError, OSError, ValueError)


@router.get("", response_model=list[ContactResponse])
def list_contacts(service: ContactService = Depends(get_contact_service)) -> list[ContactResponse]:
    try:
        return [contact_response(view) for view in service.list_contacts()]
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc


@router.get("/storage", response_model=ContactStorageResponse)
def contact_storage(service: ContactService = Depends(get_contact_service)) -> ContactStorageResponse:
    # Reports state without creating a missing directory.
    state = service.storage_state
    return ContactStorageResponse(state=state, message=None if state == STORAGE_READY else STORAGE_MISSING_MESSAGE)


@router.post("/storage/reinitialize", response_model=ContactStorageResponse)
def reinitialize_contact_storage(
    request: ReinitializeStorageRequest, service: ContactService = Depends(get_contact_service)
) -> ContactStorageResponse:
    if request.acknowledge_lost_history is not True:
        raise HTTPException(status_code=400, detail="reinitializing requires acknowledging lost contact history")
    try:
        state, suspended = service.reinitialize_storage()
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc
    return ContactStorageResponse(state=state, message=None, suspended_encryption_keys=suspended)


@router.post("/pairing/analyze", response_model=PairingAnalysisResponse)
def analyze_bundle(
    request: PairingRequest, service: ContactService = Depends(get_contact_service)
) -> PairingAnalysisResponse:
    try:
        return _analysis(service.analyze(request.bundle_json, request.contact_id))
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc


@router.post("/pairing/stage", response_model=StageResponse)
def stage_bundle(
    request: StageRequest, service: ContactService = Depends(get_contact_service)
) -> StageResponse:
    try:
        analysis, view, staged = service.stage(request.bundle_json, request.contact_id, request.label)
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc
    return StageResponse(
        analysis=_analysis(analysis),
        contact=contact_response(view) if view is not None else None,
        staged_fingerprints=list(staged),
    )


@router.get("/{contact_id}", response_model=ContactResponse)
def get_contact(contact_id: str, service: ContactService = Depends(get_contact_service)) -> ContactResponse:
    try:
        return contact_response(service.get_contact(contact_id))
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc


@router.post("/{contact_id}/keys/{fingerprint}/verify", response_model=ContactResponse)
def verify_contact_key(
    contact_id: str,
    fingerprint: str,
    request: VerifyKeyRequest,
    service: ContactService = Depends(get_contact_service),
) -> ContactResponse:
    try:
        return contact_response(service.verify_key(contact_id, fingerprint, request.confirmed_fingerprint))
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc


@router.post("/{contact_id}/keys/{fingerprint}/restore", response_model=ContactResponse)
def restore_contact_key(
    contact_id: str,
    fingerprint: str,
    request: VerifyKeyRequest,
    service: ContactService = Depends(get_contact_service),
) -> ContactResponse:
    try:
        return contact_response(service.restore_key(contact_id, fingerprint, request.confirmed_fingerprint))
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc


@router.post("/{contact_id}/confirm", response_model=ConfirmResponse)
def confirm_contact(contact_id: str, service: ContactService = Depends(get_contact_service)) -> ConfirmResponse:
    try:
        result = service.confirm(contact_id)
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc
    return ConfirmResponse(
        contact=contact_response(result.view),
        activated=list(result.activated),
        retired=list(result.retired),
        activation_pending=list(result.activation_pending),
    )


@router.post("/{contact_id}/reconcile", response_model=ReconcileResponse)
def reconcile_contact(contact_id: str, service: ContactService = Depends(get_contact_service)) -> ReconcileResponse:
    try:
        view, failed = service.reconcile(contact_id)
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc
    return ReconcileResponse(contact=contact_response(view), failed=list(failed))


@router.delete("/{contact_id}/keys/{fingerprint}", status_code=status.HTTP_204_NO_CONTENT)
def discard_contact_key(
    contact_id: str, fingerprint: str, service: ContactService = Depends(get_contact_service)
) -> Response:
    try:
        service.discard_key(contact_id, fingerprint)
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{contact_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_contact(contact_id: str, service: ContactService = Depends(get_contact_service)) -> Response:
    try:
        service.delete_contact(contact_id)
    except _HANDLED as exc:
        raise contact_http_error(exc) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
