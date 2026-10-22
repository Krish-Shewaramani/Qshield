"""Backend health endpoint."""

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health")
def health(request: Request) -> dict[str, object]:
    return {
        "status": "ok",
        "cryptography": "ready",
        "algorithms": list(request.app.state.crypto_algorithms),
    }
