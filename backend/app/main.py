"""Minimal FastAPI application for the Phase 3 backend foundation."""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.routes.health import router as health_router
from backend.app.api.routes.file_exchange import router as file_exchange_router
from backend.app.api.routes.keys import router as keys_router
from backend.app.api.routes.trusted_keys import router as trusted_keys_router
from backend.app.core.crypto_self_check import run_crypto_self_check
from backend.app.core.config import FRONTEND_ORIGINS
from backend.app.core.request_security import LocalAPIRequestSecurityMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.crypto_algorithms = run_crypto_self_check()
    yield


app = FastAPI(title="QuantumShield Local Backend", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(FRONTEND_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
    expose_headers=["Content-Disposition"],
)
app.add_middleware(LocalAPIRequestSecurityMiddleware)


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Pydantic's default includes the submitted value, which could be a passphrase.
    errors = [
        {"loc": error.get("loc", ()), "msg": error.get("msg", "invalid value"), "type": error.get("type", "value_error")}
        for error in exc.errors()
    ]
    return JSONResponse({"detail": errors}, status_code=422)


app.include_router(health_router, prefix="/api")
app.include_router(file_exchange_router, prefix="/api")
app.include_router(keys_router, prefix="/api")
app.include_router(trusted_keys_router, prefix="/api")
