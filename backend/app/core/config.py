"""Local prototype runtime configuration."""

import os
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8000
API_HOSTS = frozenset({"127.0.0.1:8000", "localhost:8000"})
# No frontend exists yet; these are the explicit localhost origins for the planned
# Vite development server, whether opened using localhost or its IPv4 loopback IP.
FRONTEND_ORIGINS = frozenset({"http://localhost:5173", "http://127.0.0.1:5173"})
# Current key APIs exchange only small JSON records (SPKI PEM is capped at
# 10,000 characters); 64 KiB bounds parsing and buffering with room for JSON.
MAX_API_BODY_BYTES = 64 * 1024
# The request-security middleware counts and forwards file-exchange body chunks
# without retaining a complete body. Multipart framing and form fields have a
# separate bound in the streaming parser.
FILE_EXCHANGE_MULTIPART_OVERHEAD_BYTES = 64 * 1024

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def runtime_data_root() -> Path:
    """Return the per-user data directory and reject repository-local paths."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA is required for runtime data")
    root = (Path(local_app_data) / "QuantumShield").resolve()
    if root == REPOSITORY_ROOT or REPOSITORY_ROOT in root.parents:
        raise RuntimeError("runtime data directory must be outside the repository")
    return root


def key_data_dir() -> Path:
    return runtime_data_root() / "keys"


def trust_data_dir() -> Path:
    return runtime_data_root() / "trust"
