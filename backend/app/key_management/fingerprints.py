"""Protocol key identifiers derived from approved public keys."""

import hashlib

from backend.app.crypto import key_serialization


def key_id(public_key: object) -> str:
    algorithm = key_serialization.algorithm_for_key(public_key).encode("ascii")
    material = algorithm + b"\x00" + key_serialization.raw_public_bytes(public_key)
    return hashlib.sha256(material).hexdigest()
