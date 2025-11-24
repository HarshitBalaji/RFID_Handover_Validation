# utils_crypto.py
#
# Passkey utilities:
# - Keys are loaded from PEM files.
# - Passkeys are ECDSA-signed payloads of the form:
#     token = base64url(payload_json) + "." + base64url(signature)
# - Payload structure:
#     {
#       "order_id": str,
#       "role": "sender" | "receiver",
#       "created_timestamp": ISO8601 UTC string,
#       "expires_at": ISO8601 UTC string
#     }

import json
import base64
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.exceptions import InvalidSignature


# ---------- Key loading ----------

def load_private_key(pem_path: str, password: bytes = None):
    with open(pem_path, "rb") as f:
        return load_pem_private_key(f.read(), password=password)


def load_public_key(pem_path: str):
    with open(pem_path, "rb") as f:
        return load_pem_public_key(f.read())


# ---------- Base64URL helpers ----------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


# ---------- Signing helpers ----------

def sign_payload(priv_key, obj: dict) -> bytes:
    """
    Sign a JSON-serializable payload dict with ECDSA(P-256, SHA-256).
    Used internally by create_passkey_string.
    """
    payload_bytes = json.dumps(
        obj, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    signature = priv_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    return signature


def create_passkey_string(
    priv_key,
    order_id: str,
    role: str,
    ttl_minutes: int = 90,
) -> tuple[str, dict]:
    """
    Create a signed passkey token for an order and role.

    Returns:
        (token, payload_dict)

    token format:
        base64url(payload_json) + "." + base64url(signature)
    """
    now = datetime.utcnow()
    payload = {
        "order_id": order_id,
        "role": role,
        "created_timestamp": now.isoformat() + "Z",
        "expires_at": (now + timedelta(minutes=ttl_minutes)).isoformat() + "Z",
    }

    payload_bytes = json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    sig = priv_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))

    payload_b64 = _b64url_encode(payload_bytes)
    sig_b64 = _b64url_encode(sig)
    token = f"{payload_b64}.{sig_b64}"
    return token, payload


def verify_passkey_string(pub_key, token: str) -> dict:
    """
    Verify a passkey token and return the decoded payload dict.

    Steps:
    - Split token into payload and signature.
    - Verify ECDSA(P-256, SHA-256) signature.
    - Decode JSON payload.

    Raises:
        ValueError: if malformed, invalid signature, or invalid JSON.
    """
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError as e:
        raise ValueError("Malformed passkey token") from e

    try:
        payload_bytes = _b64url_decode(payload_b64)
        sig = _b64url_decode(sig_b64)
    except Exception as e:
        raise ValueError("Invalid base64 encoding in passkey") from e

    # Verify signature
    try:
        pub_key.verify(sig, payload_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise ValueError("Invalid passkey signature") from e
    except Exception as e:
        raise ValueError("Error verifying passkey signature") from e

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError("Invalid passkey payload JSON") from e

    return payload


def is_passkey_expired(payload: dict, now: datetime | None = None) -> bool:
    """
    Check if the passkey payload is expired based on 'expires_at'.

    If 'expires_at' is missing or unparseable, treat as expired (fail closed).
    """
    if now is None:
        now = datetime.utcnow()

    expires_raw = payload.get("expires_at")
    if not expires_raw:
        return True

    try:
        # Support the "<iso>Z" format used in create_passkey_string
        if expires_raw.endswith("Z"):
            expires_raw = expires_raw[:-1]
        expires_at = datetime.fromisoformat(expires_raw)
    except Exception:
        return True

    return now > expires_at
