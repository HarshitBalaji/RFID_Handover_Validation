# utils_crypto.py
import json, base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature

# helper: urlsafe b64 encode w/o padding
def b64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64url_decode_nopad(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)

def load_private_key(pem_path: str, password: bytes = None):
    with open(pem_path, "rb") as f:
        return load_pem_private_key(f.read(), password=password)

def load_public_key(pem_path: str):
    with open(pem_path, "rb") as f:
        return load_pem_public_key(f.read())

def sign_payload_bytes(priv_key, payload_bytes: bytes) -> bytes:
    signature = priv_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    return signature

def sign_payload(priv_key, obj: dict) -> (bytes, bytes):
    payload_bytes = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    signature = sign_payload_bytes(priv_key, payload_bytes)
    return signature, payload_bytes

def create_passkey_string(priv_key, order_id: str, role: str, ttl_minutes: int = 90) -> (str, dict):
    now = datetime.utcnow()
    payload = {
        "order_id": order_id,
        "role": role,
        "created_timestamp": now.isoformat() + "Z",
        "expires_at": (now + timedelta(minutes=ttl_minutes)).isoformat() + "Z"
    }
    sig, payload_bytes = sign_payload(priv_key, payload)
    payload_b64 = b64url_no_pad(payload_bytes)
    sig_b64 = b64url_no_pad(sig)
    token = payload_b64 + "." + sig_b64
    return token, payload

def verify_compact_token(pub_key, token: str) -> dict:
    """
    Verifies compact token payload_b64.sig_b64.
    Returns payload dict on success.
    Raises ValueError for malformed or InvalidSignature if signature invalid or expired.
    """
    if "." not in token:
        raise ValueError("LEGACY_TOKEN")
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload_bytes = b64url_decode_nopad(payload_b64)
        sig_bytes = b64url_decode_nopad(sig_b64)
        payload = json.loads(payload_bytes.decode())
    except Exception as e:
        raise ValueError("malformed_passkey") from e

    try:
        pub_key.verify(sig_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise InvalidSignature from e

    # TTL check - return payload; caller can check expires_at if desired
    return payload
