import json, base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

def load_private_key(pem_path: str, password: bytes = None):
    with open(pem_path, "rb") as f:
        return load_pem_private_key(f.read(), password=password)

def load_public_key(pem_path: str):
    with open(pem_path, "rb") as f:
        return load_pem_public_key(f.read())

def sign_payload(priv_key, obj: dict) -> bytes:
    payload = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    signature = priv_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    return signature

def create_passkey_string(priv_key, order_id: str, role: str, ttl_minutes: int = 90) -> (str, dict):
    now = datetime.utcnow()
    payload = {
        "order_id": order_id,
        "role": role,
        "created_timestamp": now.isoformat() + "Z",
        "expires_at": (now + timedelta(minutes=ttl_minutes)).isoformat() + "Z"
    }
    sig = sign_payload(priv_key, payload)
    # store signature as base64 for a compact token
    token = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return token, payload
