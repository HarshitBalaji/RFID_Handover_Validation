# main.py (patched)
import os
import json
import uuid
import yaml
import logging
import math
import base64
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends, Body
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from databases import Database
from sqlalchemy import create_engine
from io import StringIO
import csv

# password & crypto
from passlib.hash import argon2 as pwd_hasher
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# local modules - ensure these exist and match names
from models import metadata, users, geofences, registered_devices, orders, audit_log, used_passkeys, telemetry
from utils_crypto import load_private_key, load_public_key, create_passkey_string, b64url_decode_nopad

# ---------- logging ----------
logger = logging.getLogger("poc")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

# ---------- config ----------
cfg_path = "config.yaml"
if not os.path.exists(cfg_path):
    raise RuntimeError("Missing config.yaml in working directory")
cfg = yaml.safe_load(open(cfg_path))
DB_URL = cfg["db_path"]
PASSKEY_FOLDER = cfg.get("passkey_folder", "passkeys")
TTL_MIN = cfg.get("passkey_ttl_minutes", 90)
JWT_SECRET = cfg.get("jwt_secret", "replace-me-in-prod")
JWT_ALGO = "HS256"

os.makedirs(os.path.join(PASSKEY_FOLDER, "sender"), exist_ok=True)
os.makedirs(os.path.join(PASSKEY_FOLDER, "receiver"), exist_ok=True)

# ---------- DB init ----------
engine = create_engine(DB_URL)
metadata.create_all(engine)
database = Database(DB_URL)

# ---------- crypto keys ----------
SERVER_PRIV = load_private_key(cfg["server_privkey_pem"])
SERVER_PUB = load_public_key(cfg["server_pubkey_pem"])

# ---------- FastAPI app ----------
app = FastAPI(title="Passkey Handover POC (patched)")

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ---------- safe accessor ----------
def safe_col(rec, col, fallback=None):
    """
    Read column `col` from `rec` which may be a `databases` Record.
    Returns fallback if column missing or value is None.
    """
    try:
        if rec is None:
            return fallback
        if hasattr(rec, "keys") and col in rec.keys():
            val = rec[col]
            return val if val is not None else fallback
        if isinstance(rec, dict):
            return rec.get(col, fallback)
        return getattr(rec, col, fallback)
    except Exception:
        return fallback

# ---------- helpers ----------
def create_jwt(user_row):
    """
    Build JWT payload robustly for different row/record types returned by `databases`.
    """
    # email
    try:
        email = user_row["email"] if hasattr(user_row, "keys") and "email" in user_row.keys() else getattr(user_row, "email", None) or (user_row.get("email") if isinstance(user_row, dict) else None)
    except Exception:
        email = None

    # username - prefer full_name else email
    try:
        username = (user_row["full_name"] if hasattr(user_row, "keys") and "full_name" in user_row.keys() and user_row["full_name"] else None) or getattr(user_row, "full_name", None) or (user_row.get("full_name") if isinstance(user_row, dict) else None) or email
    except Exception:
        username = email

    try:
        role = user_row["role"] if hasattr(user_row, "keys") and "role" in user_row.keys() else getattr(user_row, "role", None) or (user_row.get("role") if isinstance(user_row, dict) else None)
    except Exception:
        role = None

    try:
        sub = str(user_row["id"]) if hasattr(user_row, "keys") and "id" in user_row.keys() else str(getattr(user_row, "id", None) or (user_row.get("id") if isinstance(user_row, dict) else None))
    except Exception:
        sub = None

    payload = {"sub": sub, "email": email, "role": role, "username": username}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

# compact token parser + verifier
def parse_and_verify_compact_token(pub_key, token: str):
    if "." not in token:
        raise ValueError("LEGACY_TOKEN")
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload_bytes = b64url_decode_nopad(payload_b64)
        sig_bytes = b64url_decode_nopad(sig_b64)
        payload = json.loads(payload_bytes.decode())
    except Exception:
        raise HTTPException(400, "malformed_passkey")
    try:
        t0 = time.time()
        pub_key.verify(sig_bytes, payload_bytes, ec.ECDSA(hashes.SHA256()))
        t1 = time.time()
        # verify_ms could be logged by caller
        verify_ms = int((t1 - t0) * 1000)
    except InvalidSignature:
        raise HTTPException(400, "invalid_passkey_signature")
    expires_at = payload.get("expires_at")
    if not expires_at:
        raise HTTPException(400, "missing_expiry")
    exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > exp_dt:
        raise HTTPException(400, "passkey_expired")
    return payload

# haversine for circle geofence
def haversine_meters(lat1, lon1, lat2, lon2) -> float:
    R = 6371000.0
    phi1 = math.radians(float(lat1))
    phi2 = math.radians(float(lat2))
    dphi = math.radians(float(lat2) - float(lat1))
    dlambda = math.radians(float(lon2) - float(lon1))
    a = math.sin(dphi/2.0)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2.0)**2
    c = 2*math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

# ---------- Pydantic models ----------
class LoginModel(BaseModel):
    email: str
    password: str

class UserCreateModel(BaseModel):
    email: str
    password: str
    username: Optional[str] = None
    role: Optional[str] = "operator"

class GeofenceCircleModel(BaseModel):
    center: dict  # {"lat":..,"lon":..}
    radius_m: int

class OrderCreateModel(BaseModel):
    blood_type: Optional[str] = None
    blood_bags: Optional[int] = 1

class ValidateScanModel(BaseModel):
    order_id: str
    passkey_string: str
    device_chain: dict

class ConfirmModel(BaseModel):
    approve: bool = True

class TelemetryModel(BaseModel):
    device_id: str
    ts: int
    payload: dict

class DeviceCreateModel(BaseModel):
    device_id: str
    device_type: Optional[str] = None
    pub_key_pem: Optional[str] = None
    assigned_truck: Optional[str] = None

# ---------- startup / shutdown ----------
@app.on_event("startup")
async def startup():
    await database.connect()
    root_cfg = cfg.get("root_user", {})
    root_email = root_cfg.get("email")
    root_password = root_cfg.get("password")
    if root_email and root_password:
        existing = await database.fetch_one(users.select().where(users.c.email == root_email))
        if not existing:
            hashed = pwd_hasher.hash(root_password)
            rowid = await database.execute(users.insert().values(email=root_email, hashed_password=hashed, full_name="root", role="root"))
            await database.execute(audit_log.insert().values(user_id=rowid, event_type="root_user_created", remarks=f"root user {root_email} auto-created"))
            logger.info(f"Root user {root_email} created (from config).")
        else:
            logger.info("Root user already exists; skipping creation.")
    else:
        logger.info("No root_user configured in config.yaml (skip auto-create).")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ---------- Auth ----------
async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(401, "missing authorization")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(401, "bad authorization header")
    token = parts[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        raise HTTPException(401, "invalid token")
    user_row = await database.fetch_one(users.select().where(users.c.id == int(payload["sub"])))
    if not user_row:
        raise HTTPException(401, "user not found")
    return user_row

@app.post("/auth/login")
async def auth_login(l: LoginModel):
    """
    Login endpoint returns: { access_token, user: { id, email, username, role } }
    Robust for 'databases' Record objects.
    """
    row = await database.fetch_one(users.select().where(users.c.email == l.email))
    if not row:
        raise HTTPException(401, "invalid credentials")
    try:
        if not pwd_hasher.verify(l.password, row["hashed_password"]):
            raise HTTPException(401, "invalid credentials")
    except Exception:
        raise HTTPException(401, "invalid credentials")

    user_id = None
    try:
        user_id = int(row["id"]) if hasattr(row, "keys") and "id" in row.keys() else int(getattr(row, "id", None) or (row.get("id") if isinstance(row, dict) else None))
    except Exception:
        user_id = None

    email = row["email"] if hasattr(row, "keys") and "email" in row.keys() else getattr(row, "email", None) or (row.get("email") if isinstance(row, dict) else None)
    username = (row["full_name"] if hasattr(row, "keys") and "full_name" in row.keys() and row["full_name"] else None) or getattr(row, "full_name", None) or (row.get("full_name") if isinstance(row, dict) else None) or email
    role = row["role"] if hasattr(row, "keys") and "role" in row.keys() else getattr(row, "role", None) or (row.get("role") if isinstance(row, dict) else None)

    token = create_jwt(row)
    await database.execute(audit_log.insert().values(user_id=user_id, event_type="user_logged_in", remarks=f"login {email}"))
    return {"access_token": token, "user": {"id": user_id, "email": email, "username": username, "role": role}}

@app.post("/auth/register")
async def auth_register(uc: UserCreateModel, current_user=Depends(get_current_user)):
    if safe_col(current_user, "role") not in ("root", "admin"):
        raise HTTPException(403, "only root/admin can create users")
    existing = await database.fetch_one(users.select().where(users.c.email == uc.email))
    if existing:
        raise HTTPException(400, "email exists")
    hashed = pwd_hasher.hash(uc.password)
    full_name = uc.username or None
    res = await database.execute(users.insert().values(email=uc.email, hashed_password=hashed, full_name=full_name, role=uc.role))
    new_row = await database.fetch_one(users.select().where(users.c.email == uc.email))
    await database.execute(audit_log.insert().values(user_id=safe_col(current_user, "id"), event_type="user_created", remarks=json.dumps({"new_user_id": safe_col(new_row, "id"), "email": uc.email})))
    return {"ok": True, "user": {"id": safe_col(new_row, "id"), "email": safe_col(new_row, "email"), "role": safe_col(new_row, "role")}}

# ---------- Geofence (single circle per user) ----------
@app.post("/users/me/geofence")
async def set_my_geofence(g: GeofenceCircleModel, current_user=Depends(get_current_user)):
    center_lat = str(g.center.get("lat"))
    center_lon = str(g.center.get("lon"))
    radius = int(g.radius_m)
    existing = await database.fetch_one(geofences.select().where(geofences.c.user_id == safe_col(current_user, "id")))
    if existing:
        await database.execute(geofences.update().where(geofences.c.id == existing["id"]).values(type="circle", center_lat=center_lat, center_lon=center_lon, radius_m=radius, polygon_geojson=None, is_default=True))
        await database.execute(audit_log.insert().values(user_id=safe_col(current_user, "id"), event_type="geofence_updated", remarks=json.dumps({"user_id": safe_col(current_user, "id")})))
    else:
        nid = await database.execute(geofences.insert().values(user_id=safe_col(current_user, "id"), type="circle", center_lat=center_lat, center_lon=center_lon, radius_m=radius, polygon_geojson=None, is_default=True))
        await database.execute(audit_log.insert().values(user_id=safe_col(current_user, "id"), event_type="geofence_created", remarks=json.dumps({"id": nid})))
    return {"ok": True}

@app.get("/users/me/geofence")
async def get_my_geofence(current_user=Depends(get_current_user)):
    row = await database.fetch_one(geofences.select().where(geofences.c.user_id == safe_col(current_user, "id")))
    if not row:
        return {"geofence": None}
    return {"geofence": {"type": safe_col(row, "type"), "center_lat": safe_col(row, "center_lat"), "center_lon": safe_col(row, "center_lon"), "radius_m": safe_col(row, "radius_m")}}

# ---------- Devices (root/admin) ----------
@app.post("/devices")
async def create_device(d: DeviceCreateModel, current_user=Depends(get_current_user)):
    if safe_col(current_user, "role") not in ("root", "admin"):
        raise HTTPException(403, "not authorized")
    existing = await database.fetch_one(registered_devices.select().where(registered_devices.c.device_id == d.device_id))
    if existing:
        raise HTTPException(400, "device exists")
    await database.execute(registered_devices.insert().values(device_id=d.device_id, device_type=d.device_type, pub_key_pem=d.pub_key_pem, assigned_truck=d.assigned_truck))
    await database.execute(audit_log.insert().values(user_id=safe_col(current_user, "id"), event_type="device_registered", remarks=d.device_id))
    return {"ok": True}

@app.get("/devices")
async def list_devices(current_user=Depends(get_current_user)):
    if safe_col(current_user, "role") not in ("root", "admin"):
        raise HTTPException(403, "not authorized")
    rows = await database.fetch_all(registered_devices.select())
    out = [{"device_id": r["device_id"], "device_type": r["device_type"], "assigned_truck": r["assigned_truck"]} for r in rows]
    return {"devices": out}

@app.delete("/devices/{device_id}")
async def delete_device(device_id: str, current_user=Depends(get_current_user)):
    if safe_col(current_user, "role") not in ("root", "admin"):
        raise HTTPException(403, "not authorized")
    await database.execute(registered_devices.delete().where(registered_devices.c.device_id == device_id))
    await database.execute(audit_log.insert().values(user_id=safe_col(current_user, "id"), event_type="device_deleted", remarks=device_id))
    return {"ok": True}

# ---------- Users list/delete (root/admin) ----------
@app.get("/users")
async def list_users(current_user=Depends(get_current_user)):
    if safe_col(current_user, "role") not in ("root", "admin"):
        raise HTTPException(403, "not authorized")
    rows = await database.fetch_all(users.select())
    out = []
    for r in rows:
        uname = safe_col(r, "full_name") or safe_col(r, "email")
        out.append({"id": safe_col(r, "id"), "email": safe_col(r, "email"), "username": uname, "role": safe_col(r, "role")})
    return {"users": out}

@app.delete("/users/{user_id}")
async def delete_user(user_id: int, current_user=Depends(get_current_user)):
    if safe_col(current_user, "role") not in ("root", "admin"):
        raise HTTPException(403, "not authorized")
    await database.execute(users.delete().where(users.c.id == user_id))
    await database.execute(audit_log.insert().values(user_id=safe_col(current_user, "id"), event_type="user_deleted", remarks=str(user_id)))
    return {"ok": True}

# ---------- Orders ----------
@app.post("/orders")
async def create_order(o: OrderCreateModel, current_user=Depends(get_current_user)):
    if safe_col(current_user, "role") == "root":
        raise HTTPException(403, "root cannot create orders")
    order_id = str(uuid.uuid4())
    await database.execute(orders.insert().values(
        order_id=order_id,
        owner_user_id=safe_col(current_user, "id"),
        sender_user_id=None,
        receiver_user_id=safe_col(current_user, "id"),
        sender_name=None,
        receiver_name=None,
        blood_type=o.blood_type,
        blood_bags=o.blood_bags,
        status="AWAITING_SENDER_ASSIGNMENT"
    ))
    await database.execute(audit_log.insert().values(user_id=safe_col(current_user, "id"), order_id=order_id, event_type="order_created", remarks=json.dumps({"blood_type": o.blood_type, "blood_bags": o.blood_bags})))
    return {"order_id": order_id, "status": "AWAITING_SENDER_ASSIGNMENT"}

@app.post("/orders/{order_id}/accept")
async def accept_order(order_id: str, current_user=Depends(get_current_user)):
    if safe_col(current_user, "role") == "root":
        raise HTTPException(403, "root cannot accept orders")
    r = await database.fetch_one(orders.select().where(orders.c.order_id == order_id))
    if not r:
        raise HTTPException(404, "order not found")
    if safe_col(r, "status") != "AWAITING_SENDER_ASSIGNMENT":
        raise HTTPException(409, f"order not assignable (state={safe_col(r, 'status')})")
    t0 = time.time()
    token, payload = create_passkey_string(SERVER_PRIV, order_id, "sender", ttl_minutes=TTL_MIN)
    t1 = time.time()
    sign_ms = int((t1 - t0) * 1000)
    await database.execute(orders.update().where(orders.c.order_id == order_id).values(sender_user_id=safe_col(current_user, "id"), sender_passkey_string=token, status="CREATED"))
    await database.execute(audit_log.insert().values(user_id=safe_col(current_user, "id"), order_id=order_id, event_type="order_accepted_by_sender", remarks=json.dumps({"sign_ms": sign_ms})))
    with open(os.path.join(PASSKEY_FOLDER, "sender", f"{order_id}.json"), "w") as f:
        json.dump({"order_id": order_id, "role": "sender", "passkey_string": token, "created_timestamp": payload["created_timestamp"]}, f, indent=2)
    return {"ok": True, "order_id": order_id, "sender_user_id": safe_col(current_user, "id")}

@app.post("/orders/{order_id}/generate_receiver_passkey")
async def generate_receiver_passkey(order_id: str, body: dict = Body({}), current_user=Depends(get_current_user)):
    """
    Kept for backward compatibility but the recommended flow is truck->/truck/validate_geofence.
    """
    r = await database.fetch_one(orders.select().where(orders.c.order_id == order_id))
    if not r:
        raise HTTPException(404, "order not found")
    owner_id = safe_col(r, "owner_user_id")
    gf = await database.fetch_one(geofences.select().where((geofences.c.user_id == owner_id) & (geofences.c.is_default == True)))
    if not gf:
        raise HTTPException(400, "no_default_geofence")
    truck_location = body.get("truck_location")
    if not truck_location:
        last_t = await database.fetch_one(telemetry.select().where(telemetry.c.order_id == order_id).order_by(telemetry.c.created_at.desc()))
        if last_t:
            try:
                p = json.loads(safe_col(last_t, "payload") or "{}")
                truck_location = {"lat": p.get("lat") or p.get("truck_lat"), "lon": p.get("lon") or p.get("truck_lon")}
            except Exception:
                truck_location = None
    if not truck_location or truck_location.get("lat") is None:
        raise HTTPException(400, "missing_truck_location")
    lat = float(truck_location["lat"])
    lon = float(truck_location["lon"])
    if safe_col(gf, "type") != "circle":
        raise HTTPException(400, "geofence not circle")
    center_lat = float(safe_col(gf, "center_lat"))
    center_lon = float(safe_col(gf, "center_lon"))
    radius_m = float(safe_col(gf, "radius_m") or 0)
    inside = haversine_meters(lat, lon, center_lat, center_lon) <= radius_m
    await database.execute(audit_log.insert().values(order_id=order_id, event_type="receiver_generate_attempt", remarks=json.dumps({"inside": inside, "loc": truck_location})))
    if not inside:
        raise HTTPException(403, "not_in_geofence")
    t0 = time.time()
    token, payload = create_passkey_string(SERVER_PRIV, order_id, "receiver", ttl_minutes=TTL_MIN)
    t1 = time.time()
    sign_ms = int((t1 - t0) * 1000)
    await database.execute(orders.update().where(orders.c.order_id == order_id).values(receiver_passkey_string=token))
    await database.execute(audit_log.insert().values(order_id=order_id, event_type="receiver_passkey_issued", remarks=json.dumps({"sign_ms": sign_ms})))
    with open(os.path.join(PASSKEY_FOLDER, "receiver", f"{order_id}.json"), "w") as f:
        json.dump({"order_id": order_id, "role": "receiver", "passkey_string": token, "created_timestamp": payload["created_timestamp"]}, f, indent=2)
    return {"receiver_passkey": token, "sign_ms": sign_ms}

# Truck-trigger: validate geofence and create receiver passkey (intended for truck/bridge)
@app.post("/truck/validate_geofence")
async def truck_validate_geofence(body: dict = Body(...)):
    order_id = body.get("order_id")
    truck_location = body.get("truck_location")
    if not order_id or not truck_location:
        raise HTTPException(400, "missing order_id or truck_location")
    r = await database.fetch_one(orders.select().where(orders.c.order_id == order_id))
    if not r:
        raise HTTPException(404, "order not found")
    owner_id = safe_col(r, "owner_user_id")
    gf = await database.fetch_one(geofences.select().where((geofences.c.user_id == owner_id) & (geofences.c.is_default == True)))
    if not gf:
        raise HTTPException(400, "no_default_geofence")
    if safe_col(gf, "type") != "circle":
        raise HTTPException(400, "geofence not circle")
    lat = float(truck_location.get("lat"))
    lon = float(truck_location.get("lon"))
    center_lat = float(safe_col(gf, "center_lat"))
    center_lon = float(safe_col(gf, "center_lon"))
    radius_m = float(safe_col(gf, "radius_m") or 0)
    inside = haversine_meters(lat, lon, center_lat, center_lon) <= radius_m
    await database.execute(audit_log.insert().values(order_id=order_id, event_type="truck_geofence_check", remarks=json.dumps({"inside": inside, "loc": truck_location})))
    if not inside:
        raise HTTPException(403, "truck not in geofence")
    t0 = time.time()
    token, payload = create_passkey_string(SERVER_PRIV, order_id, "receiver", ttl_minutes=TTL_MIN)
    t1 = time.time()
    sign_ms = int((t1 - t0) * 1000)
    await database.execute(orders.update().where(orders.c.order_id == order_id).values(receiver_passkey_string=token))
    await database.execute(audit_log.insert().values(order_id=order_id, event_type="receiver_passkey_issued", remarks=json.dumps({"sign_ms": sign_ms})))
    with open(os.path.join(PASSKEY_FOLDER, "receiver", f"{order_id}.json"), "w") as f:
        json.dump({"order_id": order_id, "role": "receiver", "passkey_string": token, "created_timestamp": payload["created_timestamp"]}, f, indent=2)
    return {"ok": True, "order_id": order_id, "issued": True}

@app.get("/orders/{order_id}/sender_passkey")
async def get_sender_passkey(order_id: str, current_user=Depends(get_current_user)):
    r = await database.fetch_one(orders.select().where(orders.c.order_id == order_id))
    if not r:
        raise HTTPException(404, "order not found")
    if safe_col(r, "sender_user_id") != safe_col(current_user, "id") and safe_col(current_user, "role") not in ("root", "admin"):
        raise HTTPException(403, "not authorized")
    token = safe_col(r, "sender_passkey_string")
    if not token:
        raise HTTPException(404, "sender passkey not found")
    return {"sender_passkey": token}

@app.get("/orders/{order_id}/receiver_passkey")
async def get_receiver_passkey(order_id: str, current_user=Depends(get_current_user)):
    r = await database.fetch_one(orders.select().where(orders.c.order_id == order_id))
    if not r:
        raise HTTPException(404, "order not found")
    if safe_col(r, "receiver_user_id") != safe_col(current_user, "id") and safe_col(current_user, "role") not in ("root", "admin"):
        raise HTTPException(403, "not authorized")
    token = safe_col(r, "receiver_passkey_string")
    if not token:
        raise HTTPException(404, "receiver passkey not issued yet")
    return {"receiver_passkey": token}

# ---------- Validate scan ----------
@app.post("/validate_scan")
async def validate_scan(v: ValidateScanModel):
    row = await database.fetch_one(orders.select().where(orders.c.order_id == v.order_id))
    if not row:
        await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=v.device_chain.get("box_id"), event_type="validate_failed", remarks="order_not_found"))
        raise HTTPException(404, "order not found")
    used = await database.fetch_one(used_passkeys.select().where(used_passkeys.c.passkey_string == v.passkey_string))
    if used:
        await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=v.device_chain.get("box_id"), event_type="validate_failed", remarks="replay"))
        raise HTTPException(400, "passkey already used")

    box_id = v.device_chain.get("box_id")
    truck_id = v.device_chain.get("truck_id")

    token_is_verified = False
    payload = None
    try:
        t_verify_start = time.time()
        payload = parse_and_verify_compact_token(SERVER_PUB, v.passkey_string)
        t_verify_end = time.time()
        verify_ms = int((t_verify_end - t_verify_start) * 1000)
        token_is_verified = True
        await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="verify_time", remarks=str(verify_ms)))
    except ValueError:
        token_is_verified = False
    except HTTPException as e:
        await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="validate_failed", remarks=f"sig_invalid:{str(e.detail)}"))
        raise

    if token_is_verified:
        if payload.get("order_id") != v.order_id:
            await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="validate_failed", remarks="order_id_mismatch"))
            raise HTTPException(400, "order_id_mismatch_in_passkey")
        role = payload.get("role")
        if role == "sender":
            if safe_col(row, "status") != "CREATED":
                await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="validate_failed", remarks="unexpected_state_for_sender"))
                raise HTTPException(400, f"order in unexpected state {safe_col(row,'status')}")
            await database.execute(orders.update().where(orders.c.order_id == v.order_id).values(box_id=box_id, truck_id=truck_id, status="PENDING_CONFIRMATION", pending_confirmation_by="sender", pending_confirm_ts=datetime.utcnow()))
            await database.execute(used_passkeys.insert().values(passkey_string=v.passkey_string))
            await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="sender_scanned", remarks=json.dumps({"truck_id": truck_id, "box_id": box_id})))
            return {"ok": True, "order_id": v.order_id, "transition": "PENDING_CONFIRMATION", "pending_by": "sender"}
        elif role == "receiver":
            if safe_col(row, "status") != "IN_TRANSIT":
                await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="validate_failed", remarks="unexpected_state_for_receiver"))
                raise HTTPException(400, f"order in unexpected state {safe_col(row,'status')}")
            await database.execute(orders.update().where(orders.c.order_id == v.order_id).values(status="PENDING_CONFIRMATION", pending_confirmation_by="receiver", pending_confirm_ts=datetime.utcnow()))
            await database.execute(used_passkeys.insert().values(passkey_string=v.passkey_string))
            await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="receiver_scanned", remarks=json.dumps({"truck_id": truck_id, "box_id": box_id})))
            return {"ok": True, "order_id": v.order_id, "transition": "PENDING_CONFIRMATION", "pending_by": "receiver"}
        else:
            await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="validate_failed", remarks="invalid_role"))
            raise HTTPException(400, "invalid_role")
    else:
        # legacy fallback
        if v.passkey_string == safe_col(row, "sender_passkey_string"):
            if safe_col(row, "status") != "CREATED":
                await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="validate_failed", remarks="unexpected_state_for_sender"))
                raise HTTPException(400, f"order in unexpected state {safe_col(row,'status')}")
            await database.execute(orders.update().where(orders.c.order_id == v.order_id).values(box_id=box_id, truck_id=truck_id, status="PENDING_CONFIRMATION", pending_confirmation_by="sender", pending_confirm_ts=datetime.utcnow()))
            await database.execute(used_passkeys.insert().values(passkey_string=v.passkey_string))
            await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="sender_scanned", remarks="legacy_token"))
            return {"ok": True, "order_id": v.order_id, "transition": "PENDING_CONFIRMATION", "pending_by": "sender"}
        elif v.passkey_string == safe_col(row, "receiver_passkey_string"):
            if safe_col(row, "status") != "IN_TRANSIT":
                await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="validate_failed", remarks="unexpected_state_for_receiver"))
                raise HTTPException(400, f"order in unexpected state {safe_col(row,'status')}")
            await database.execute(orders.update().where(orders.c.order_id == v.order_id).values(status="PENDING_CONFIRMATION", pending_confirmation_by="receiver", pending_confirm_ts=datetime.utcnow()))
            await database.execute(used_passkeys.insert().values(passkey_string=v.passkey_string))
            await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="receiver_scanned", remarks="legacy_token"))
            return {"ok": True, "order_id": v.order_id, "transition": "PENDING_CONFIRMATION", "pending_by": "receiver"}
        else:
            await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=box_id, event_type="validate_failed", remarks="bad_passkey"))
            raise HTTPException(400, "invalid passkey")

# ---------- Confirm endpoint ----------
@app.post("/orders/{order_id}/confirm")
async def confirm_order(order_id: str, body: ConfirmModel, current_user=Depends(get_current_user)):
    r = await database.fetch_one(orders.select().where(orders.c.order_id == order_id))
    if not r:
        raise HTTPException(404, "order not found")
    if safe_col(r, "status") != "PENDING_CONFIRMATION":
        raise HTTPException(409, "no pending confirmation")
    expected = safe_col(r, "pending_confirmation_by")
    allowed = False
    if safe_col(current_user, "role") in ("root", "admin"):
        allowed = True
    else:
        if expected == "sender" and (safe_col(r, "sender_user_id") == safe_col(current_user, "id") or safe_col(r, "owner_user_id") == safe_col(current_user, "id")):
            allowed = True
        if expected == "receiver" and (safe_col(r, "receiver_user_id") == safe_col(current_user, "id") or safe_col(r, "owner_user_id") == safe_col(current_user, "id")):
            allowed = True
    if not allowed:
        raise HTTPException(403, "not authorized to confirm")
    if expected == "sender":
        await database.execute(orders.update().where(orders.c.order_id == order_id).values(status="IN_TRANSIT", pending_confirmation_by=None, pending_confirm_ts=None))
        await database.execute(audit_log.insert().values(user_id=safe_col(current_user, "id"), order_id=order_id, event_type="sender_confirmed", remarks="sender confirmed scan"))
        return {"ok": True, "order_id": order_id, "transition": "IN_TRANSIT"}
    elif expected == "receiver":
        await database.execute(orders.update().where(orders.c.order_id == order_id).values(status="DELIVERED", pending_confirmation_by=None, pending_confirm_ts=None))
        await database.execute(audit_log.insert().values(user_id=safe_col(current_user, "id"), order_id=order_id, event_type="receiver_confirmed", remarks="receiver confirmed scan"))
        return {"ok": True, "order_id": order_id, "transition": "DELIVERED"}
    else:
        raise HTTPException(400, "invalid pending side")

# ---------- Telemetry ----------
@app.post("/telemetry_upload")
async def telemetry_upload(t: TelemetryModel):
    p = t.payload or {}
    order_id = p.get("order_id")
    def _get_latlon(obj):
        lat = obj.get("lat") or obj.get("truck_lat")
        lon = obj.get("lon") or obj.get("truck_lon")
        if not lat or not lon:
            gps_obj = obj.get("gps") or {}
            lat = lat or gps_obj.get("lat")
            lon = lon or gps_obj.get("lon")
        return lat, lon
    temperature = p.get("temperature")
    lat, lon = _get_latlon(p)
    await database.execute(telemetry.insert().values(order_id=order_id, device_id=t.device_id, ts=t.ts, payload=json.dumps(p)))
    audit_payload = {"ts": t.ts, "temperature": temperature, "truck_lat": lat, "truck_lon": lon}
    await database.execute(audit_log.insert().values(order_id=order_id, device_id=t.device_id, event_type="telemetry", remarks=json.dumps(audit_payload)))
    return {"ok": True}

# ---------- Orders listing & retrieval ----------
@app.get("/orders")
async def list_orders(current_user=Depends(get_current_user)):
    """
    Visibility:
      - sender_user_id is NULL -> visible to all authenticated users
      - sender assigned -> visible only to sender, receiver, owner, root/admin
    """
    rows = await database.fetch_all(orders.select())
    out = []
    for r in rows:
        sender_uid = safe_col(r, "sender_user_id")
        receiver_uid = safe_col(r, "receiver_user_id")
        owner_uid = safe_col(r, "owner_user_id")

        if sender_uid is None:
            vis = True
        else:
            if safe_col(current_user, "role") in ("root", "admin"):
                vis = True
            elif safe_col(current_user, "id") in (sender_uid, receiver_uid, owner_uid):
                vis = True
            else:
                vis = False

        if not vis:
            continue

        created_at_val = safe_col(r, "created_at")
        created_at_iso = created_at_val.isoformat() if created_at_val else None

        out.append({
            "order_id": safe_col(r, "order_id"),
            "status": safe_col(r, "status"),
            "box_id": safe_col(r, "box_id"),
            "truck_id": safe_col(r, "truck_id"),
            "blood_type": safe_col(r, "blood_type"),
            "blood_bags": safe_col(r, "blood_bags"),
            "sender_user_id": sender_uid,
            "receiver_user_id": receiver_uid,
            "pending_confirmation_by": safe_col(r, "pending_confirmation_by"),
            "created_at": created_at_iso
        })
    return {"orders": out}

@app.get("/orders/{order_id}")
async def get_order(order_id: str, current_user=Depends(get_current_user)):
    r = await database.fetch_one(orders.select().where(orders.c.order_id == order_id))
    if not r:
        raise HTTPException(404, "order not found")
    if safe_col(r, "sender_user_id") is not None:
        if safe_col(current_user, "role") not in ("root", "admin") and safe_col(current_user, "id") not in (safe_col(r, "sender_user_id"), safe_col(r, "receiver_user_id"), safe_col(r, "owner_user_id")):
            raise HTTPException(403, "not authorized to view")
    created_at_val = safe_col(r, "created_at")
    created_at_iso = created_at_val.isoformat() if created_at_val else None
    return {
        "order_id": safe_col(r, "order_id"),
        "status": safe_col(r, "status"),
        "box_id": safe_col(r, "box_id"),
        "truck_id": safe_col(r, "truck_id"),
        "blood_type": safe_col(r, "blood_type"),
        "blood_bags": safe_col(r, "blood_bags"),
        "sender_user_id": safe_col(r, "sender_user_id"),
        "receiver_user_id": safe_col(r, "receiver_user_id"),
        "pending_confirmation_by": safe_col(r, "pending_confirmation_by"),
        "created_at": created_at_iso
    }

# ---------- Audit download ----------
@app.get("/orders/{order_id}/audit/download")
async def download_audit_log(order_id: str, current_user=Depends(get_current_user)):
    try:
        _ = await get_order(order_id, current_user)
    except HTTPException as e:
        raise e
    rows = await database.fetch_all(audit_log.select().where(audit_log.c.order_id == order_id).order_by(audit_log.c.event_ts))
    output = StringIO()
    w = csv.writer(output)
    w.writerow(["event_ts", "event_type", "device_id", "order_id", "remarks"])
    for r in rows:
        w.writerow([r["event_ts"].isoformat() if r["event_ts"] else "", r["event_type"], r["device_id"] or "", r["order_id"] or "", r["remarks"] or ""])
    output.seek(0)
    filename = f"audit_{order_id}.csv"
    return StreamingResponse(iter([output.read()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})

# ---------- Root frontend (static) ----------
@app.get("/", response_class=HTMLResponse)
async def root_html():
    path = os.path.join("static", "frontend.html")
    if os.path.exists(path):
        return open(path, "r", encoding="utf-8").read()
    return HTMLResponse("<html><body><h3>Passkey Handover POC</h3></body></html>")
