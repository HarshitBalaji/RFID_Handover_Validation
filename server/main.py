import os
import yaml
import json
import base64
import csv
from io import StringIO
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from databases import Database
from sqlalchemy import create_engine

from models import (
    metadata,
    registered_devices,
    orders,
    audit_log,
    used_passkeys,
    telemetry,
)
from utils_crypto import (
    load_private_key,
    load_public_key,
    create_passkey_string,
    verify_passkey_string,
    is_passkey_expired,
)

# For truck attestation verification
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# ---------- Config and DB setup ----------

cfg = yaml.safe_load(open("config.yaml"))
DB_URL = cfg["db_path"]
PASSKEY_FOLDER = cfg.get("passkey_folder", "passkeys")
TTL_MIN = cfg.get("passkey_ttl_minutes", 90)

os.makedirs(os.path.join(PASSKEY_FOLDER, "sender"), exist_ok=True)
os.makedirs(os.path.join(PASSKEY_FOLDER, "receiver"), exist_ok=True)

engine = create_engine(DB_URL)
metadata.create_all(engine)
database = Database(DB_URL)

SERVER_PRIV = load_private_key(cfg["server_privkey_pem"])
SERVER_PUB = load_public_key(cfg["server_pubkey_pem"])

app = FastAPI(title="Passkey Handover POC")

# Static frontend (if any)
app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------- Pydantic models ----------

class CreateOrderModel(BaseModel):
    order_id: str


class ValidateScanModel(BaseModel):
    order_id: str
    passkey_string: str
    device_chain: dict          # { "box_id": "...", "truck_id": "..." }
    truck_id: str               # attested truck_id
    truck_sig: str              # base64url ECDSA signature over body (without truck_sig)


class TelemetryModel(BaseModel):
    device_id: str              # box_id
    ts: int
    payload: dict
    truck_id: str               # attested truck_id
    truck_sig: str              # base64url ECDSA signature over body (without truck_sig)

class TruckRegisterModel(BaseModel):
    truck_id: str          # logical truck identifier, e.g. "TRUCK-001"
    pub_key_pem: str       # PEM-encoded EC public key of the truck
    assigned_truck: str | None = None  # optional, can mirror truck_id or be unused



# ---------- CORS ----------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Lifecycle ----------

@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


# ---------- Truck attestation helpers ----------

def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


async def verify_truck_attestation(body: dict):
    """
    Verify truck_id + truck_sig using registered_devices.pub_key_pem.

    body: dict of the payload as received (must include truck_id, truck_sig).
    The truck has signed the canonical JSON of body *without* truck_sig.
    """
    truck_id = body.get("truck_id")
    truck_sig = body.get("truck_sig")

    if not truck_id or not truck_sig:
        raise HTTPException(400, "missing truck_id/truck_sig")

    # Look up truck public key
    row = await database.fetch_one(
        registered_devices.select().where(
            registered_devices.c.device_id == truck_id
        )
    )
    if not row or not row["pub_key_pem"]:
        raise HTTPException(403, "unregistered truck")

    pub_pem = row["pub_key_pem"].encode("utf-8")
    try:
        pub_key = serialization.load_pem_public_key(pub_pem)
    except Exception:
        raise HTTPException(500, "invalid truck public key PEM")

    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        raise HTTPException(500, "truck public key is not EC")

    # Recreate the signed message: body without truck_sig
    msg_obj = dict(body)
    msg_obj.pop("truck_sig", None)

    data = json.dumps(msg_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    try:
        sig = _b64url_decode(truck_sig)
    except Exception:
        raise HTTPException(400, "invalid truck_sig encoding")

    try:
        pub_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise HTTPException(403, "invalid truck_sig")


# ---------- Endpoints ----------

@app.post("/create_order")
async def create_order(o: CreateOrderModel):
    existing = await database.fetch_one(
        orders.select().where(orders.c.order_id == o.order_id)
    )
    if existing:
        raise HTTPException(400, "order already exists")

    await database.execute(
        orders.insert().values(order_id=o.order_id, status="CREATED")
    )

    token, payload = create_passkey_string(
        SERVER_PRIV, o.order_id, "sender", ttl_minutes=TTL_MIN
    )
    await database.execute(
        orders.update()
        .where(orders.c.order_id == o.order_id)
        .values(sender_passkey_string=token)
    )

    fileobj = {
        "order_id": o.order_id,
        "role": "sender",
        "passkey_string": token,
        "created_timestamp": payload["created_timestamp"],
        "expires_at": payload["expires_at"],
    }
    path = os.path.join(PASSKEY_FOLDER, "sender", f"{o.order_id}.json")
    with open(path, "w") as f:
        json.dump(fileobj, f, indent=2)

    await database.execute(
        audit_log.insert().values(
            order_id=o.order_id,
            event_type="order_created",
            device_id=None,
            remarks="sender_passkey_issued",
        )
    )
    return {"sender_passkey": token, "file": fileobj}


@app.post("/generate_receiver_passkey/{order_id}")
async def generate_receiver_passkey(order_id: str):
    row = await database.fetch_one(
        orders.select().where(orders.c.order_id == order_id)
    )
    if not row:
        raise HTTPException(404, "order not found")

    token, payload = create_passkey_string(
        SERVER_PRIV, order_id, "receiver", ttl_minutes=TTL_MIN
    )
    await database.execute(
        orders.update()
        .where(orders.c.order_id == order_id)
        .values(receiver_passkey_string=token)
    )

    fileobj = {
        "order_id": order_id,
        "role": "receiver",
        "passkey_string": token,
        "created_timestamp": payload["created_timestamp"],
        "expires_at": payload["expires_at"],
    }
    path = os.path.join(PASSKEY_FOLDER, "receiver", f"{order_id}.json")
    with open(path, "w") as f:
        json.dump(fileobj, f, indent=2)

    await database.execute(
        audit_log.insert().values(
            order_id=order_id,
            event_type="receiver_passkey_issued",
            remarks="geofence_triggered",
        )
    )
    return {"receiver_passkey": token, "file": fileobj}


@app.post("/validate_scan")
async def validate_scan(v: ValidateScanModel):
    # Verify truck attestation first
    await verify_truck_attestation(v.dict())

    # Fetch order
    row = await database.fetch_one(
        orders.select().where(orders.c.order_id == v.order_id)
    )
    if not row:
        await database.execute(
            audit_log.insert().values(
                order_id=v.order_id,
                device_id=v.device_chain.get("box_id"),
                event_type="validate_failed",
                remarks="order_not_found",
            )
        )
        raise HTTPException(404, "order not found")

    # Replay protection
    used = await database.fetch_one(
        used_passkeys.select().where(
            used_passkeys.c.passkey_string == v.passkey_string
        )
    )
    if used:
        await database.execute(
            audit_log.insert().values(
                order_id=v.order_id,
                device_id=v.device_chain.get("box_id"),
                event_type="validate_failed",
                remarks="replay",
            )
        )
        raise HTTPException(400, "passkey already used")

    box_id = v.device_chain.get("box_id")
    truck_id_from_chain = v.device_chain.get("truck_id")
    truck_id_attested = v.truck_id

    # Ensure device_chain truck_id matches attested truck_id
    if truck_id_from_chain != truck_id_attested:
        await database.execute(
            audit_log.insert().values(
                order_id=v.order_id,
                device_id=box_id,
                event_type="validate_failed",
                remarks="truck_id_mismatch_between_chain_and_attestation",
            )
        )
        raise HTTPException(400, "truck_id mismatch")

    # Cryptographic verification of passkey
    try:
        payload = verify_passkey_string(SERVER_PUB, v.passkey_string)
    except ValueError:
        await database.execute(
            audit_log.insert().values(
                order_id=v.order_id,
                device_id=box_id,
                event_type="validate_failed",
                remarks="invalid_passkey_signature",
            )
        )
        raise HTTPException(400, "invalid passkey")

    if payload.get("order_id") != v.order_id:
        await database.execute(
            audit_log.insert().values(
                order_id=v.order_id,
                device_id=box_id,
                event_type="validate_failed",
                remarks="order_mismatch",
            )
        )
        raise HTTPException(400, "passkey not issued for this order")

    role = payload.get("role")
    if role not in ("sender", "receiver"):
        await database.execute(
            audit_log.insert().values(
                order_id=v.order_id,
                device_id=box_id,
                event_type="validate_failed",
                remarks="invalid_role",
            )
        )
        raise HTTPException(400, "invalid passkey role")

    if is_passkey_expired(payload):
        await database.execute(
            audit_log.insert().values(
                order_id=v.order_id,
                device_id=box_id,
                event_type="validate_failed",
                remarks="expired",
            )
        )
        raise HTTPException(400, "passkey expired")

    # Role-specific logic
    if role == "sender":
        expected = row["sender_passkey_string"]
        if v.passkey_string != expected:
            await database.execute(
                audit_log.insert().values(
                    order_id=v.order_id,
                    device_id=box_id,
                    event_type="validate_failed",
                    remarks="sender_passkey_mismatch",
                )
            )
            raise HTTPException(400, "invalid sender passkey")

        if row["status"] != "CREATED":
            await database.execute(
                audit_log.insert().values(
                    order_id=v.order_id,
                    device_id=box_id,
                    event_type="validate_failed",
                    remarks="unexpected_state_for_sender",
                )
            )
            raise HTTPException(
                400, f"order in unexpected state {row['status']}"
            )

        await database.execute(
            orders.update()
            .where(orders.c.order_id == v.order_id)
            .values(
                box_id=box_id,
                truck_id=truck_id_attested,
                status="IN_TRANSIT",
            )
        )

        await database.execute(
            used_passkeys.insert().values(passkey_string=v.passkey_string)
        )

        await database.execute(
            audit_log.insert().values(
                order_id=v.order_id,
                device_id=box_id,
                event_type="sender_validated",
                remarks=json.dumps(
                    {
                        "truck_id": truck_id_attested,
                        "box_id": box_id,
                        "role": role,
                        "created_timestamp": payload.get("created_timestamp"),
                        "expires_at": payload.get("expires_at"),
                    }
                ),
            )
        )
        return {"ok": True, "order_id": v.order_id, "transition": "IN_TRANSIT"}

    elif role == "receiver":
        expected = row["receiver_passkey_string"]
        if v.passkey_string != expected:
            await database.execute(
                audit_log.insert().values(
                    order_id=v.order_id,
                    device_id=box_id,
                    event_type="validate_failed",
                    remarks="receiver_passkey_mismatch",
                )
            )
            raise HTTPException(400, "invalid receiver passkey")

        if row["status"] != "IN_TRANSIT":
            await database.execute(
                audit_log.insert().values(
                    order_id=v.order_id,
                    device_id=box_id,
                    event_type="validate_failed",
                    remarks="unexpected_state_for_receiver",
                )
            )
            raise HTTPException(
                400, f"order in unexpected state {row['status']}"
            )

        await database.execute(
            orders.update()
            .where(orders.c.order_id == v.order_id)
            .values(status="DELIVERED")
        )

        await database.execute(
            used_passkeys.insert().values(passkey_string=v.passkey_string)
        )

        await database.execute(
            audit_log.insert().values(
                order_id=v.order_id,
                device_id=box_id,
                event_type="receiver_validated",
                remarks=json.dumps(
                    {
                        "truck_id": truck_id_attested,
                        "box_id": box_id,
                        "role": role,
                        "created_timestamp": payload.get("created_timestamp"),
                        "expires_at": payload.get("expires_at"),
                    }
                ),
            )
        )
        return {"ok": True, "order_id": v.order_id, "transition": "DELIVERED"}

    await database.execute(
        audit_log.insert().values(
            order_id=v.order_id,
            device_id=box_id,
            event_type="validate_failed",
            remarks="bad_passkey",
        )
    )
    raise HTTPException(400, "invalid passkey")


@app.post("/telemetry_upload")
async def telemetry_upload(t: TelemetryModel):
    # Verify truck attestation
    await verify_truck_attestation(t.dict())

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

    await database.execute(
        telemetry.insert().values(
            order_id=order_id,
            device_id=t.device_id,
            ts=t.ts,
            payload=json.dumps(p),
        )
    )

    audit_payload = {
        "ts": t.ts,
        "temperature": temperature,
        "truck_lat": lat,
        "truck_lon": lon,
        "truck_id": t.truck_id,
    }
    await database.execute(
        audit_log.insert().values(
            order_id=order_id,
            device_id=t.device_id,
            event_type="telemetry",
            remarks=json.dumps(audit_payload),
        )
    )
    return {"ok": True}


@app.get("/orders")
async def get_orders():
    rows = await database.fetch_all(orders.select())
    out = []
    for r in rows:
        out.append(
            {
                "order_id": r["order_id"],
                "status": r["status"],
                "box_id": r["box_id"],
                "truck_id": r["truck_id"],
                "created_at": r["created_at"].isoformat()
                if r["created_at"]
                else None,
            }
        )
    return {"orders": out}


@app.get("/orders/{order_id}")
async def get_order(order_id: str):
    r = await database.fetch_one(
        orders.select().where(orders.c.order_id == order_id)
    )
    if not r:
        raise HTTPException(404, "order not found")
    return {
        "order_id": r["order_id"],
        "status": r["status"],
        "box_id": r["box_id"],
        "truck_id": r["truck_id"],
        "created_at": r["created_at"].isoformat()
        if r["created_at"]
        else None,
    }


@app.get("/orders/{order_id}/audit/download")
async def download_audit_log(order_id: str):
    order_row = await database.fetch_one(
        orders.select().where(orders.c.order_id == order_id)
    )
    if not order_row:
        raise HTTPException(404, "order not found")

    order_truck_id = order_row["truck_id"]
    order_box_id = order_row["box_id"]

    rows = await database.fetch_all(
        audit_log.select()
        .where(audit_log.c.order_id == order_id)
        .order_by(audit_log.c.event_ts)
    )

    output = StringIO()
    w = csv.writer(output)
    w.writerow(
        [
            "event_ts",
            "event_type",
            "device_id",
            "order_id",
            "truck_id",
            "box_id",
            "temperature",
            "truck_lat",
            "truck_lon",
            "remarks",
        ]
    )

    for r in rows:
        remarks_raw = r["remarks"] or ""
        temperature = ""
        truck_lat = ""
        truck_lon = ""
        csv_truck_id = order_truck_id
        csv_box_id = order_box_id

        try:
            robj = json.loads(remarks_raw) if remarks_raw else {}
        except Exception:
            robj = {}

        if isinstance(robj, dict):
            if robj.get("truck_id") is not None:
                csv_truck_id = robj.get("truck_id")
            if robj.get("box_id") is not None:
                csv_box_id = robj.get("box_id")

        if r["event_type"] == "telemetry" and isinstance(robj, dict):
            if robj.get("temperature") is not None:
                temperature = robj.get("temperature")
            if robj.get("truck_lat") is not None:
                truck_lat = robj.get("truck_lat")
            if robj.get("truck_lon") is not None:
                truck_lon = robj.get("truck_lon")

        w.writerow(
            [
                r["event_ts"].isoformat() if r["event_ts"] else "",
                r["event_type"],
                r["device_id"],
                r["order_id"],
                csv_truck_id,
                csv_box_id,
                temperature,
                truck_lat,
                truck_lon,
                remarks_raw,
            ]
        )

    output.seek(0)
    headers = {
        "Content-Disposition": f'attachment; filename="audit_{order_id}.csv"'
    }
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers=headers,
    )

@app.post("/register_truck")
async def register_truck(t: TruckRegisterModel):
    """
    Register or update a truck device.

    - Stores the truck's public key in registered_devices.pub_key_pem.
    - device_id is the truck_id from the request.
    - device_type is fixed as "truck".
    """
    # Check if this truck already exists
    existing = await database.fetch_one(
        registered_devices.select().where(
            registered_devices.c.device_id == t.truck_id
        )
    )

    if existing:
        # Update existing record
        await database.execute(
            registered_devices.update()
            .where(registered_devices.c.device_id == t.truck_id)
            .values(
                device_type="truck",
                pub_key_pem=t.pub_key_pem,
                assigned_truck=t.assigned_truck,
            )
        )
        action = "updated"
    else:
        # Insert new record
        await database.execute(
            registered_devices.insert().values(
                device_id=t.truck_id,
                device_type="truck",
                pub_key_pem=t.pub_key_pem,
                assigned_truck=t.assigned_truck,
            )
        )
        action = "created"

    # Optional audit event
    await database.execute(
        audit_log.insert().values(
            order_id=None,
            device_id=t.truck_id,
            event_type="truck_registered",
            remarks=action,
        )
    )

    return {
        "ok": True,
        "truck_id": t.truck_id,
        "action": action,
    }


@app.get("/trucks")
async def list_trucks():
    """
    Return the list of registered trucks (device_type == 'truck').
    """
    rows = await database.fetch_all(
        registered_devices.select().where(
            registered_devices.c.device_type == "truck"
        )
    )

    trucks = []
    for r in rows:
        trucks.append(
            {
                "truck_id": r["device_id"],
                "device_type": r["device_type"],
                "assigned_truck": r["assigned_truck"],
                # pub_key_pem is included for debugging/provisioning; you can omit in production
                "pub_key_pem": r["pub_key_pem"],
            }
        )

    return {"trucks": trucks}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000) 