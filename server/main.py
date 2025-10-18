import os, yaml, json, base64
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, StreamingResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from databases import Database
from sqlalchemy import create_engine, select
from models import metadata, registered_devices, orders, audit_log, used_passkeys, telemetry
from utils_crypto import load_private_key, load_public_key, create_passkey_string
from datetime import datetime
import csv
from io import StringIO

# Load config
cfg = yaml.safe_load(open("config.yaml"))
DB_URL = cfg["db_path"]
PASSKEY_FOLDER = cfg.get("passkey_folder", "passkeys")
TTL_MIN = cfg.get("passkey_ttl_minutes", 90)

# Ensure passkey dirs
os.makedirs(os.path.join(PASSKEY_FOLDER, "sender"), exist_ok=True)
os.makedirs(os.path.join(PASSKEY_FOLDER, "receiver"), exist_ok=True)

engine = create_engine(DB_URL)
metadata.create_all(engine)
database = Database(DB_URL)

SERVER_PRIV = load_private_key(cfg["server_privkey_pem"])
SERVER_PUB = load_public_key(cfg["server_pubkey_pem"])

app = FastAPI(title="Passkey Handover POC")

# serve a simple frontend
app.mount("/static", StaticFiles(directory="static"), name="static")

class CreateOrderModel(BaseModel):
    order_id: str

class GenerateReceiverModel(BaseModel):
    # optional: guard param if needed
    pass

class ValidateScanModel(BaseModel):
    order_id: str
    passkey_string: str
    device_chain: dict  # expects { "box_id": "...", "truck_id": "..." } truck may add truck_id

class TelemetryModel(BaseModel):
    device_id: str
    ts: int
    payload: dict

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # lock down to your host(s) later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# 1) create_order -> generates sender passkey and returns passkey string + JSON
@app.post("/create_order")
async def create_order(o: CreateOrderModel):
    # ensure order doesn't exist
    row = await database.fetch_one(orders.select().where(orders.c.order_id == o.order_id))
    if row:
        raise HTTPException(400, "order already exists")
    # create order (no box/truck assigned)
    await database.execute(orders.insert().values(order_id=o.order_id, status="CREATED"))
    # generate sender passkey string and store
    token, payload = create_passkey_string(SERVER_PRIV, o.order_id, "sender", ttl_minutes=TTL_MIN)
    await database.execute(orders.update().where(orders.c.order_id == o.order_id).values(sender_passkey_string=token))
    # write JSON file under passkeys/sender/<order_id>.json
    fileobj = {"order_id": o.order_id, "role": "sender", "passkey_string": token, "created_timestamp": payload["created_timestamp"]}
    path = os.path.join(PASSKEY_FOLDER, "sender", f"{o.order_id}.json")
    with open(path, "w") as f:
        json.dump(fileobj, f, indent=2)
    # audit
    await database.execute(audit_log.insert().values(order_id=o.order_id, event_type="order_created", device_id=None, remarks="sender_passkey_issued"))
    return {"sender_passkey": token, "file": fileobj}

# 2) generate receiver passkey (server-side when geofence triggered)
@app.post("/generate_receiver_passkey/{order_id}")
async def generate_receiver_passkey(order_id: str):
    row = await database.fetch_one(orders.select().where(orders.c.order_id == order_id))
    if not row:
        raise HTTPException(404, "order not found")
    token, payload = create_passkey_string(SERVER_PRIV, order_id, "receiver", ttl_minutes=TTL_MIN)
    await database.execute(orders.update().where(orders.c.order_id == order_id).values(receiver_passkey_string=token))
    fileobj = {"order_id": order_id, "role": "receiver", "passkey_string": token, "created_timestamp": payload["created_timestamp"]}
    path = os.path.join(PASSKEY_FOLDER, "receiver", f"{order_id}.json")
    with open(path, "w") as f:
        json.dump(fileobj, f, indent=2)
    await database.execute(audit_log.insert().values(order_id=order_id, event_type="receiver_passkey_issued", remarks="geofence_triggered"))
    return {"receiver_passkey": token, "file": fileobj}

# 3) validate_scan: called by truck (truck appends truck_id) - server validates token and updates order state
@app.post("/validate_scan")
async def validate_scan(v: ValidateScanModel):
    row = await database.fetch_one(orders.select().where(orders.c.order_id == v.order_id))
    if not row:
        await database.execute(audit_log.insert().values(
            order_id=v.order_id,
            device_id=v.device_chain.get("box_id"),
            event_type="validate_failed",
            remarks="order_not_found"
        ))
        raise HTTPException(404, "order not found")

    # prevent replay: check used_passkeys
    used = await database.fetch_one(used_passkeys.select().where(used_passkeys.c.passkey_string == v.passkey_string))
    if used:
        await database.execute(audit_log.insert().values(
            order_id=v.order_id,
            device_id=v.device_chain.get("box_id"),
            event_type="validate_failed",
            remarks="replay"
        ))
        raise HTTPException(400, "passkey already used")

    box_id = v.device_chain.get("box_id")
    truck_id = v.device_chain.get("truck_id")

    # sender scan -> CREATED -> IN_TRANSIT, set box/truck and keep them
    if v.passkey_string == row["sender_passkey_string"]:
        if row["status"] != "CREATED":
            await database.execute(audit_log.insert().values(
                order_id=v.order_id,
                device_id=box_id,
                event_type="validate_failed",
                remarks="unexpected_state_for_sender"
            ))
            raise HTTPException(400, f"order in unexpected state {row['status']}")

        # Attach identifiers and move to IN_TRANSIT
        await database.execute(
            orders.update()
            .where(orders.c.order_id == v.order_id)
            .values(box_id=box_id, truck_id=truck_id, status="IN_TRANSIT")
        )

        await database.execute(used_passkeys.insert().values(passkey_string=v.passkey_string))

        # Rich JSON remarks (includes both truck_id and box_id)
        await database.execute(audit_log.insert().values(
            order_id=v.order_id,
            device_id=box_id,
            event_type="sender_validated",
            remarks=json.dumps({"truck_id": truck_id, "box_id": box_id})
        ))
        return {"ok": True, "order_id": v.order_id, "transition": "IN_TRANSIT"}

    # receiver scan -> IN_TRANSIT -> DELIVERED, KEEP box/truck in DB for audit
    elif v.passkey_string == row["receiver_passkey_string"]:
        if row["status"] != "IN_TRANSIT":
            await database.execute(audit_log.insert().values(
                order_id=v.order_id,
                device_id=box_id,
                event_type="validate_failed",
                remarks="unexpected_state_for_receiver"
            ))
            raise HTTPException(400, f"order in unexpected state {row['status']}")

        # IMPORTANT: do NOT clear box_id/truck_id; we keep them for audit lineage
        await database.execute(
            orders.update()
            .where(orders.c.order_id == v.order_id)
            .values(status="DELIVERED")
        )

        await database.execute(used_passkeys.insert().values(passkey_string=v.passkey_string))

        await database.execute(audit_log.insert().values(
            order_id=v.order_id,
            device_id=box_id,
            event_type="receiver_validated",
            remarks=json.dumps({"truck_id": truck_id, "box_id": box_id})
        ))
        return {"ok": True, "order_id": v.order_id, "transition": "DELIVERED"}

    else:
        await database.execute(audit_log.insert().values(
            order_id=v.order_id,
            device_id=box_id,
            event_type="validate_failed",
            remarks="bad_passkey"
        ))
        raise HTTPException(400, "invalid passkey")

# 4) telemetry endpoint — truck forwards only telemetry for attached boxes; server stores telemetry with order_id if present
@app.post("/telemetry_upload")
async def telemetry_upload(t: TelemetryModel):
    # Always persist the raw payload as-is
    p = t.payload or {}

    # Prefer order_id from payload; keep behavior consistent with your DB
    order_id = p.get("order_id")

    # Extract telemetry values (robust to both nested-only and top-level duplicates)
    # agent may send only in payload, or also send duplicates like truck_lat/truck_lon/gps
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

    # Persist telemetry table (unchanged)
    await database.execute(
        telemetry.insert().values(
            order_id=order_id,
            device_id=t.device_id,
            ts=t.ts,
            payload=json.dumps(p),
        )
    )

    # Enrich the audit row so CSV can expose telemetry columns
    audit_payload = {
        "ts": t.ts,
        "temperature": temperature,
        "truck_lat": lat,
        "truck_lon": lon,
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

# 5) get orders list (hide passkeys)
@app.get("/orders")
async def get_orders():
    rows = await database.fetch_all(orders.select())
    out = []
    for r in rows:
        out.append({
            "order_id": r["order_id"],
            "status": r["status"],
            "box_id": r["box_id"],
            "truck_id": r["truck_id"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None
        })
    return {"orders": out}

@app.get("/orders/{order_id}")
async def get_order(order_id: str):
    r = await database.fetch_one(orders.select().where(orders.c.order_id == order_id))
    if not r:
        raise HTTPException(404, "order not found")
    return {
        "order_id": r["order_id"],
        "status": r["status"],
        "box_id": r["box_id"],
        "truck_id": r["truck_id"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None
    }

# 6) Download audit log CSV for an order
@app.get("/orders/{order_id}/audit/download")
async def download_audit_log(order_id: str):
    # Fetch the order row once; its box_id/truck_id are retained even after delivery
    order_row = await database.fetch_one(orders.select().where(orders.c.order_id == order_id))
    order_truck_id = order_row["truck_id"] if order_row else None
    order_box_id = order_row["box_id"] if order_row else None

    rows = await database.fetch_all(
        audit_log.select()
        .where(audit_log.c.order_id == order_id)
        .order_by(audit_log.c.event_ts)
    )

    output = StringIO()
    w = csv.writer(output)
    # New columns truck_id, box_id; keep telemetry columns too
    w.writerow(["event_ts", "event_type", "device_id", "order_id",
                "truck_id", "box_id",
                "temperature", "truck_lat", "truck_lon", "remarks"])

    for r in rows:
        remarks_raw = r["remarks"] or ""
        temperature = ""
        truck_lat = ""
        truck_lon = ""
        csv_truck_id = order_truck_id
        csv_box_id = order_box_id

        # Try to parse remarks as JSON to override/add truck/box and telemetry
        try:
            robj = json.loads(remarks_raw) if remarks_raw else {}
        except Exception:
            robj = {}

        # For sender/receiver validations we stored {"truck_id","box_id"}
        if isinstance(robj, dict):
            if robj.get("truck_id") is not None:
                csv_truck_id = robj.get("truck_id")
            if robj.get("box_id") is not None:
                csv_box_id = robj.get("box_id")

        # For telemetry we stored telemetry fields in remarks JSON
        if r["event_type"] == "telemetry" and isinstance(robj, dict):
            if robj.get("temperature") is not None:
                temperature = robj.get("temperature")
            truck_lat = robj.get("truck_lat") if robj.get("truck_lat") is not None else truck_lat
            truck_lon = robj.get("truck_lon") if robj.get("truck_lon") is not None else truck_lon
            # tolerant fallbacks
            if not truck_lat:
                truck_lat = robj.get("lat")
            if not truck_lon:
                truck_lon = robj.get("lon")

        w.writerow([
            r["event_ts"].isoformat() if r["event_ts"] else "",
            r["event_type"],
            r["device_id"],
            r["order_id"],
            csv_truck_id or "",
            csv_box_id or "",
            temperature if temperature is not None else "",
            truck_lat if truck_lat is not None else "",
            truck_lon if truck_lon is not None else "",
            remarks_raw
        ])

    output.seek(0)
    filename = f"audit_{order_id}.csv"
    return StreamingResponse(
        iter([output.read()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# Simple frontend page
@app.get("/", response_class=HTMLResponse)
async def root():
    with open("static/frontend.html", "r", encoding="utf-8") as f:
        return f.read()
