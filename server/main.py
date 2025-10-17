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
        await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=v.device_chain.get("box_id"), event_type="validate_failed", remarks="order_not_found"))
        raise HTTPException(404, "order not found")
    # prevent replay: check used_passkeys
    used = await database.fetch_one(used_passkeys.select().where(used_passkeys.c.passkey_string == v.passkey_string))
    if used:
        await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=v.device_chain.get("box_id"), event_type="validate_failed", remarks="replay"))
        raise HTTPException(400, "passkey already used")
    # check matches sender or receiver
    if v.passkey_string == row["sender_passkey_string"]:
        # sender scanned => we expect status CREATED; attach box_id and truck_id and set IN_TRANSIT
        if row["status"] != "CREATED":
            await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=v.device_chain.get("box_id"), event_type="validate_failed", remarks="unexpected_state_for_sender"))
            raise HTTPException(400, f"order in unexpected state {row['status']}")
        # set box_id and truck_id
        await database.execute(orders.update().where(orders.c.order_id == v.order_id).values(box_id=v.device_chain.get("box_id"), truck_id=v.device_chain.get("truck_id"), status="IN_TRANSIT"))
        await database.execute(used_passkeys.insert().values(passkey_string=v.passkey_string))
        await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=v.device_chain.get("box_id"), event_type="sender_validated", remarks=f"truck:{v.device_chain.get('truck_id')}"))
        return {"ok": True, "order_id": v.order_id, "transition": "IN_TRANSIT"}
    elif v.passkey_string == row["receiver_passkey_string"]:
        # receiver scanned => expect IN_TRANSIT -> DELIVERED and remove assignment (clear box_id/truck_id)
        if row["status"] != "IN_TRANSIT":
            await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=v.device_chain.get("box_id"), event_type="validate_failed", remarks="unexpected_state_for_receiver"))
            raise HTTPException(400, f"order in unexpected state {row['status']}")
        await database.execute(orders.update().where(orders.c.order_id == v.order_id).values(status="DELIVERED", box_id=None, truck_id=None))
        await database.execute(used_passkeys.insert().values(passkey_string=v.passkey_string))
        await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=v.device_chain.get("box_id"), event_type="receiver_validated", remarks=f"truck:{v.device_chain.get('truck_id')}"))
        return {"ok": True, "order_id": v.order_id, "transition": "DELIVERED"}
    else:
        await database.execute(audit_log.insert().values(order_id=v.order_id, device_id=v.device_chain.get("box_id"), event_type="validate_failed", remarks="bad_passkey"))
        raise HTTPException(400, "invalid passkey")

# 4) telemetry endpoint — truck forwards only telemetry for attached boxes; server stores telemetry with order_id if present
@app.post("/telemetry_upload")
async def telemetry_upload(t: TelemetryModel):
    # payload should contain order_id if truck attached it; but we'll persist whatever truck sends
    order_id = t.payload.get("order_id")
    await database.execute(telemetry.insert().values(order_id=order_id, device_id=t.device_id, ts=t.ts, payload=json.dumps(t.payload)))
    await database.execute(audit_log.insert().values(order_id=order_id, device_id=t.device_id, event_type="telemetry", remarks=json.dumps({"ts": t.ts})))
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
    rows = await database.fetch_all(audit_log.select().where(audit_log.c.order_id == order_id).order_by(audit_log.c.event_ts))
    output = StringIO()
    w = csv.writer(output)
    w.writerow(["event_ts", "event_type", "device_id", "remarks"])
    for r in rows:
        w.writerow([r["event_ts"].isoformat() if r["event_ts"] else "", r["event_type"], r["device_id"], (r["remarks"] or "")])
    output.seek(0)
    filename = f"audit_{order_id}.csv"
    return StreamingResponse(iter([output.read()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})

# Simple frontend page
@app.get("/", response_class=HTMLResponse)
async def root():
    with open("static/frontend.html", "r", encoding="utf-8") as f:
        return f.read()
