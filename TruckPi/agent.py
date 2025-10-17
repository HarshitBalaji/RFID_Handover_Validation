# --- PATCHED: truck_agent.py ---
# Changes:
# 1) Appends Truck GPS (lat/lon) to every telemetry sample.
#    - GPS sources:
#        a) gpsd (recommended) -> set cfg.gps.source: "gpsd" (host/port optional)
#        b) serial NMEA -> set cfg.gps.source: "serial" and gps.serial_device (e.g., "/dev/ttyUSB0")
#        c) fixed/mock -> set cfg.gps.source: "fixed" and gps.fixed_lat/lon
#      If GPS not available, fields are left None but message still forwards.
#
# 2) Durable retry queue (SQLite) for scans & telemetry when offline:
#    - Table outbox_queue(type, endpoint, body_json, next_attempt_at, retry_count, last_error)
#    - Exponential backoff and rate-limited catch-up on reconnect.
#
# 3) CSV logging (always, every message we process):
#    - truck_logs/telemetry.csv with columns:
#        recv_ts_iso,box_id,device_ts,temperature,truck_lat,truck_lon,order_id,forwarded
#    - truck_logs/scans.csv with columns:
#        recv_ts_iso,box_id,role,order_id,forwarded,status,remarks
#
# 4) Forwarding policy:
#    - Telemetry forwarded only if the box is attached to an order (boxes.current_order != '000').
#    - Agent injects order_id if attached.
#    - Server will downsample; truck forwards at the device cadence (~2 min).
#
# 5) Scan handling:
#    - Expects ESP32 to publish the FULL JSON from the tag when possible:
#        {"order_id":"...","role":"sender|receiver","passkey_string":"..."}
#      We pass that order_id to the server /validate_scan.
#    - If only a token arrives, we try current attached order for receiver case; else still send with order_id=None.
#
# Note: Requires paho-mqtt, requests, PyYAML. gpsd/serial are optional depending on GPS source.

import paho.mqtt.client as mqtt
import json, sqlite3, yaml, time, requests, os, threading, csv, queue, sys
from urllib.parse import urljoin
from datetime import datetime, timezone

# --- Config ---
cfg = yaml.safe_load(open("config.yaml"))

MQTT_BROKER = cfg.get("mqtt_broker", "127.0.0.1")
MQTT_PORT   = cfg.get("mqtt_port", 1883)
SERVER_REST = cfg.get("server_rest", "http://127.0.0.1:8000")
TRUCK_ID    = cfg.get("truck_id", "truck-001")
LOCAL_DB    = cfg.get("local_db", "truck_local.db")

# GPS configuration
gps_cfg = cfg.get("gps", {}) or {}
GPS_SOURCE = gps_cfg.get("source", "gpsd")  # "gpsd" | "serial" | "fixed" | "none"
GPSD_HOST  = gps_cfg.get("gpsd_host", "127.0.0.1")
GPSD_PORT  = int(gps_cfg.get("gpsd_port", 2947))
SERIAL_DEV = gps_cfg.get("serial_device", "/dev/ttyUSB0")
FIXED_LAT  = gps_cfg.get("fixed_lat")
FIXED_LON  = gps_cfg.get("fixed_lon")

# Logging
LOG_DIR = cfg.get("truck_logs_dir", "truck_logs")
os.makedirs(LOG_DIR, exist_ok=True)
TELEM_CSV = os.path.join(LOG_DIR, "telemetry.csv")
SCANS_CSV = os.path.join(LOG_DIR, "scans.csv")

# --- Local DB init ---
conn = sqlite3.connect(LOCAL_DB, check_same_thread=False)
cur = conn.cursor()
cur.execute("""CREATE TABLE IF NOT EXISTS boxes (box_id TEXT PRIMARY KEY, current_order TEXT DEFAULT '000')""")
cur.execute("""CREATE TABLE IF NOT EXISTS outbox_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,                -- 'telemetry' | 'scan'
    endpoint TEXT NOT NULL,            -- '/telemetry_upload' | '/validate_scan'
    body_json TEXT NOT NULL,
    next_attempt_at INTEGER NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
)""")
conn.commit()

def now_epoch() -> int:
    return int(time.time())

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def csv_append(path: str, headers: list, row: list):
    exists = os.path.isfile(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(headers)
        w.writerow(row)

def get_current_order(box_id):
    r = cur.execute("SELECT current_order FROM boxes WHERE box_id=?", (box_id,)).fetchone()
    if r:
        return r[0]
    else:
        cur.execute("INSERT INTO boxes(box_id,current_order) VALUES(?,?)", (box_id,'000'))
        conn.commit()
        return '000'

def set_current_order(box_id, order_id):
    cur.execute("INSERT OR REPLACE INTO boxes(box_id,current_order) VALUES(?,?)", (box_id, order_id))
    conn.commit()

# --- GPS Provider ---
class GPSProvider:
    def __init__(self):
        self._lat = None
        self._lon = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)

    def get(self):
        with self._lock:
            return self._lat, self._lon

    def _update(self, lat, lon):
        with self._lock:
            self._lat = lat
            self._lon = lon

    def _run(self):
        if GPS_SOURCE == "fixed":
            # Fixed location (for lab/POC)
            self._update(FIXED_LAT, FIXED_LON)
            while not self._stop.is_set():
                time.sleep(1)
            return

        if GPS_SOURCE == "none":
            # No GPS; leave None
            while not self._stop.is_set():
                time.sleep(2)
            return

        if GPS_SOURCE == "gpsd":
            try:
                import socket
                # Minimal gpsd protocol watcher (ASCII). For robust use, install 'gps' module; here we keep dependencies light.
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((GPSD_HOST, GPSD_PORT))
                # Watch command to enable JSON reports
                s.sendall(b'?WATCH={"enable":true,"json":true}\n')
                buf = b""
                s.settimeout(1)
                while not self._stop.is_set():
                    try:
                        chunk = s.recv(4096)
                        if not chunk:
                            time.sleep(0.5); continue
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            try:
                                obj = json.loads(line.decode(errors="ignore"))
                            except Exception:
                                continue
                            # TPV sentences contain lat/lon
                            if obj.get("class") == "TPV":
                                lat = obj.get("lat")
                                lon = obj.get("lon")
                                if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                                    self._update(lat, lon)
                    except socket.timeout:
                        continue
                    except Exception:
                        time.sleep(1)
                        continue
            except Exception:
                # Fallback: leave None, keep trying slowly
                while not self._stop.is_set():
                    time.sleep(2)
            return

        if GPS_SOURCE == "serial":
            try:
                import serial
                ser = serial.Serial(SERIAL_DEV, 9600, timeout=1)
                line = b""
                while not self._stop.is_set():
                    try:
                        b = ser.readline()
                        if not b:
                            continue
                        s = b.decode(errors="ignore").strip()
                        if s.startswith("$GPRMC") or s.startswith("$GPGGA") or s.startswith("$GNGGA"):
                            # Minimal NMEA lat/lon parse (DDMM.MMMM)
                            parts = s.split(",")
                            # GPRMC: lat idx 3/4, lon idx 5/6
                            def _nmea_to_deg(val, hemi):
                                if not val:
                                    return None
                                # DDMM.MMMM or DDDMM.MMMM
                                if "." not in val:
                                    return None
                                head, tail = val.split(".", 1)
                                deg = int(head[:-2])
                                minutes = float(head[-2:] + "." + tail)
                                dec = deg + minutes/60.0
                                if hemi in ("S","W"):
                                    dec = -dec
                                return dec
                            if len(parts) >= 7:
                                lat = _nmea_to_deg(parts[3], parts[4])
                                lon = _nmea_to_deg(parts[5], parts[6])
                                if lat is not None and lon is not None:
                                    self._update(lat, lon)
                    except Exception:
                        time.sleep(0.5)
                        continue
            except Exception:
                while not self._stop.is_set():
                    time.sleep(2)
            return

gps = GPSProvider()
gps.start()

# --- Outbox Queue (durable retries) ---
BACKOFF_BASE = 2        # seconds
BACKOFF_MAX  = 60       # cap per attempt
CATCHUP_RATE_HZ = 5     # max sends per second while draining backlog

def enqueue(type_: str, endpoint: str, body: dict, initial_delay: int = 0, last_error: str = None):
    cur.execute(
        "INSERT INTO outbox_queue(type, endpoint, body_json, next_attempt_at, last_error) VALUES(?,?,?,?,?)",
        (type_, endpoint, json.dumps(body), now_epoch() + initial_delay, last_error)
    )
    conn.commit()

def try_send_row(row):
    _id, type_, endpoint, body_json, next_at, retry_count, last_error = row
    body = json.loads(body_json)
    url = urljoin(SERVER_REST, endpoint)
    try:
        r = requests.post(url, json=body, timeout=5)
        if r.status_code == 200:
            # Success -> delete row
            cur.execute("DELETE FROM outbox_queue WHERE id=?", (_id,))
            conn.commit()
            return True, None, r
        else:
            return False, f"HTTP {r.status_code}: {r.text[:200]}", r
    except Exception as e:
        return False, str(e), None

def worker_outbox():
    # Periodically attempt due rows with backoff and rate limiting
    while True:
        now = now_epoch()
        rows = cur.execute(
            "SELECT id,type,endpoint,body_json,next_attempt_at,retry_count,last_error FROM outbox_queue WHERE next_attempt_at <= ? ORDER BY id LIMIT 50",
            (now,)
        ).fetchall()
        if not rows:
            time.sleep(1)
            continue
        for row in rows:
            ok, err, resp = try_send_row(row)
            if ok:
                # slight pacing to avoid bursts
                time.sleep(1.0 / CATCHUP_RATE_HZ)
                continue
            # update backoff
            _id, type_, endpoint, body_json, next_at, retry_count, last_error = row
            retry_count += 1
            delay = min(BACKOFF_BASE * (2 ** (retry_count - 1)), BACKOFF_MAX)
            next_attempt = now_epoch() + delay
            cur.execute(
                "UPDATE outbox_queue SET retry_count=?, next_attempt_at=?, last_error=? WHERE id=?",
                (retry_count, next_attempt, err, _id)
            )
            conn.commit()
            # small delay between attempts to prevent tight loops
            time.sleep(0.2)

threading.Thread(target=worker_outbox, daemon=True).start()

# --- Forwarders ---
def forward_json(endpoint: str, body: dict, type_: str, csv_note=None):
    """Try immediate send; on failure, enqueue for retry."""
    url = urljoin(SERVER_REST, endpoint)
    try:
        r = requests.post(url, json=body, timeout=5)
        if r.status_code == 200:
            return True, r
        else:
            enqueue(type_, endpoint, body, initial_delay=2, last_error=f"HTTP {r.status_code}")
            return False, r
    except Exception as e:
        enqueue(type_, endpoint, body, initial_delay=2, last_error=str(e))
        return False, None

def handle_telemetry(box_id, payload_from_device):
    # Only forward if box is attached to an order
    cur_order = get_current_order(box_id)
    if not cur_order or cur_order == '000':
        print(f"[telemetry] box {box_id} not attached to any order — logging locally only")
        # still log locally (helps debugging)
        lat, lon = gps.get()
        temperature = (payload_from_device or {}).get("temperature")
        csv_append(TELEM_CSV,
                   ["recv_ts_iso","box_id","device_ts","temperature","truck_lat","truck_lon","order_id","forwarded"],
                   [now_iso(), box_id, int(time.time()), temperature, lat, lon, None, False])
        return

    # Build payload; attach order_id and truck GPS
    lat, lon = gps.get()
    body_payload = dict(payload_from_device or {})
    body_payload["order_id"] = body_payload.get("order_id", cur_order)
    # normalize temperature key if needed
    if "Temperature" in body_payload and "temperature" not in body_payload:
        body_payload["temperature"] = body_payload["Temperature"]

    # append GPS (truck-level)
    body_payload["lat"] = lat
    body_payload["lon"] = lon

    # device timestamp: prefer device-provided 'ts' if present; else current time
    device_ts = int(body_payload.get("ts", int(time.time())))

    body = {
        "device_id": box_id,
        "ts": device_ts,
        "payload": body_payload
    }

    ok, resp = forward_json("/telemetry_upload", body, type_="telemetry")
    print("[telemetry] forwarded:", ok, "for box", box_id)

    # CSV log
    temperature = body_payload.get("temperature")
    csv_append(TELEM_CSV,
               ["recv_ts_iso","box_id","device_ts","temperature","truck_lat","truck_lon","order_id","forwarded"],
               [now_iso(), box_id, device_ts, temperature, lat, lon, cur_order, bool(ok)])

def handle_scan_from_passkey_json(box_id, passkey_obj: dict):
    """Handle full JSON from tag: must contain passkey_string + order_id + role."""
    token = passkey_obj.get("passkey_string") or passkey_obj.get("token") or passkey_obj.get("passkey")
    order_id = passkey_obj.get("order_id")
    role = passkey_obj.get("role")
    if not token:
        print("[scan] missing passkey_string in JSON")
        return
    if not order_id:
        # fallback: try current order when role is receiver
        cur_order = get_current_order(box_id)
        if cur_order != '000':
            order_id = cur_order
    payload = {
        "order_id": order_id,
        "passkey_string": token,
        "device_chain": {"box_id": box_id, "truck_id": TRUCK_ID}
    }
    ok, resp = forward_json("/validate_scan", payload, type_="scan")
    status = "OK" if ok else f"FAIL:{(resp.status_code if resp else 'net')}"
    print("[scan] validation sent (JSON) ->", status)
    if ok and resp is not None and resp.status_code == 200:
        data = resp.json()
        if data.get("transition") == "IN_TRANSIT":
            set_current_order(box_id, data["order_id"])
            print(f"box {box_id} now attached to order {data['order_id']}")
        elif data.get("transition") == "DELIVERED":
            set_current_order(box_id, '000')
            print(f"box {box_id} order completed and detached")
    csv_append(SCANS_CSV,
               ["recv_ts_iso","box_id","role","order_id","forwarded","status","remarks"],
               [now_iso(), box_id, role, order_id, bool(ok), status, "full_json"])

def handle_scan_token_only(box_id, token: str):
    """Handle scans where only the token string is published."""
    # Best effort order_id:
    cur_order = get_current_order(box_id)
    order_id = None if cur_order == '000' else cur_order
    payload = {
        "order_id": order_id,
        "passkey_string": token,
        "device_chain": {"box_id": box_id, "truck_id": TRUCK_ID}
    }
    ok, resp = forward_json("/validate_scan", payload, type_="scan")
    status = "OK" if ok else f"FAIL:{(resp.status_code if resp else 'net')}"
    print("[scan] validation sent (token) ->", status)
    if ok and resp is not None and resp.status_code == 200:
        data = resp.json()
        if data.get("transition") == "IN_TRANSIT":
            set_current_order(box_id, data["order_id"])
            print(f"box {box_id} now attached to order {data['order_id']}")
        elif data.get("transition") == "DELIVERED":
            set_current_order(box_id, '000')
            print(f"box {box_id} order completed and detached")
    csv_append(SCANS_CSV,
               ["recv_ts_iso","box_id","role","order_id","forwarded","status","remarks"],
               [now_iso(), box_id, None, order_id, bool(ok), status, "token_only"])

# --- MQTT callbacks ---
def on_connect(client, userdata, flags, rc):
    print("connected rc", rc)
    client.subscribe("boxes/+/telemetry")
    client.subscribe("boxes/+/scan")

def on_message(client, userdata, msg):
    topic = msg.topic
    parts = topic.split('/')
    if len(parts) >= 3 and parts[0] == 'boxes':
        box_id = parts[1]
        typ = parts[2]
        try:
            payload = json.loads(msg.payload.decode())
        except Exception:
            payload = None

        if typ == 'telemetry':
            # payload may be {"payload": {...}} or direct map
            inner = payload.get('payload', payload) if isinstance(payload, dict) else {}
            handle_telemetry(box_id, inner)

        elif typ == 'scan':
            # Expect full JSON from tag if possible; else token string
            if isinstance(payload, dict) and ("passkey_string" in payload or "token" in payload or "passkey" in payload):
                # If the ESP32 published the entire passkey JSON read from the tag, it will also include order_id/role.
                handle_scan_from_passkey_json(box_id, payload)
            else:
                # token may be raw string message
                token = None
                if isinstance(payload, str):
                    token = payload.strip()
                elif payload is None:
                    try:
                        token = msg.payload.decode().strip()
                    except Exception:
                        token = None
                else:
                    # Some firmware publish {"data":"<token>"}; try common keys
                    token = (payload.get("data") if isinstance(payload, dict) else None) or token
                if not token:
                    print("[scan] no token found in message for box", box_id)
                    return
                handle_scan_token_only(box_id, token)

if __name__ == "__main__":
    client = mqtt.Client("truck_agent")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_start()
    print("truck agent running. local DB:", LOCAL_DB, "logs dir:", LOG_DIR, "gps source:", GPS_SOURCE)
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        gps.stop()
        client.loop_stop()
        client.disconnect()
