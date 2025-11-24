# --- FINAL: truck_agent.py ---
# Highlights:
# - Safe URL builder, fail-fast config check
# - Thread-safe SQLite (per-call cursor + lock, WAL mode)
# - Durable outbox with exponential backoff, drops permanent 4xx
# - Telemetry duplicates key fields to top-level for audit visibility
# - order_id omitted (not null) when unknown
# - Better debug logging; idempotent message_id for telemetry

import paho.mqtt.client as mqtt
import json, sqlite3, yaml, time, requests, os, threading, csv, sys, uuid
from datetime import datetime, timezone

# ========= Config =========
cfg = yaml.safe_load(open("config.yaml"))

MQTT_BROKER = cfg.get("mqtt_broker", "127.0.0.1")
MQTT_PORT   = int(cfg.get("mqtt_port", 1883))
SERVER_REST = str(cfg.get("server_rest", "http://10.250.23.7:8000")).strip()
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

# ========= Early config validation =========
if any(s in SERVER_REST.lower() for s in ["<server_ip_or_host>", "<", ">"]):
    print(f"FATAL: SERVER_REST in config.yaml is still a placeholder: {SERVER_REST}")
    print("Please set server_rest to something like 'http://192.168.29.249:8000'")
    sys.exit(2)

# ========= HTTP =========
PERMANENT_4XX = {400, 401, 403, 404, 405, 409, 410, 415, 422}
HTTP_TIMEOUT = (3.5, 8.0)  # (connect, read) seconds

session = requests.Session()
# You can uncomment basic retries for transient 5xx/429 if you like:
# from requests.adapters import HTTPAdapter
# from urllib3.util.retry import Retry
# retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429,502,503,504], allowed_methods=frozenset(["POST"]))
# adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
# session.mount("http://", adapter)
# session.mount("https://", adapter)

def build_url(base: str, endpoint: str) -> str:
    return f"{base.rstrip('/')}/{endpoint.lstrip('/')}"

# ========= SQLite (thread-safe helpers) =========
conn = sqlite3.connect(LOCAL_DB, check_same_thread=False)
db_lock = threading.RLock()
with db_lock:
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS boxes (box_id TEXT PRIMARY KEY, current_order TEXT DEFAULT '000')""")
    c.execute("""CREATE TABLE IF NOT EXISTS outbox_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,              -- 'telemetry' | 'scan'
        endpoint TEXT NOT NULL,          -- 'telemetry_upload' | 'validate_scan'
        body_json TEXT NOT NULL,
        next_attempt_at INTEGER NOT NULL,
        retry_count INTEGER NOT NULL DEFAULT 0,
        last_error TEXT
    )""")
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    conn.commit()
    c.close()

def db_exec(query, params=(), *, commit=False, fetchone=False, fetchall=False):
    with db_lock:
        cur = conn.cursor()
        cur.execute(query, params)
        res = None
        if fetchone:
            res = cur.fetchone()
        elif fetchall:
            res = cur.fetchall()
        if commit:
            conn.commit()
        cur.close()
        return res

def now_epoch() -> int: return int(time.time())
def now_iso() -> str: return datetime.now(timezone.utc).isoformat()

def csv_append(path: str, headers: list, row: list):
    exists = os.path.isfile(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(headers)
        w.writerow(row)

def get_current_order(box_id):
    r = db_exec("SELECT current_order FROM boxes WHERE box_id=?", (box_id,), fetchone=True)
    if r: return r[0]
    db_exec("INSERT INTO boxes(box_id,current_order) VALUES(?,?)", (box_id,'000'), commit=True)
    return '000'

def set_current_order(box_id, order_id):
    db_exec("INSERT OR REPLACE INTO boxes(box_id,current_order) VALUES(?,?)", (box_id, order_id), commit=True)

# ========= GPS provider =========
class GPSProvider:
    def __init__(self):
        self._lat = None; self._lon = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self): self._thread.start()
    def stop(self): self._stop.set(); self._thread.join(timeout=2)
    def get(self):
        with self._lock: return self._lat, self._lon
    def _update(self, lat, lon):
        with self._lock: self._lat, self._lon = lat, lon

    def _run(self):
        if GPS_SOURCE == "fixed":
            self._update(FIXED_LAT, FIXED_LON)
            while not self._stop.is_set(): time.sleep(1); return

        if GPS_SOURCE == "none":
            while not self._stop.is_set(): time.sleep(2); return

        if GPS_SOURCE == "gpsd":
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5); s.connect((GPSD_HOST, GPSD_PORT))
                s.sendall(b'?WATCH={"enable":true,"json":true}\n')
                buf = b""; s.settimeout(1)
                while not self._stop.is_set():
                    try:
                        chunk = s.recv(4096)
                        if not chunk: time.sleep(0.5); continue
                        buf += chunk
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            try: obj = json.loads(line.decode(errors="ignore"))
                            except Exception: continue
                            if obj.get("class") == "TPV":
                                lat = obj.get("lat"); lon = obj.get("lon")
                                if isinstance(lat,(int,float)) and isinstance(lon,(int,float)):
                                    self._update(lat, lon)
                    except socket.timeout: continue
                    except Exception: time.sleep(1); continue
            except Exception:
                while not self._stop.is_set(): time.sleep(2); return

        if GPS_SOURCE == "serial":
            try:
                import serial
                ser = serial.Serial(SERIAL_DEV, 9600, timeout=1)
                while not self._stop.is_set():
                    try:
                        b = ser.readline()
                        if not b: continue
                        s = b.decode(errors="ignore").strip()
                        if s.startswith("$GPRMC") or s.startswith("$GPGGA") or s.startswith("$GNGGA"):
                            parts = s.split(",")
                            def _nmea_to_deg(val, hemi):
                                if not val or "." not in val: return None
                                head, tail = val.split(".", 1)
                                deg = int(head[:-2]); minutes = float(head[-2:] + "." + tail)
                                dec = deg + minutes/60.0
                                if hemi in ("S","W"): dec = -dec
                                return dec
                            if len(parts) >= 7:
                                lat = _nmea_to_deg(parts[3], parts[4])
                                lon = _nmea_to_deg(parts[5], parts[6])
                                if lat is not None and lon is not None:
                                    self._update(lat, lon)
                    except Exception: time.sleep(0.5); continue
            except Exception:
                while not self._stop.is_set(): time.sleep(2); return

gps = GPSProvider(); gps.start()

# ========= Outbox =========
BACKOFF_BASE = 2        # seconds
BACKOFF_MAX  = 60       # cap
CATCHUP_RATE_HZ = 5     # max sends/sec when draining

def enqueue(type_: str, endpoint: str, body: dict, initial_delay: int = 0, last_error: str = None):
    db_exec(
        "INSERT INTO outbox_queue(type, endpoint, body_json, next_attempt_at, last_error) VALUES(?,?,?,?,?)",
        (type_, endpoint.lstrip('/'), json.dumps(body), now_epoch() + initial_delay, last_error),
        commit=True
    )

def try_send_row(row):
    _id, type_, endpoint, body_json, next_at, retry_count, last_error = row
    body = json.loads(body_json)
    url = build_url(SERVER_REST, endpoint)
    try:
        print(f"[debug] retry POST {url}")
        r = session.post(url, json=body, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            db_exec("DELETE FROM outbox_queue WHERE id=?", (_id,), commit=True)
            return True, None, r
        msg = f"HTTP {r.status_code}: {r.text[:200]}"
        if r.status_code in PERMANENT_4XX:
            db_exec("DELETE FROM outbox_queue WHERE id=?", (_id,), commit=True)
            return False, f"permanent:{msg}", r
        return False, msg, r
    except Exception as e:
        return False, str(e), None

def worker_outbox():
    while True:
        due = db_exec(
            "SELECT id,type,endpoint,body_json,next_attempt_at,retry_count,last_error FROM outbox_queue WHERE next_attempt_at <= ? ORDER BY id LIMIT 50",
            (now_epoch(),), fetchall=True
        ) or []
        if not due:
            time.sleep(1); continue
        for row in due:
            ok, err, resp = try_send_row(row)
            if ok:
                time.sleep(1.0 / CATCHUP_RATE_HZ)
                continue
            _id, type_, endpoint, body_json, next_at, retry_count, last_error = row
            if isinstance(err, str) and err.startswith("permanent:"):
                print(f"[outbox] dropped permanent failure id={_id} err={err}")
                continue
            retry_count += 1
            delay = min(BACKOFF_BASE * (2 ** (retry_count - 1)), BACKOFF_MAX)
            db_exec(
                "UPDATE outbox_queue SET retry_count=?, next_attempt_at=?, last_error=? WHERE id=?",
                (retry_count, now_epoch() + delay, err, _id), commit=True
            )
            time.sleep(0.2)

threading.Thread(target=worker_outbox, daemon=True).start()

# ========= Send wrapper =========
def forward_json(endpoint: str, body: dict, type_: str):
    endpoint = endpoint.lstrip('/')
    url = build_url(SERVER_REST, endpoint)
    try:
        print(f"[debug] POST {url}")
        r = session.post(url, json=body, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            return True, r
        msg = f"HTTP {r.status_code}: {r.text[:200]}"
        if r.status_code in PERMANENT_4XX:
            print(f"[forward_json] permanent failure, not enqueuing: {msg}")
            return False, r
        enqueue(type_, endpoint, body, initial_delay=2, last_error=msg)
        return False, r
    except Exception as e:
        enqueue(type_, endpoint, body, initial_delay=2, last_error=str(e))
        return False, None

# ========= Telemetry =========
def handle_telemetry(box_id, payload_from_device):
    cur_order = get_current_order(box_id)

    # Read & normalize device payload
    inner = dict(payload_from_device or {})
    if "Temperature" in inner and "temperature" not in inner:
        inner["temperature"] = inner["Temperature"]

    # GPS & device ts
    lat, lon = gps.get()
    device_ts = int(inner.get("ts", int(time.time())))
    temperature = inner.get("temperature")

    # If not attached, just log locally and return (policy)
    if not cur_order or cur_order == '000':
        print(f"[telemetry] box {box_id} not attached to any order — logging locally only")
        csv_append(TELEM_CSV,
                   ["recv_ts_iso","box_id","device_ts","temperature","truck_lat","truck_lon","order_id","forwarded"],
                   [now_iso(), box_id, device_ts, temperature, lat, lon, None, False])
        return

    # Populate nested payload with order_id + GPS (back-compat)
    inner["order_id"] = inner.get("order_id", cur_order)
    inner["lat"] = lat
    inner["lon"] = lon

    # Build body with top-level duplicates for audit
    body = {
        "message_id": f"{box_id}-{device_ts}",   # helps server dedupe
        "device_id": box_id,
        "ts": device_ts,

        # Top-level duplicates for audit log
        "order_id": cur_order,
        "temperature": temperature,
        "truck_lat": lat,
        "truck_lon": lon,

        # Optional conventional GPS object
        "gps": {"lat": lat, "lon": lon},

        # Original nested payload
        "payload": inner
    }

    ok, resp = forward_json("telemetry_upload", body, type_="telemetry")
    print("[telemetry] forwarded:", ok, "for box", box_id, f"(http={getattr(resp,'status_code', 'net')})")

    csv_append(TELEM_CSV,
               ["recv_ts_iso","box_id","device_ts","temperature","truck_lat","truck_lon","order_id","forwarded"],
               [now_iso(), box_id, device_ts, temperature, lat, lon, cur_order, bool(ok)])

# ========= Scans =========
def _scan_payload(box_id, token, order_id: str | None):
    p = {
        "passkey_string": token,
        "device_chain": {"box_id": box_id, "truck_id": TRUCK_ID}
    }
    if isinstance(order_id, str) and order_id.strip():
        p["order_id"] = order_id.strip()
    return p

def handle_scan_from_passkey_json(box_id, passkey_obj: dict):
    token = passkey_obj.get("passkey_string") or passkey_obj.get("token") or passkey_obj.get("passkey")
    role = passkey_obj.get("role")
    order_id = passkey_obj.get("order_id")
    if not token:
        print("[scan] missing passkey_string in JSON"); return

    if not order_id:
        cur_order = get_current_order(box_id)
        if cur_order != '000': order_id = cur_order

    payload = _scan_payload(box_id, token, order_id)
    ok, resp = forward_json("validate_scan", payload, type_="scan")
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
    cur_order = get_current_order(box_id)
    order_id = None if cur_order == '000' else cur_order
    payload = _scan_payload(box_id, token, order_id)

    ok, resp = forward_json("validate_scan", payload, type_="scan")
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

# ========= MQTT =========
def on_connect(client, userdata, flags, rc):
    print("connected rc", rc)
    client.subscribe("boxes/+/telemetry")
    client.subscribe("boxes/+/scan")

def on_message(client, userdata, msg):
    topic = msg.topic
    parts = topic.split('/')
    if len(parts) >= 3 and parts[0] == 'boxes':
        box_id = parts[1]; typ = parts[2]
        try:
            payload = json.loads(msg.payload.decode())
        except Exception:
            payload = None

        if typ == 'telemetry':
            inner = payload.get('payload', payload) if isinstance(payload, dict) else {}
            handle_telemetry(box_id, inner)

        elif typ == 'scan':
            if isinstance(payload, dict) and ("passkey_string" in payload or "token" in payload or "passkey" in payload):
                handle_scan_from_passkey_json(box_id, payload)
            else:
                token = None
                if isinstance(payload, str):
                    token = payload.strip()
                elif payload is None:
                    try: token = msg.payload.decode().strip()
                    except Exception: token = None
                else:
                    token = (payload.get("data") if isinstance(payload, dict) else None) or token
                if not token:
                    print("[scan] no token found in message for box", box_id); return
                handle_scan_token_only(box_id, token)

if __name__ == "__main__":
    client = mqtt.Client("truck_agent")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_start()
    print("truck agent running. local DB:", LOCAL_DB, "logs dir:", LOG_DIR, "gps source:", GPS_SOURCE, "server:", SERVER_REST)
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        gps.stop()
        client.loop_stop()
        client.disconnect()

