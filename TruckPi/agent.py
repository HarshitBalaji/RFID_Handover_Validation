# --- COMPLETE: truck_agent.py with MQTT TLS + Truck Attestation ---

import paho.mqtt.client as mqtt
import json, sqlite3, yaml, time, requests, os, threading, csv, sys, uuid, base64, ssl
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# ========= Config =========
cfg = yaml.safe_load(open("config.yaml"))

MQTT_BROKER = cfg.get("mqtt_broker", "broker.example.local")
MQTT_PORT   = int(cfg.get("mqtt_port", 8883))
MQTT_USE_TLS = MQTT_PORT == 8883  # Auto-detect TLS from port

# TLS certificates for MQTT
MQTT_CA_CERT = cfg.get("mqtt_ca_cert", "keys/ca/ca.crt")
MQTT_CLIENT_CERT = cfg.get("mqtt_client_cert", "keys/truck/truck_client.crt")
MQTT_CLIENT_KEY = cfg.get("mqtt_client_key", "keys/truck/truck_client.key")

SERVER_REST = str(cfg.get("server_rest", "http://192.168.29.249:8000")).strip()
TRUCK_ID    = cfg.get("truck_id", "TRUCK-001")
LOCAL_DB    = cfg.get("local_db", "truck_local.db")

# Truck attestation key (can reuse MQTT client key)
TRUCK_PRIVKEY_PATH = cfg.get("truck_privkey_pem", "keys/truck/truck_client.key")

# GPS configuration
gps_cfg = cfg.get("gps", {}) or {}
GPS_SOURCE = gps_cfg.get("source", "gpsd")
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
    sys.exit(2)

# ========= Load Truck Private Key for Attestation =========

def load_truck_private_key(path: str):
    """Load truck's ECDSA private key for signing attestations"""
    try:
        with open(path, "rb") as f:
            pem_data = f.read()
            return serialization.load_pem_private_key(
                pem_data,
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        print(f"ERROR: Failed to load truck private key from {path}: {e}")
        print("Truck attestation will fail without this key!")
        return None

TRUCK_PRIVKEY = load_truck_private_key(TRUCK_PRIVKEY_PATH)

if TRUCK_PRIVKEY is None:
    print(f"WARNING: Truck private key not loaded from {TRUCK_PRIVKEY_PATH}")
    print("Attestation signatures will fail!")
else:
    print(f"✓ Truck private key loaded from {TRUCK_PRIVKEY_PATH}")

# ========= Attestation Signing =========

def sign_truck_attestation(payload: dict) -> str:
    """
    Sign a payload with truck's private key.
    Returns base64url-encoded signature.
    
    The payload must NOT contain 'truck_sig' field.
    """
    if TRUCK_PRIVKEY is None:
        raise RuntimeError("Truck private key not loaded - cannot sign attestation")
    
    # Check if it's an EC key
    if not isinstance(TRUCK_PRIVKEY, ec.EllipticCurvePrivateKey):
        raise RuntimeError(f"Truck key is not EC key, got {type(TRUCK_PRIVKEY)}")
    
    # Canonical JSON (sorted keys, no spaces)
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    
    # Sign with ECDSA
    signature = TRUCK_PRIVKEY.sign(data, ec.ECDSA(hashes.SHA256()))
    
    # Return base64url-encoded (no padding)
    return base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

# ========= HTTP =========
PERMANENT_4XX = {400, 401, 403, 404, 405, 409, 410, 415, 422}
HTTP_TIMEOUT = (3.5, 8.0)

session = requests.Session()

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
        type TEXT NOT NULL,
        endpoint TEXT NOT NULL,
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
            print(f"GPS: Using fixed location ({FIXED_LAT}, {FIXED_LON})")
            while not self._stop.is_set(): time.sleep(1)
            return

        if GPS_SOURCE == "none":
            print("GPS: Disabled")
            while not self._stop.is_set(): time.sleep(2)
            return

        if GPS_SOURCE == "gpsd":
            print(f"GPS: Connecting to gpsd at {GPSD_HOST}:{GPSD_PORT}")
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
            except Exception as e:
                print(f"GPS: gpsd connection failed: {e}")
                while not self._stop.is_set(): time.sleep(2)
                return

        if GPS_SOURCE == "serial":
            print(f"GPS: Reading from serial {SERIAL_DEV}")
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
            except Exception as e:
                print(f"GPS: Serial connection failed: {e}")
                while not self._stop.is_set(): time.sleep(2)
                return

gps = GPSProvider(); gps.start()

# ========= Outbox =========
BACKOFF_BASE = 2
BACKOFF_MAX  = 60
CATCHUP_RATE_HZ = 5

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

    inner = dict(payload_from_device or {})
    if "Temperature" in inner and "temperature" not in inner:
        inner["temperature"] = inner["Temperature"]

    lat, lon = gps.get()
    device_ts = int(inner.get("ts", int(time.time())))
    temperature = inner.get("temperature")

    if not cur_order or cur_order == '000':
        print(f"[telemetry] box {box_id} not attached – logging locally only")
        csv_append(TELEM_CSV,
                   ["recv_ts_iso","box_id","device_ts","temperature","truck_lat","truck_lon","order_id","forwarded"],
                   [now_iso(), box_id, device_ts, temperature, lat, lon, None, False])
        return

    inner["order_id"] = inner.get("order_id", cur_order)
    inner["lat"] = lat
    inner["lon"] = lon

    # Build telemetry body WITHOUT truck_sig first
    # IMPORTANT: Only include fields that server expects in TelemetryModel
    body = {
        "device_id": box_id,
        "ts": device_ts,
        "payload": inner,
        "truck_id": TRUCK_ID
    }

    # Sign the telemetry (canonical JSON without truck_sig)
    try:
        truck_sig = sign_truck_attestation(body)
        body["truck_sig"] = truck_sig
    except Exception as e:
        print(f"[ERROR] Failed to sign telemetry: {e}")
        body["truck_sig"] = ""

    ok, resp = forward_json("telemetry_upload", body, type_="telemetry")
    
    # Enhanced logging with response details
    if ok:
        print(f"[telemetry] ✓ forwarded for box {box_id}")
    else:
        status_code = getattr(resp, 'status_code', 'network_error')
        error_text = getattr(resp, 'text', 'no response')[:100] if resp else 'connection failed'
        print(f"[telemetry] ✗ failed for box {box_id}: {status_code} - {error_text}")

    csv_append(TELEM_CSV,
               ["recv_ts_iso","box_id","device_ts","temperature","truck_lat","truck_lon","order_id","forwarded"],
               [now_iso(), box_id, device_ts, temperature, lat, lon, cur_order, bool(ok)])


# ========= Alerts =========
def handle_alert(box_id, payload_from_device):
    """
    Handle alert messages from ESP32 boxes.
    For now, just log locally - no forwarding to server.
    """
    alert_type = "unknown"
    reason = "unknown"
    temperature = None
    
    if isinstance(payload_from_device, dict):
        alert_type = payload_from_device.get("type", "unknown")
        reason = payload_from_device.get("reason", "unknown")
        temperature = payload_from_device.get("temperature")
    
    cur_order = get_current_order(box_id)
    
    print(f"[alert] ⚠️  box {box_id}: {reason} (temp={temperature}, order={cur_order})")
    
    # Log to CSV for audit
    ALERTS_CSV = os.path.join(LOG_DIR, "alerts.csv")
    csv_append(ALERTS_CSV,
               ["recv_ts_iso", "box_id", "order_id", "alert_type", "reason", "temperature"],
               [now_iso(), box_id, cur_order if cur_order != '000' else None, alert_type, reason, temperature])

# ========= Scans =========

def _scan_payload(box_id, token, order_id: str | None):
    """
    Build the payload to send to server's /validate_scan endpoint.
    Includes truck attestation (truck_id + truck_sig).
    """
    # Build payload WITHOUT truck_sig first
    payload = {
        "passkey_string": token,
        "device_chain": {"box_id": box_id, "truck_id": TRUCK_ID},
        "truck_id": TRUCK_ID
    }
    
    # Add order_id if available
    if isinstance(order_id, str) and order_id.strip():
        payload["order_id"] = order_id.strip()
    
    # Sign the payload (without truck_sig field)
    try:
        truck_sig = sign_truck_attestation(payload)
        payload["truck_sig"] = truck_sig
    except Exception as e:
        print(f"[ERROR] Failed to sign truck attestation: {e}")
        payload["truck_sig"] = ""
    
    return payload


def handle_scan_from_passkey_json(box_id, passkey_obj: dict):
    """
    Handle when ESP32 sends a FULL passkey JSON object.
    """
    token = passkey_obj.get("passkey_string")
    role = passkey_obj.get("role")
    order_id = passkey_obj.get("order_id")
    
    if not token:
        print("[scan] ERROR: missing passkey_string in JSON")
        return

    if not order_id:
        cur_order = get_current_order(box_id)
        if cur_order != '000':
            order_id = cur_order

    payload = _scan_payload(box_id, token, order_id)
    
    ok, resp = forward_json("validate_scan", payload, type_="scan")
    status = "OK" if ok else f"FAIL:{(resp.status_code if resp else 'net')}"
    print(f"[scan] validation sent (full JSON, role={role}) -> {status}")

    if ok and resp is not None and resp.status_code == 200:
        data = resp.json()
        if data.get("transition") == "IN_TRANSIT":
            set_current_order(box_id, data["order_id"])
            print(f"✓ SENDER validated: box {box_id} → order {data['order_id']}")
        elif data.get("transition") == "DELIVERED":
            set_current_order(box_id, '000')
            print(f"✓ RECEIVER validated: order {order_id} completed, box {box_id} detached")

    csv_append(SCANS_CSV,
               ["recv_ts_iso","box_id","role","order_id","forwarded","status","remarks"],
               [now_iso(), box_id, role, order_id, bool(ok), status, "full_json"])


def handle_scan_token_only(box_id, token: str):
    """
    Handle when ESP32 sends ONLY a passkey_string.
    """
    cur_order = get_current_order(box_id)
    order_id = None if cur_order == '000' else cur_order
    payload = _scan_payload(box_id, token, order_id)

    ok, resp = forward_json("validate_scan", payload, type_="scan")
    status = "OK" if ok else f"FAIL:{(resp.status_code if resp else 'net')}"
    print(f"[scan] validation sent (token only) -> {status}")

    if ok and resp is not None and resp.status_code == 200:
        data = resp.json()
        if data.get("transition") == "IN_TRANSIT":
            set_current_order(box_id, data["order_id"])
            print(f"✓ Box {box_id} → order {data['order_id']}")
        elif data.get("transition") == "DELIVERED":
            set_current_order(box_id, '000')
            print(f"✓ Order completed, box {box_id} detached")

    csv_append(SCANS_CSV,
               ["recv_ts_iso","box_id","role","order_id","forwarded","status","remarks"],
               [now_iso(), box_id, None, order_id, bool(ok), status, "token_only"])

# ========= MQTT with TLS =========

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"✓ MQTT connected to {MQTT_BROKER}:{MQTT_PORT}")
        client.subscribe("boxes/+/telemetry")
        client.subscribe("boxes/+/scan")
        client.subscribe("boxes/+/alerts")
        print("✓ Subscribed to: boxes/+/{telemetry,scan,alerts}")
    else:
        print(f"✗ MQTT connection failed with code {rc}")

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
            inner = payload.get('payload', payload) if isinstance(payload, dict) else {}
            handle_telemetry(box_id, inner)

        elif typ == 'scan':
            if isinstance(payload, dict):
                if "passkey_string" in payload:
                    print(f"[scan] Received full passkey JSON from box {box_id}")
                    handle_scan_from_passkey_json(box_id, payload)
                else:
                    token = payload.get("token") or payload.get("data") or payload.get("passkey")
                    if token:
                        print(f"[scan] Received token from dict for box {box_id}")
                        handle_scan_token_only(box_id, str(token))
                    else:
                        print(f"[scan] ERROR: dict payload but no token field")
            
            elif isinstance(payload, str):
                print(f"[scan] Received plain token string from box {box_id}")
                handle_scan_token_only(box_id, payload.strip())
            
            else:
                try:
                    token = msg.payload.decode().strip()
                    if token:
                        print(f"[scan] Received raw token from box {box_id}")
                        handle_scan_token_only(box_id, token)
                    else:
                        print(f"[scan] ERROR: empty payload from box {box_id}")
                except Exception as e:
                    print(f"[scan] ERROR: could not decode payload: {e}")

        elif typ == 'alerts':
            handle_alert(box_id, payload)

def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"✗ MQTT disconnected unexpectedly (rc={rc})")

# ========= Main =========

if __name__ == "__main__":
    print("="*60)
    print("Truck Agent Starting")
    print("="*60)
    print(f"Truck ID:     {TRUCK_ID}")
    print(f"MQTT Broker:  {MQTT_BROKER}:{MQTT_PORT} (TLS: {MQTT_USE_TLS})")
    print(f"Server REST:  {SERVER_REST}")
    print(f"Local DB:     {LOCAL_DB}")
    print(f"Logs Dir:     {LOG_DIR}")
    print(f"GPS Source:   {GPS_SOURCE}")
    print("="*60)

    # Configure MQTT client
    client = mqtt.Client("truck_agent_" + TRUCK_ID)
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    # Configure TLS if using port 8883
    if MQTT_USE_TLS:
        if not os.path.exists(MQTT_CA_CERT):
            print(f"ERROR: CA cert not found: {MQTT_CA_CERT}")
            sys.exit(1)
        if not os.path.exists(MQTT_CLIENT_CERT):
            print(f"ERROR: Client cert not found: {MQTT_CLIENT_CERT}")
            sys.exit(1)
        if not os.path.exists(MQTT_CLIENT_KEY):
            print(f"ERROR: Client key not found: {MQTT_CLIENT_KEY}")
            sys.exit(1)
        
        print(f"Configuring MQTT TLS:")
        print(f"  CA:     {MQTT_CA_CERT}")
        print(f"  Cert:   {MQTT_CLIENT_CERT}")
        print(f"  Key:    {MQTT_CLIENT_KEY}")
        
        client.tls_set(
            ca_certs=MQTT_CA_CERT,
            certfile=MQTT_CLIENT_CERT,
            keyfile=MQTT_CLIENT_KEY,
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS,
            ciphers=None
        )
        # For self-signed certs or development, you might need:
        # client.tls_insecure_set(True)
    
    print("Connecting to MQTT broker...")
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
    except Exception as e:
        print(f"FATAL: Could not connect to MQTT broker: {e}")
        sys.exit(1)
    
    client.loop_start()
    print("✓ Truck agent running")
    print("Press Ctrl+C to stop")
    print("="*60)
    
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        gps.stop()
        client.loop_stop()
        client.disconnect()
        conn.close()
        print("✓ Shutdown complete")
