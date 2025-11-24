# models.py
# --- PATCHED: models.py ---
# No breaking changes. Kept schema stable.
# Notes:
# - Status values remain: CREATED, IN_TRANSIT, DELIVERED (DELIVERED == completed).
# - Telemetry kept for downsampled server persistence.

from sqlalchemy import (
    Table, Column, Integer, String, MetaData, DateTime, Text
)
from sqlalchemy.sql import func

metadata = MetaData()

registered_devices = Table(
    "registered_devices", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("device_id", String, unique=True, nullable=False),
    Column("device_type", String),
    Column("pub_key_pem", Text),
    Column("assigned_truck", String, nullable=True),
)

orders = Table(
    "orders", metadata,
    Column("order_id", String, primary_key=True),
    Column("box_id", String, nullable=True),
    Column("truck_id", String, nullable=True),
    Column("status", String, default="CREATED"),  # CREATED, IN_TRANSIT, DELIVERED
    Column("sender_passkey_string", Text, nullable=True),
    Column("receiver_passkey_string", Text, nullable=True),
    Column("created_at", DateTime, server_default=func.now())
)

audit_log = Table(
    "audit_log", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("event_ts", DateTime, server_default=func.now()),
    Column("order_id", String, nullable=True),
    Column("device_id", String, nullable=True),
    Column("event_type", String),
    Column("remarks", Text)
)

used_passkeys = Table(
    "used_passkeys", metadata,
    Column("id", Integer, primary_key=True),
    Column("passkey_string", String, unique=True),
    Column("used_at", DateTime, server_default=func.now())
)

telemetry = Table(
    "telemetry", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("order_id", String, nullable=True),
    Column("device_id", String, nullable=False),
    Column("ts", Integer, nullable=False),
    Column("payload", Text),
    Column("created_at", DateTime, server_default=func.now())
)
