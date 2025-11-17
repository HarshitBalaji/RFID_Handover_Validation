# models.py
# Extended schema: users + geofences + orders + devices + audit + telemetry + used_passkeys

from sqlalchemy import (
    Table, Column, Integer, String, MetaData, DateTime, Text, Boolean, ForeignKey
)
from sqlalchemy.sql import func

metadata = MetaData()

users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("email", String, unique=True, nullable=False),
    Column("hashed_password", String, nullable=False),
    Column("full_name", String, nullable=True),
    Column("role", String, nullable=False, default="operator"),  # root, admin, operator
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now())
)

geofences = Table(
    "geofences", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE")),
    Column("name", String),
    Column("type", String),  # circle | polygon
    Column("center_lat", String, nullable=True),
    Column("center_lon", String, nullable=True),
    Column("radius_m", Integer, nullable=True),
    Column("polygon_geojson", Text, nullable=True),
    Column("is_default", Boolean, default=False),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now())
)

registered_devices = Table(
    "registered_devices", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("device_id", String, unique=True, nullable=False),
    Column("device_type", String),
    Column("pub_key_pem", Text),
    Column("assigned_truck", String, nullable=True),
    Column("created_at", DateTime, server_default=func.now())
)

orders = Table(
    "orders", metadata,
    Column("order_id", String, primary_key=True),
    Column("owner_user_id", Integer, ForeignKey("users.id"), nullable=True),
    Column("sender_user_id", Integer, ForeignKey("users.id"), nullable=True),
    Column("receiver_user_id", Integer, ForeignKey("users.id"), nullable=True),
    Column("sender_name", String, nullable=True),
    Column("receiver_name", String, nullable=True),
    Column("blood_type", String, nullable=True),
    Column("blood_bags", Integer, nullable=True),
    Column("box_id", String, nullable=True),
    Column("truck_id", String, nullable=True),
    Column("status", String, default="CREATED"),  # CREATED, AWAITING_SENDER_APPROVAL, IN_TRANSIT, PENDING_CONFIRMATION, DELIVERED
    Column("sender_passkey_string", Text, nullable=True),
    Column("receiver_passkey_string", Text, nullable=True),
    Column("pending_confirmation_by", String, nullable=True),  # 'sender' or 'receiver'
    Column("pending_confirm_ts", DateTime, nullable=True),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now())
)

audit_log = Table(
    "audit_log", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("event_ts", DateTime, server_default=func.now()),
    Column("order_id", String, nullable=True),
    Column("device_id", String, nullable=True),
    Column("user_id", Integer, nullable=True),
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
