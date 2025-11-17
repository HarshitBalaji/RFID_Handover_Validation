// src/pages/Dashboard.jsx
import React, { useEffect, useState } from "react";
import { listOrders, acceptOrder, downloadSenderPasskey, downloadReceiverPasskey, getMyGeofence, getUser } from "../services/api";
import AdminUsers from "../components/AdminUsers";
import AdminDevices from "../components/AdminDevices";
import GeofenceEditor from "../components/GeofenceEditor";

export default function Dashboard() {
  const me = JSON.parse(localStorage.getItem("poc_user"));
  const [orders, setOrders] = useState([]);
  const [geofence, setGeofence] = useState(null);
  const [showGf, setShowGf] = useState(false);

  const load = async () => {
    try {
      const data = await listOrders();
      setOrders(data.orders || []);
      if (me && me.role !== "root") {
        const gf = await getMyGeofence();
        setGeofence(gf.geofence || null);
      }
    } catch (e) {
      alert("Load orders failed: " + e.message);
    }
  };

  useEffect(() => { load(); }, []);

  const doAccept = async (oid) => {
    if (!confirm("Accept this order and become sender?")) return;
    try {
      await acceptOrder(oid);
      await load();
      alert("Accepted; you can now download the sender passkey.");
    } catch (e) { alert("Accept failed: " + e.message); }
  };

  const downloadSender = async (oid) => {
    try {
      const res = await downloadSenderPasskey(oid);
      // show the passkey JSON to user and allow copy
      const txt = JSON.stringify(res, null, 2);
      const w = window.open();
      w.document.body.innerText = txt;
    } catch (e) { alert("Download sender passkey failed: " + e.message); }
  };

  const downloadReceiver = async (oid) => {
    try {
      const res = await downloadReceiverPasskey(oid);
      const txt = JSON.stringify(res, null, 2);
      const w = window.open();
      w.document.body.innerText = txt;
    } catch (e) { alert("Receiver passkey not available or download failed: " + e.message); }
  };

  return (
    <div>
      <h2>Dashboard - {me ? me.username || me.email : ""}</h2>

      {me && me.role === "root" && (
        <>
          <AdminUsers />
          <AdminDevices />
        </>
      )}

      {me && me.role !== "root" && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <div><h3>Geofence</h3></div>
            <div><button className="btn btn--outline" onClick={() => setShowGf(true)}>Edit</button></div>
          </div>
          <div>{geofence ? <div>radius: {geofence.radius_m} m</div> : <div className="muted">No geofence</div>}</div>
        </div>
      )}

      <div className="card">
        <h3>Orders</h3>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Order</th><th>Status</th><th>Receiver</th><th>Sender</th><th>Blood</th><th>Actions</th></tr></thead>
            <tbody>
              {orders.map(o => (
                <tr key={o.order_id}>
                  <td className="mono">{o.order_id}</td>
                  <td>{o.status}</td>
                  <td>{o.receiver_user_id ? `User ${o.receiver_user_id}` : "-"}</td>
                  <td>{o.sender_user_id ? `User ${o.sender_user_id}` : "-"}</td>
                  <td>{o.blood_type} x {o.blood_bags}</td>
                  <td>
                    {o.status === "AWAITING_SENDER_ASSIGNMENT" && me && me.role !== "root" && (
                      <button className="btn btn--primary" onClick={() => doAccept(o.order_id)}>Accept (become sender)</button>
                    )}
                    {o.status === "CREATED" && me && me.role !== "root" && o.sender_user_id === me.id && (
                      <button className="btn btn--outline" onClick={() => downloadSender(o.order_id)}>Download Sender Passkey</button>
                    )}
                    {o.status === "CREATED" && me && me.role !== "root" && o.receiver_user_id === me.id && (
                      <button className="btn btn--outline" onClick={() => downloadReceiver(o.order_id)}>Download Receiver Passkey</button>
                    )}
                    <button className="btn btn--ghost" onClick={() => window.open(`${localStorage.getItem("poc_api") || "http://127.0.0.1:8000"}/orders/${o.order_id}/audit/download`)}>Audit</button>
                  </td>
                </tr>
              ))}
              {!orders.length && <tr><td colSpan={6} className="muted">No orders</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {showGf && <GeofenceEditor onClose={() => { setShowGf(false); load(); }} />}
    </div>
  );
}
