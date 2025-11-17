import React, { useState, useEffect } from "react";
import { listDevices, createDevice, deleteDevice } from "../services/api";

export default function AdminDevices() {
  const [devices, setDevices] = useState([]);
  const [id, setId] = useState("");
  const [dtype, setDtype] = useState("box");

  useEffect(()=>{ load(); }, []);
  const load = async () => { try { const r = await listDevices(); setDevices(r.devices || []); } catch (e) { alert(e.message); } };

  const add = async () => {
    try {
      await createDevice({ device_id: id, device_type: dtype });
      setId("");
      await load();
      alert("Device added");
    } catch (e) { alert(e.message); }
  };

  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h3>Manage Devices</h3>
      <div style={{ display: "flex", gap: 8 }}>
        <input className="input" placeholder="Device ID" value={id} onChange={e=>setId(e.target.value)} />
        <select className="input" value={dtype} onChange={e=>setDtype(e.target.value)}><option>box</option><option>truck</option></select>
        <button className="btn btn--primary" onClick={add}>Add</button>
      </div>
      <div className="table-wrap" style={{ marginTop: 8 }}>
        <table className="table"><thead><tr><th>Device</th><th>Type</th><th>Actions</th></tr></thead><tbody>
          {devices.map(d => <tr key={d.device_id}><td className="mono">{d.device_id}</td><td>{d.device_type}</td><td><button className="btn btn--outline" onClick={()=>{ if(!confirm("Delete?")) return; deleteDevice(d.device_id).then(load); }}>Delete</button></td></tr>)}
        </tbody></table>
      </div>
    </div>
  );
}
