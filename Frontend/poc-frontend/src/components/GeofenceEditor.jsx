import React, { useEffect, useState } from "react";
import { MapContainer, TileLayer, Marker, Circle, useMapEvents } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import { getMyGeofence, upsertGeofence } from "../services/api";

function ClickMarker({ setPos }) {
  useMapEvents({ click(e) { setPos([e.latlng.lat, e.latlng.lng]); } });
  return null;
}

export default function GeofenceEditor({ onClose }) {
  const [pos, setPos] = useState([12.9716,77.5946]);
  const [radius, setRadius] = useState(100);

  useEffect(()=>{ (async ()=>{ try { const res = await getMyGeofence(); if(res.geofence && res.geofence.center_lat){ setPos([Number(res.geofence.center_lat), Number(res.geofence.center_lon)]); setRadius(res.geofence.radius_m || 100); } }catch{} })(); }, []);

  const save = async () => {
    try {
      await upsertGeofence({ center: { lat: pos[0], lon: pos[1] }, radius_m: Number(radius) });
      alert("Saved");
      onClose();
    } catch (e) { alert("Save failed: " + e.message); }
  };

  return (
    <div className="modal-overlay">
      <div className="modal">
        <h3>Edit Geofence</h3>
        <div style={{ height: 320 }}>
          <MapContainer center={pos} zoom={15} style={{ height: "100%", width: "100%" }}>
            <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
            <ClickMarker setPos={setPos} />
            <Marker position={pos} />
            <Circle center={pos} radius={Number(radius)} />
          </MapContainer>
        </div>
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <input className="input" value={radius} onChange={e=>setRadius(e.target.value)} />
          <button className="btn btn--primary" onClick={save}>Save</button>
          <button className="btn btn--ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
