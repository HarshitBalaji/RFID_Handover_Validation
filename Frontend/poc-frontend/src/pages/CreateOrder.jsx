import React, { useState } from "react";
import { createOrder } from "../services/api";
import { useNavigate } from "react-router-dom";

export default function CreateOrder() {
  const [bloodType, setBloodType] = useState("A+");
  const [bloodBags, setBloodBags] = useState(1);
  const nav = useNavigate();

  const submit = async () => {
    try {
      await createOrder({ blood_type: bloodType, blood_bags: Number(bloodBags) });
      alert("Order created");
      nav("/");
    } catch (e) {
      alert("Create failed: " + e.message);
    }
  };

  return (
    <div className="card" style={{ maxWidth: 640, margin: "12px auto" }}>
      <h2>Create Order</h2>
      <div style={{ display: "grid", gap: 8 }}>
        <label>Blood Type</label>
        <select className="input" value={bloodType} onChange={(e)=>setBloodType(e.target.value)}>
          {["A+","A-","B+","B-","AB+","AB-","O+","O-"].map(b => <option key={b} value={b}>{b}</option>)}
        </select>
        <label>Number of Bags</label>
        <input className="input" type="number" value={bloodBags} onChange={(e) => setBloodBags(e.target.value)} />
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn--primary" onClick={submit}>Create</button>
          <button className="btn btn--ghost" onClick={() => nav("/")}>Cancel</button>
        </div>
      </div>
    </div>
  );
}
