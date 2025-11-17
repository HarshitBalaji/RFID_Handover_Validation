import React, { useState, useEffect } from "react";
import { listUsers, createUser, deleteUser } from "../services/api";

export default function AdminUsers() {
  const [users, setUsers] = useState([]);
  const [email, setEmail] = useState("");
  const [pass, setPass] = useState("");
  const [role, setRole] = useState("operator");

  useEffect(()=>{ load(); }, []);
  const load = async () => { try { const r = await listUsers(); setUsers(r.users || []); } catch (e) { alert(e.message); } };

  const add = async () => {
    try {
      await createUser({ email, password: pass, role });
      setEmail(""); setPass("");
      await load();
      alert("User created");
    } catch (e) { alert("Create failed: " + e.message); }
  };

  return (
    <div className="card">
      <h3>Manage Users</h3>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <input className="input" placeholder="email" value={email} onChange={e=>setEmail(e.target.value)} />
        <input className="input" placeholder="password" value={pass} onChange={e=>setPass(e.target.value)} />
        <select className="input" value={role} onChange={e=>setRole(e.target.value)}><option>operator</option><option>admin</option></select>
        <button className="btn btn--primary" onClick={add}>Create</button>
      </div>
      <div className="table-wrap" style={{ marginTop: 12 }}>
        <table className="table"><thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Actions</th></tr></thead>
        <tbody>
          {users.map(u => <tr key={u.id}><td>{u.id}</td><td>{u.email}</td><td>{u.role}</td><td><button className="btn btn--outline" onClick={()=>{ if(!confirm("Delete?")) return; deleteUser(u.id).then(load); }}>Delete</button></td></tr>)}
        </tbody></table>
      </div>
    </div>
  );
}
