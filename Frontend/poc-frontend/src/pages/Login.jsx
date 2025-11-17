import React, { useState } from "react";
import { login, storeAuth } from "../services/api";
import { useNavigate } from "react-router-dom";

export default function Login() {
  const [email, setEmail] = useState("");
  const [pass, setPass] = useState("");
  const nav = useNavigate();

  const doLogin = async () => {
    try {
      const data = await login(email, pass);
      console.log("login response:", data);
      if (!data || typeof data !== "object" || !data.access_token || !data.user) {
        alert("Login returned unexpected response. Check server logs.");
        return;
      }
      storeAuth(data);
      nav("/");
    } catch (e) {
      alert("Login failed: " + e.message);
    }
  };

  return (
    <div className="card" style={{ maxWidth: 480, margin: "18px auto" }}>
      <h2>Login</h2>
      <div style={{ display: "grid", gap: 8 }}>
        <label>Email</label>
        <input className="input" value={email} onChange={(e)=>setEmail(e.target.value)} />
        <label>Password</label>
        <input className="input" type="password" value={pass} onChange={(e)=>setPass(e.target.value)} />
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn--primary" onClick={doLogin}>Login</button>
        </div>
        <div className="muted small">Registration is root-only. Contact admin.</div>
      </div>
    </div>
  );
}
