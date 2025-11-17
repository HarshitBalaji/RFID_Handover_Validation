// src/services/api.js
function _rawApiBase() {
  return localStorage.getItem("poc_api") || null;
}
function _normalizeApiBase(raw) {
  if (!raw) return "http://127.0.0.1:8000";
  let s = raw.replace(/^[\s'"]+|[\s'"]+$/g, "");
  if (s.endsWith("/")) s = s.slice(0,-1);
  return s;
}
export function getApiBase() { return _normalizeApiBase(_rawApiBase()); }
export function setApiBase(url) { localStorage.setItem("poc_api", url); }

export function setToken(token) { localStorage.setItem("poc_token", token || ""); }
export function getToken() { return localStorage.getItem("poc_token") || ""; }

export function setUser(u) { if (!u) localStorage.removeItem("poc_user"); else localStorage.setItem("poc_user", JSON.stringify(u)); }
export function getUser() { const s = localStorage.getItem("poc_user"); return s ? JSON.parse(s) : null; }

async function apiFetch(path, opts = {}) {
  if (!path.startsWith("/")) path = "/" + path;
  const base = getApiBase();
  const url = base + path;
  const headers = (opts.headers && {...opts.headers}) || {};
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let body = opts.body;
  if (body && !(body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(url, {...opts, headers, body});
  const text = await res.text().catch(()=>"");
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} ${text}`.trim());
  if (!text) return {};
  try { return JSON.parse(text); } catch { return text; }
}

// Auth
export function login(email, password) {
  return apiFetch("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
}
export function registerUser(payload) {
  return apiFetch("/auth/register", { method: "POST", body: JSON.stringify(payload) });
}

// Orders
export function createOrder(payload) { return apiFetch("/orders", { method: "POST", body: JSON.stringify(payload) }); }
export function listOrders() { return apiFetch("/orders"); }
export function acceptOrder(orderId) { return apiFetch(`/orders/${orderId}/accept`, { method: "POST" }); }
export function downloadSenderPasskey(orderId) { return apiFetch(`/orders/${orderId}/sender_passkey`); }
export function downloadReceiverPasskey(orderId) { return apiFetch(`/orders/${orderId}/receiver_passkey`); }

// Truck endpoint
export function truckValidateGeofence(body) { return apiFetch("/truck/validate_geofence", { method: "POST", body: JSON.stringify(body) }); }

// Geofence
export function getMyGeofence() { return apiFetch("/users/me/geofence"); }
export function upsertGeofence(payload) { return apiFetch("/users/me/geofence", { method: "POST", body: JSON.stringify(payload) }); }

// Admin
export function listUsers() { return apiFetch("/users"); }
export function createUser(payload) { return apiFetch("/auth/register", { method: "POST", body: JSON.stringify(payload) }); }
export function deleteUser(id) { return apiFetch(`/users/${id}`, { method: "DELETE" }); }
export function listDevices() { return apiFetch("/devices"); }
export function createDevice(payload) { return apiFetch("/devices", { method: "POST", body: JSON.stringify(payload) }); }
export function deleteDevice(id) { return apiFetch(`/devices/${id}`, { method: "DELETE" }); }

// Auth helpers
export function storeAuth(data) {
  setToken(data.access_token);
  // backend returns { user: { id, email, username, role } } now
  setUser(data.user);
}
export function logout() {
  setToken(""); setUser(null);
}
