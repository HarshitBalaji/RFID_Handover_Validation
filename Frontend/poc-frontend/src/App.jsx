import React, { useEffect, useState } from "react";

// ----- Minimal React Single-File Frontend for the POC -----
// Drop this into any Vite/CRA project OR serve via a simple React host.
// Features:
// - Configurable API base URL (persisted to localStorage)
// - List orders
// - Create order (POC: user-provided string)
// - Download/preview Audit CSV & Final Export CSV
// - Status badges, status hints, simple toasts, and loading states
// Styling: TailwindCSS classes (works even if Tailwind isn't present; it's still readable)
// ---------------------------------------------------------------------------

// Small CSV parser (no external deps)
function parseCSV(text) {
  const rows = [];
  let i = 0;
  let field = "";
  let row = [];
  let inQuotes = false;
  const pushField = () => { row.push(field); field = ""; };
  const pushRow = () => { rows.push(row); row = []; };
  while (i < text.length) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else { inQuotes = false; }
      } else { field += ch; }
    } else {
      if (ch === '"') inQuotes = true;
      else if (ch === ',') pushField();
      else if (ch === '')
       { pushField(); pushRow(); }
      else field += ch;
    }
    i++;
  }
  if (field.length || row.length) { pushField(); pushRow(); }
  return rows.filter(r => r.length && r.some(c => c !== ""));
}

function Badge({ children, color = "blue" }) {
  const cls = {
    blue: "bg-blue-100 text-blue-800",
    green: "bg-green-100 text-green-800",
    yellow: "bg-yellow-100 text-yellow-800",
    gray: "bg-gray-100 text-gray-800",
    red: "bg-red-100 text-red-800",
  }[color] || "bg-gray-100 text-gray-800";
  return <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${cls}`}>{children}</span>;
}

function useLocalStorage(key, initial) {
  const [val, setVal] = useState(() => {
    const v = localStorage.getItem(key); return v ? JSON.parse(v) : initial;
  });
  useEffect(() => { localStorage.setItem(key, JSON.stringify(val)); }, [key, val]);
  return [val, setVal];
}

const statusColor = (s) => ({
  CREATED: "yellow",
  IN_TRANSIT: "blue",
  DELIVERED: "green",
}[s] || "gray");

// Helper hint text per status
const statusHint = (s) => ({
  CREATED: "Next: Scan Sender tag at pickup to start tracking.",
  IN_TRANSIT: "Next: Scan Receiver tag at delivery to complete the order.",
  DELIVERED: "Order completed. Final export available.",
}[s] || "");

async function fetchJSON(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return await r.json();
}

async function fetchText(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return await r.text();
}

function Toast({ text, kind = "info" }) {
  const colors = {
    info: "bg-slate-800 text-white",
    ok: "bg-emerald-600 text-white",
    err: "bg-rose-600 text-white",
  };
  return <div className={`fixed bottom-4 right-4 px-4 py-2 rounded-lg shadow ${colors[kind]}`}>{text}</div>;
}

export default function App() {
  const [apiBase, setApiBase] = useLocalStorage("poc_api", "http://127.0.0.1:8000");
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const [newOrderId, setNewOrderId] = useState("");

  const [csvPreview, setCsvPreview] = useState({ title: "", headers: [], rows: [] });
  const [csvOpen, setCsvOpen] = useState(false);

  const showToast = (text, kind = "info", ms = 2200) => {
    setToast({ text, kind });
    setTimeout(() => setToast(null), ms);
  };

  const loadOrders = async () => {
    setLoading(true);
    try {
      const data = await fetchJSON(`${apiBase}/orders`);
      setOrders(data.orders || []);
    } catch (e) {
      showToast(`Failed to load orders: ${e.message}`, "err");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadOrders(); }, [apiBase]);

  const createOrder = async () => {
    if (!newOrderId.trim()) { showToast("Enter an order id", "err"); return; }
    try {
      await fetchJSON(`${apiBase}/create_order`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ order_id: newOrderId.trim() })
      });
      setNewOrderId("");
      showToast("Order created & sender passkey issued", "ok");
      loadOrders();
    } catch (e) {
      showToast(`Create failed: ${e.message}`, "err");
    }
  };

  const download = (url) => {
    const a = document.createElement("a");
    a.href = url; a.target = "_blank"; a.rel = "noopener"; a.click();
  };

  const openAuditPreview = async (orderId) => {
    try {
      const text = await fetchText(`${apiBase}/orders/${orderId}/audit/download`);
      const rows = parseCSV(text);
      if (!rows.length) { showToast("Empty audit", "info"); return; }
      const [headers, ...rest] = rows;
      setCsvPreview({ title: `Audit – ${orderId}`, headers, rows: rest });
      setCsvOpen(true);
    } catch (e) {
      showToast(`Audit fetch failed: ${e.message}`, "err");
    }
  };

  const openExportPreview = async (orderId) => {
    try {
      const text = await fetchText(`${apiBase}/orders/${orderId}/export`);
      const rows = parseCSV(text);
      if (!rows.length) { showToast("Empty export", "info"); return; }
      const [headers, ...rest] = rows;
      setCsvPreview({ title: `Export – ${orderId}`, headers, rows: rest });
      setCsvOpen(true);
    } catch (e) {
      showToast(`Export fetch failed: ${e.message}`, "err");
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="sticky top-0 z-10 bg-white border-b">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="font-semibold text-lg">Cold-Chain Handover POC</div>
          <div className="flex items-center gap-2">
            <input
              className="border rounded px-3 py-1 text-sm w-72"
              value={apiBase}
              onChange={(e) => setApiBase(e.target.value)}
              placeholder="http://127.0.0.1:8000"
            />
            <button onClick={loadOrders} className="px-3 py-1 rounded bg-slate-800 text-white text-sm">Reload</button>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-8">
        {/* Create Order */}
        <section className="bg-white rounded-2xl shadow p-4">
          <div className="flex items-end gap-3">
            <div className="flex-1">
              <label className="block text-xs text-slate-500">New Order ID</label>
              <input className="border rounded w-full px-3 py-2" value={newOrderId} onChange={e => setNewOrderId(e.target.value)} placeholder="e.g. ORDER123" />
            </div>
            <button onClick={createOrder} className="px-4 py-2 rounded bg-emerald-600 text-white">Create</button>
          </div>
          <p className="text-xs text-slate-500 mt-2">Creates order in state <strong>CREATED</strong> and issues Sender passkey JSON file on the server.</p>
        </section>

        {/* Orders List */}
        <section className="bg-white rounded-2xl shadow p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-semibold">Orders</h2>
            {loading && <span className="text-xs text-slate-500">Loading…</span>}
          </div>
          <div className="overflow-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left bg-slate-100">
                  <th className="px-3 py-2">Order ID</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Box</th>
                  <th className="px-3 py-2">Truck</th>
                  <th className="px-3 py-2">Created</th>
                  <th className="px-3 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {orders.map((o) => (
                  <tr key={o.order_id} className="border-t">
                    <td className="px-3 py-2 font-mono">{o.order_id}</td>
                    <td className="px-3 py-2"><Badge color={statusColor(o.status)}>{o.status}</Badge></td>
                    <td className="px-3 py-2">{o.box_id || <span className="text-slate-400">—</span>}</td>
                    <td className="px-3 py-2">{o.truck_id || <span className="text-slate-400">—</span>}</td>
                    <td className="px-3 py-2">{o.created_at || <span className="text-slate-400">—</span>}</td>
                    <td className="px-3 py-2">
                      <div className="text-xs text-slate-500 mb-1">{statusHint(o.status)}</div>
                      <div className="flex flex-wrap gap-2">
                        <button onClick={() => openAuditPreview(o.order_id)} className="px-3 py-1 rounded bg-slate-700 text-white">View Audit</button>
                        <button onClick={() => download(`${apiBase}/orders/${o.order_id}/audit/download`)} className="px-3 py-1 rounded border">Download Audit (CSV)</button>
                        {o.status === 'DELIVERED' && (
                          <>
                            <button onClick={() => openExportPreview(o.order_id)} className="px-3 py-1 rounded bg-teal-600 text-white">View Final Export</button>
                            <button onClick={() => download(`${apiBase}/orders/${o.order_id}/export`)} className="px-3 py-1 rounded border">Download Final Export (CSV)</button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {!orders.length && (
                  <tr><td className="px-3 py-6 text-center text-slate-400" colSpan={6}>No orders found</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* CSV Preview Modal */}
        {csvOpen && (
          <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-20">
            <div className="bg-white rounded-2xl shadow-2xl w-full max-w-4xl max-h-[80vh] flex flex-col">
              <div className="px-4 py-3 border-b flex items-center justify-between">
                <div className="font-semibold">{csvPreview.title}</div>
                <button className="px-3 py-1 rounded bg-slate-800 text-white" onClick={() => setCsvOpen(false)}>Close</button>
              </div>
              <div className="p-4 overflow-auto">
                <table className="min-w-full text-xs">
                  <thead>
                    <tr>
                      {csvPreview.headers.map((h, i) => (
                        <th key={i} className="text-left px-2 py-1 bg-slate-100 sticky top-0">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {csvPreview.rows.map((r, i) => (
                      <tr key={i} className="border-t">
                        {r.map((c, j) => <td key={j} className="px-2 py-1 align-top">{c}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </main>

      {toast && <Toast text={toast.text} kind={toast.kind} />}
    </div>
  );
}
