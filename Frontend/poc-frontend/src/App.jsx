import React, { useEffect, useState } from "react";
import "./poc.css"; // keep this import

// -----------------------
// Helper: parse CSV
// -----------------------
function parseCSV(text) {
  const rows = [];
  let i = 0,
    field = "",
    row = [],
    inQuotes = false;
  const pushField = () => {
    row.push(field);
    field = "";
  };
  const pushRow = () => {
    rows.push(row);
    row = [];
  };

  while (i < text.length) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else {
      if (ch === '"') inQuotes = true;
      else if (ch === ",") pushField();
      else if (ch === "\n") {
        pushField();
        pushRow();
      } else if (ch === "\r") {
        if (text[i + 1] === "\n") {
          i++;
        }
        pushField();
        pushRow();
      } else field += ch;
    }
    i++;
  }
  if (field.length || row.length) {
    pushField();
    pushRow();
  }
  return rows.filter((r) => r.length && r.some((c) => c !== ""));
}

// -----------------------
// Helper: local storage
// -----------------------
function useLocalStorage(key, initial) {
  const [val, setVal] = useState(() => {
    try {
      const v = localStorage.getItem(key);
      return v ? JSON.parse(v) : initial;
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(val));
    } catch {}
  }, [key, val]);
  return [val, setVal];
}

// -----------------------
// Helper: toast
// -----------------------
function Toast({ text, kind = "info" }) {
  return <div className={`toast toast--${kind}`}>{text}</div>;
}

// -----------------------
// Skeleton loader
// -----------------------
function Skeleton({ rows = 5 }) {
  return (
    <div className="skeleton">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skeleton__row" />
      ))}
    </div>
  );
}

// -----------------------
// Temperature coloring helpers
// -----------------------
function classifyTemp(val) {
  const x = parseFloat(String(val ?? "").replace(/[^0-9.+-]/g, ""));
  if (Number.isNaN(x)) return null;
  if (x >= 4 && x <= 6) return "ok";
  if ((x >= 2 && x < 4) || (x > 6 && x <= 8)) return "warn";
  return "bad";
}

function TemperatureTag({ value }) {
  const cls = classifyTemp(value);
  if (!cls) return <span>{value}</span>;
  return <span className={`temp temp--${cls}`}>{value}</span>;
}

const TEMP_HEADER_CANDIDATES = new Set([
  "temperature",
  "temp",
  "temp_c",
  "temperature_c",
]);

// -----------------------
// Status badges
// -----------------------
function Badge({ children, color = "blue" }) {
  return <span className={`badge badge--${color}`}>{children}</span>;
}

const statusColor = (s) =>
  ({
    CREATED: "yellow",
    IN_TRANSIT: "blue",
    DELIVERED: "green",
  }[s] || "gray");

const statusHint = (s) =>
  ({
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

// -----------------------
// Main App
// -----------------------
export default function App() {
  const [apiBase, setApiBase] = useLocalStorage(
    "poc_api",
    "http://127.0.0.1:8000"
  );
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const [newOrderId, setNewOrderId] = useState("");

  const [csvPreview, setCsvPreview] = useState({
    title: "",
    headers: [],
    rows: [],
  });
  const [csvOpen, setCsvOpen] = useState(false);

  const showToast = (text, kind = "info", ms = 2200) => {
    setToast({ text, kind });
    window.clearTimeout(showToast._t);
    showToast._t = window.setTimeout(() => setToast(null), ms);
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

  useEffect(() => {
    loadOrders();
    // eslint-disable-next-line
  }, [apiBase]);

  const createOrder = async () => {
    if (!newOrderId.trim()) {
      showToast("Enter an order id", "err");
      return;
    }
    try {
      await fetchJSON(`${apiBase}/create_order`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ order_id: newOrderId.trim() }),
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
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener";
    a.click();
  };

  const openAuditPreview = async (orderId) => {
    try {
      const text = await fetchText(`${apiBase}/orders/${orderId}/audit/download`);
      const rows = parseCSV(text);
      if (!rows.length) {
        showToast("Empty audit", "info");
        return;
      }
      const [headers, ...rest] = rows;
      setCsvPreview({ title: `Audit – ${orderId}`, headers, rows: rest });
      setCsvOpen(true);
    } catch (e) {
      showToast(`Audit fetch failed: ${e.message}`, "err");
    }
  };

  const temperatureColIndex = (() => {
    if (!csvPreview.headers?.length) return -1;
    return csvPreview.headers.findIndex((h) =>
      TEMP_HEADER_CANDIDATES.has(String(h).trim().toLowerCase())
    );
  })();

  return (
    <div className="app">
      <header className="header">
        <div className="container header__inner">
          <div className="brand">
            <div className="brand__logo">❄️</div>
            <div className="brand__title">Cold-Chain Handover POC</div>
          </div>
          <div className="header__controls">
            <div className="input-group">
              <label className="label">API Base</label>
              <input
                className="input"
                value={apiBase}
                onChange={(e) => setApiBase(e.target.value)}
                placeholder="http://127.0.0.1:8000"
              />
            </div>
            <button onClick={loadOrders} className="btn btn--dark">
              Reload
            </button>
          </div>
        </div>
      </header>

      <main className="container space-y">
        {/* Create Order */}
        <section className="card">
          <div className="card__grid">
            <div className="input-group">
              <label className="label">New Order ID</label>
              <input
                className="input"
                value={newOrderId}
                onChange={(e) => setNewOrderId(e.target.value)}
                placeholder="e.g. ORDER123"
              />
              <div className="hint">
                Creates the order and issues a Sender passkey JSON on the server.
              </div>
            </div>
            <div className="card__actions">
              <button onClick={createOrder} className="btn btn--primary">
                Create
              </button>
            </div>
          </div>
        </section>

        {/* Orders List */}
        <section className="card">
          <div className="card__header">
            <h2 className="card__title">Orders</h2>
            {loading && <span className="muted">Loading…</span>}
          </div>

          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Order ID</th>
                  <th>Status</th>
                  <th>Box</th>
                  <th>Truck</th>
                  <th>Created</th>
                  <th style={{ width: 340 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {!loading &&
                  orders.map((o) => (
                    <tr key={o.order_id}>
                      <td className="mono">{o.order_id}</td>
                      <td>
                        <Badge color={statusColor(o.status)}>{o.status}</Badge>
                      </td>
                      <td>{o.box_id || <span className="muted">—</span>}</td>
                      <td>{o.truck_id || <span className="muted">—</span>}</td>
                      <td>{o.created_at || <span className="muted">—</span>}</td>
                      <td>
                        <div className="hint">{statusHint(o.status)}</div>
                        <div className="actions">
                          <button
                            onClick={() => openAuditPreview(o.order_id)}
                            className="btn btn--dark"
                          >
                            View Audit
                          </button>
                          <button
                            onClick={() =>
                              download(
                                `${apiBase}/orders/${o.order_id}/audit/download`
                              )
                            }
                            className="btn btn--outline"
                          >
                            Download CSV
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                {loading && (
                  <tr>
                    <td colSpan={6}>
                      <Skeleton rows={6} />
                    </td>
                  </tr>
                )}
                {!loading && !orders.length && (
                  <tr>
                    <td className="center muted" colSpan={6}>
                      No orders found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* CSV Preview Modal */}
        {csvOpen && (
          <div className="modal" onClick={() => setCsvOpen(false)}>
            <div className="modal__dialog" onClick={(e) => e.stopPropagation()}>
              <div className="modal__header">
                <div className="modal__title">{csvPreview.title}</div>
                <button
                  className="btn btn--dark"
                  onClick={() => setCsvOpen(false)}
                >
                  Close
                </button>
              </div>
              <div className="modal__body">
                {/* Legend */}
                <div className="legend">
                  <span className="legend__item">
                    <span className="legend__swatch swatch--ok" />
                    4–6°C Normal
                  </span>
                  <span className="legend__item">
                    <span className="legend__swatch swatch--warn" />
                    2–4 / 6–8°C Warning
                  </span>
                  <span className="legend__item">
                    <span className="legend__swatch swatch--bad" />
                    Anomaly
                  </span>
                </div>

                <div className="table-wrap">
                  <table className="table table--compact">
                    <thead>
                      <tr>
                        {csvPreview.headers.map((h, i) => (
                          <th key={i}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {csvPreview.rows.map((r, i) => (
                        <tr key={i}>
                          {r.map((c, j) => (
                            <td key={j}>
                              {j === temperatureColIndex ? (
                                <TemperatureTag value={c} />
                              ) : (
                                c
                              )}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {toast && <Toast text={toast.text} kind={toast.kind} />}
      <footer className="footer">
        © {new Date().getFullYear()} Cold-Chain POC
      </footer>
    </div>
  );
}
