import React from "react";
import { Routes, Route, Navigate, Link, useNavigate } from "react-router-dom";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import CreateOrder from "./pages/CreateOrder";
import ProtectedRoute from "./components/ProtectedRoute";
import { getUser, logout } from "./services/api";

export default function App() {
  const user = getUser();
  const nav = useNavigate();

  return (
    <div className="app">
      <header className="header">
        <div className="container header__inner">
          <div className="brand"><div className="brand__logo">🧊</div><div className="brand__title">Cold-Chain</div></div>
          <nav className="nav">
            {user ? (
              <>
                <Link to="/">Dashboard</Link>
                {user.role !== "root" && <Link to="/create-order">Create Order</Link>}
                <span className="nav-user">{user.email} ({user.role})</span>
                <button className="btn btn--ghost" onClick={() => { logout(); nav("/login"); }}>Logout</button>
              </>
            ) : (
              <Link to="/login">Login</Link>
            )}
          </nav>
        </div>
      </header>

      <main className="container">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          } />
          <Route path="/create-order" element={
            <ProtectedRoute allowRoles={["operator","admin"]}>
              <CreateOrder />
            </ProtectedRoute>
          } />
          <Route path="*" element={<Navigate to={user ? "/" : "/login"} />} />
        </Routes>
      </main>
    </div>
  );
}
