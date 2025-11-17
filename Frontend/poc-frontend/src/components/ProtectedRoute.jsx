import React from "react";
import { Navigate } from "react-router-dom";
import { getUser } from "../services/api";

export default function ProtectedRoute({ children, allowRoles = null }) {
  const user = getUser();
  if (!user) return <Navigate to="/login" />;
  if (allowRoles && !allowRoles.includes(user.role)) return <div className="card">You are not authorized to view this page.</div>;
  return children;
}
