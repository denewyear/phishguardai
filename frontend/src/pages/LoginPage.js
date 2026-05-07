import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../App";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const s = {
    page: { minHeight: "calc(100vh - 48px)", display: "flex", alignItems: "center", justifyContent: "center", background: "#f8f9fa" },
    card: { background: "white", border: "1px solid #e0e0e0", borderRadius: 12, padding: "40px 36px", width: 380 },
    title: { fontSize: 22, fontWeight: 700, color: "#0F6E56", marginBottom: 6 },
    sub: { fontSize: 13, color: "#888", marginBottom: 24 },
    label: { display: "block", fontSize: 12, fontWeight: 600, color: "#444", marginBottom: 5 },
    input: { width: "100%", padding: "10px 12px", border: "1px solid #ddd", borderRadius: 7, fontSize: 14, marginBottom: 14, outline: "none" },
    btn: { width: "100%", padding: 11, background: "#0F6E56", color: "white", border: "none", borderRadius: 7, fontSize: 14, fontWeight: 600, cursor: "pointer", marginTop: 4 },
    err: { background: "#FCEBEB", color: "#791F1F", padding: "9px 12px", borderRadius: 7, fontSize: 12, marginBottom: 14 },
    link: { fontSize: 12, color: "#0F6E56", textAlign: "center", marginTop: 16 },
  };

  async function handleSubmit(e) {
    e.preventDefault();
    setError(""); setLoading(true);
    try {
      const data = await api.login(email, password);
      login(data.token, data.email);
      navigate("/");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={s.page}>
      <div style={s.card}>
        <div style={s.title}>Welcome back</div>
        <div style={s.sub}>Log in to your PhishGuard account</div>
        {error && <div style={s.err}>{error}</div>}
        <form onSubmit={handleSubmit}>
          <label style={s.label}>Email</label>
          <input style={s.input} type="email" value={email} onChange={e => setEmail(e.target.value)} required placeholder="you@example.com" />
          <label style={s.label}>Password</label>
          <input style={s.input} type="password" value={password} onChange={e => setPassword(e.target.value)} required placeholder="••••••••" />
          <button style={s.btn} type="submit" disabled={loading}>{loading ? "Logging in…" : "Log in"}</button>
        </form>
        <div style={s.link}>Don't have an account? <Link to="/register" style={{ color: "#0F6E56", fontWeight: 600 }}>Sign up</Link></div>
      </div>
    </div>
  );
}
