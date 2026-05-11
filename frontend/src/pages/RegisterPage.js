import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { api } from "../api/mockApi";
import { useAuth } from "../App";
import { T } from "../styles";

export default function RegisterPage() {
  const [email, setEmail]       = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm]   = useState("");
  const [error, setError]       = useState("");
  const [loading, setLoading]   = useState(false);
  const { login } = useAuth();
  const navigate  = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();
    if (password !== confirm) { setError("Passwords do not match"); return; }
    setError(""); setLoading(true);
    try {const d = await api.register(email, password); 
	// Register doesn't return token, need to login
	const loginData = await api.login(email, password);
	login(loginData.access_token, email); navigate("/"); }
    catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }

  const inp = { width: "100%", padding: "11px 13px", background: T.bg, border: `1px solid ${T.border}`, borderRadius: 9, color: T.white, fontSize: 14, outline: "none", boxSizing: "border-box", marginBottom: 16 };

  return (
    <div style={{ minHeight: "calc(100vh - 54px)", display: "flex", alignItems: "center", justifyContent: "center", background: T.bg }}>
      <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 16, padding: "42px 40px", width: 400 }}>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ fontSize: 40, marginBottom: 10 }}>🛡️</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: T.white, marginBottom: 5 }}>Create account</div>
          <div style={{ fontSize: 13, color: T.slate }}>Start detecting phishing instantly</div>
        </div>
        {error && <div style={{ background: "#1a0505", color: T.red, padding: "10px 14px", borderRadius: 9, fontSize: 12, marginBottom: 18, border: `1px solid ${T.red}33` }}>{error}</div>}
        <form onSubmit={handleSubmit}>
          <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: T.slate, marginBottom: 6 }}>Email</label>
          <input style={inp} type="email" value={email} onChange={e => setEmail(e.target.value)} required placeholder="you@example.com" />
          <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: T.slate, marginBottom: 6 }}>Password</label>
          <input style={inp} type="password" value={password} onChange={e => setPassword(e.target.value)} required placeholder="At least 6 characters" />
          <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: T.slate, marginBottom: 6 }}>Confirm password</label>
          <input style={{ ...inp, marginBottom: 22 }} type="password" value={confirm} onChange={e => setConfirm(e.target.value)} required placeholder="••••••••" />
          <button type="submit" disabled={loading} style={{ width: "100%", padding: 13, background: loading ? T.border : T.teal, color: T.bg, border: "none", borderRadius: 9, fontSize: 14, fontWeight: 800, cursor: "pointer" }}>
            {loading ? "Creating account…" : "Sign up →"}
          </button>
        </form>
        <div style={{ fontSize: 12, color: T.slate, textAlign: "center", marginTop: 20 }}>
          Already have an account? <Link to="/login" style={{ color: T.teal, fontWeight: 700 }}>Log in</Link>
        </div>
      </div>
    </div>
  );
}
