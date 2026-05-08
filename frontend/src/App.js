import React, { createContext, useContext, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate, Link, useNavigate, useLocation } from "react-router-dom";
import { T } from "./styles";
import LoginPage          from "./pages/LoginPage";
import RegisterPage       from "./pages/RegisterPage";
import AnalyzePage        from "./pages/AnalyzePage";
import HistoryPage        from "./pages/HistoryPage";
import TrendingPage       from "./pages/TrendingPage";
import SharedGalleryPage  from "./pages/SharedGalleryPage";

// ── Auth context ───────────────────────────────────────────────────
const AuthCtx = createContext(null);
export function useAuth() { return useContext(AuthCtx); }

function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const t = localStorage.getItem("token");
    const e = localStorage.getItem("email");
    return t ? { token: t, email: e } : null;
  });
  const login  = (token, email) => { localStorage.setItem("token", token); localStorage.setItem("email", email); setUser({ token, email }); };
  const logout = ()              => { localStorage.removeItem("token"); localStorage.removeItem("email"); setUser(null); };
  return <AuthCtx.Provider value={{ user, login, logout }}>{children}</AuthCtx.Provider>;
}

// ── Nav link with active underline ─────────────────────────────────
function NL({ to, children }) {
  const active = useLocation().pathname === to;
  return (
    <Link to={to} style={{ color: active ? T.teal : T.slate, textDecoration: "none", fontSize: 13, fontWeight: active ? 700 : 500, borderBottom: `2px solid ${active ? T.teal : "transparent"}`, paddingBottom: 2 }}>
      {children}
    </Link>
  );
}

function Nav() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <nav style={{ background: T.panel, borderBottom: `1px solid ${T.border}`, padding: "0 28px", height: 54, display: "flex", alignItems: "center", justifyContent: "space-between", position: "sticky", top: 0, zIndex: 100 }}>
      {/* Logo */}
      <Link to="/" style={{ textDecoration: "none", display: "flex", alignItems: "center", gap: 9 }}>
        <div style={{ width: 30, height: 30, background: T.teal + "22", border: `2px solid ${T.teal}`, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15 }}>🛡️</div>
        <span style={{ color: T.white, fontWeight: 800, fontSize: 17, letterSpacing: "-0.5px" }}>
          Phish<span style={{ color: T.teal }}>Guard</span>
          <span style={{ fontSize: 10, color: T.slate, fontWeight: 400, marginLeft: 6, background: T.teal + "22", border: `1px solid ${T.teal}44`, borderRadius: 4, padding: "1px 5px" }}>mock</span>
        </span>
      </Link>

      {/* Links */}
      <div style={{ display: "flex", gap: 22, alignItems: "center" }}>
        <NL to="/trending">📊 Trending</NL>
        <NL to="/shared">🔗 Gallery</NL>
        {user && <>
          <NL to="/">Analyze</NL>
          <NL to="/history">My History</NL>
        </>}
      </div>

      {/* Auth */}
      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
        {user ? (
          <>
            <span style={{ fontSize: 12, color: T.teal, background: T.teal + "18", padding: "4px 11px", borderRadius: 99, border: `1px solid ${T.teal}33` }}>
              {user.email.split("@")[0]}
            </span>
            <button onClick={() => { logout(); navigate("/login"); }} style={{ background: "transparent", border: `1px solid ${T.border}`, color: T.slate, borderRadius: 7, padding: "5px 13px", fontSize: 12, cursor: "pointer" }}>
              Log out
            </button>
          </>
        ) : (
          <>
            <Link to="/login"    style={{ color: T.slate, textDecoration: "none", fontSize: 13 }}>Log in</Link>
            <Link to="/register" style={{ background: T.teal, color: T.bg, padding: "6px 16px", borderRadius: 7, fontSize: 13, fontWeight: 700, textDecoration: "none" }}>Sign up</Link>
          </>
        )}
      </div>
    </nav>
  );
}

function Protected({ children }) {
  const { user } = useAuth();
  return user ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Nav />
        <Routes>
          <Route path="/login"    element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/trending" element={<TrendingPage />} />
          <Route path="/shared"   element={<SharedGalleryPage />} />
          <Route path="/"         element={<Protected><AnalyzePage /></Protected>} />
          <Route path="/history"  element={<Protected><HistoryPage /></Protected>} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
