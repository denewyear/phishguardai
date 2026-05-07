import React, { createContext, useContext, useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate, Link, useNavigate } from "react-router-dom";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import AnalyzePage from "./pages/AnalyzePage";
import HistoryPage from "./pages/HistoryPage";

// ── Auth context ───────────────────────────────────────────────────
const AuthCtx = createContext(null);
export function useAuth() { return useContext(AuthCtx); }

function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const t = localStorage.getItem("pg_token");
    const e = localStorage.getItem("pg_email");
    return t ? { token: t, email: e } : null;
  });

  function login(token, email) {
    localStorage.setItem("pg_token", token);
    localStorage.setItem("pg_email", email);
    setUser({ token, email });
  }
  function logout() {
    localStorage.removeItem("pg_token");
    localStorage.removeItem("pg_email");
    setUser(null);
  }
  return <AuthCtx.Provider value={{ user, login, logout }}>{children}</AuthCtx.Provider>;
}

// ── Nav ───────────────────────────────────────────────────────────
function Nav() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const s = {
    nav: { background: "#0F6E56", padding: "0 20px", height: 48, display: "flex", alignItems: "center", justifyContent: "space-between" },
    logo: { color: "white", fontWeight: 700, fontSize: 17, textDecoration: "none" },
    links: { display: "flex", gap: 20, alignItems: "center" },
    link: { color: "#9FE1CB", textDecoration: "none", fontSize: 13 },
    pill: { background: "#1D9E75", color: "white", borderRadius: 99, padding: "4px 12px", fontSize: 12, fontWeight: 600 },
    btn: { background: "transparent", border: "1px solid #9FE1CB", color: "#9FE1CB", borderRadius: 6, padding: "4px 12px", fontSize: 12, cursor: "pointer" },
  };
  return (
    <nav style={s.nav}>
      <Link to="/" style={s.logo}>Phish<span style={{ color: "#9FE1CB" }}>Guard</span> AI</Link>
      <div style={s.links}>
        {user ? (
          <>
            <Link to="/" style={s.link}>Analyzer</Link>
            <Link to="/history" style={s.link}>My History</Link>
            <span style={s.pill}>{user.email}</span>
            <button style={s.btn} onClick={() => { logout(); navigate("/login"); }}>Log out</button>
          </>
        ) : (
          <>
            <Link to="/login" style={s.link}>Log in</Link>
            <Link to="/register" style={{ ...s.link, background: "#1D9E75", color: "white", padding: "5px 14px", borderRadius: 6 }}>Sign up</Link>
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
          <Route path="/"         element={<Protected><AnalyzePage /></Protected>} />
          <Route path="/history"  element={<Protected><HistoryPage /></Protected>} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
