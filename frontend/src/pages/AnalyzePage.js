import React, { useState, useEffect } from "react";
import { api } from "../api/client";

const RISK_COLORS = {
  "HIGH RISK":   { bg: "#FCEBEB", border: "#F09595", text: "#791F1F", badge: "#E24B4A", dot: "#E24B4A" },
  "MEDIUM RISK": { bg: "#FAEEDA", border: "#FAC775", text: "#633806", badge: "#EF9F27", dot: "#EF9F27" },
  "LOW RISK":    { bg: "#EAF3DE", border: "#C0DD97", text: "#27500A", badge: "#639922", dot: "#639922" },
};

function StatCard({ label, value, color }) {
  return (
    <div style={{ background: "#f3f4f6", borderRadius: 8, padding: "12px 14px", flex: 1 }}>
      <div style={{ fontSize: 11, color: "#888", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, color: color || "#1a1a1a" }}>{value}</div>
    </div>
  );
}

function ResultCard({ result }) {
  const c = RISK_COLORS[result.classification] || RISK_COLORS["LOW RISK"];
  return (
    <div style={{ border: `1.5px solid ${c.border}`, borderRadius: 12, overflow: "hidden", marginTop: 16 }}>
      <div style={{ background: c.bg, padding: "14px 16px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: c.text, marginBottom: 6 }}>{result.classification}</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ background: c.badge, color: "white", borderRadius: 99, padding: "2px 10px", fontSize: 11, fontWeight: 700 }}>
              {result.risk_score}/100
            </span>
          </div>
        </div>
        <div style={{ width: 58, height: 58, borderRadius: "50%", border: `3px solid ${c.badge}`, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: c.text, lineHeight: 1 }}>{result.risk_score}</div>
          <div style={{ fontSize: 9, color: c.text }}>/ 100</div>
        </div>
      </div>
      <div style={{ padding: "14px 16px" }}>
        {result.patterns_detected.length > 0 && (
          <>
            <div style={{ fontSize: 10, fontWeight: 700, color: "#888", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8 }}>Patterns detected</div>
            {result.patterns_detected.map((p, i) => (
              <div key={i} style={{ display: "flex", gap: 8, marginBottom: 5, alignItems: "flex-start" }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: c.dot, flexShrink: 0, marginTop: 5 }} />
                <span style={{ fontSize: 12, color: "#333" }}>{p}</span>
              </div>
            ))}
          </>
        )}
        <div style={{ marginTop: 12, padding: "9px 12px", background: c.bg, borderRadius: 7, fontSize: 12, color: c.text, lineHeight: 1.5 }}>
          {result.recommendation}
        </div>
      </div>
    </div>
  );
}

export default function AnalyzePage() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);

  useEffect(() => {
    api.stats().then(setStats).catch(() => {});
    api.history(5, 0).then(d => setRecent(d.items || [])).catch(() => {});
  }, [result]);

  async function handleAnalyze(e) {
    e.preventDefault();
    if (!message.trim()) return;
    setError(""); setLoading(true); setResult(null);
    try {
      const data = await api.analyze(message.trim());
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const s = {
    page: { maxWidth: 1100, margin: "0 auto", padding: "28px 20px", display: "grid", gridTemplateColumns: "1fr 300px", gap: 24 },
    card: { background: "white", border: "1px solid #e5e7eb", borderRadius: 12, padding: "22px 22px" },
    h2: { fontSize: 15, fontWeight: 700, color: "#111", marginBottom: 6 },
    sub: { fontSize: 12, color: "#888", marginBottom: 14, lineHeight: 1.5 },
    textarea: { width: "100%", height: 96, resize: "vertical", border: "1px solid #ddd", borderRadius: 8, padding: "10px 12px", fontSize: 13, fontFamily: "inherit", lineHeight: 1.5, outline: "none" },
    btn: { marginTop: 10, width: "100%", padding: "10px 0", background: "#0F6E56", color: "white", border: "none", borderRadius: 8, fontSize: 14, fontWeight: 600, cursor: "pointer" },
    err: { background: "#FCEBEB", color: "#791F1F", padding: "9px 12px", borderRadius: 7, fontSize: 12, marginTop: 10 },
    stats: { display: "flex", gap: 8, marginBottom: 14 },
    histRow: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: "1px solid #f3f4f6" },
    histText: { fontSize: 12, color: "#333", maxWidth: 170, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
    histMeta: { display: "flex", gap: 6, alignItems: "center" },
    histTime: { fontSize: 11, color: "#999" },
  };

  const badgeColor = { "HIGH RISK": "#E24B4A", "MEDIUM RISK": "#EF9F27", "LOW RISK": "#639922" };

  return (
    <div style={s.page}>
      {/* Left: analyzer */}
      <div>
        <div style={s.card}>
          <div style={s.h2}>Analyze a suspicious message</div>
          <div style={s.sub}>Paste any suspicious SMS, email, or message. We'll score it for phishing patterns instantly. You can also text our Twilio number to get the same analysis via SMS.</div>
          <form onSubmit={handleAnalyze}>
            <textarea
              style={s.textarea}
              value={message}
              onChange={e => setMessage(e.target.value)}
              placeholder="Paste suspicious message here…"
            />
            <button style={s.btn} type="submit" disabled={loading}>
              {loading ? "Analyzing…" : "Analyze message"}
            </button>
          </form>
          {error && <div style={s.err}>{error}</div>}
          {result && <ResultCard result={result} />}
        </div>
      </div>

      {/* Right: stats + history */}
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {/* Stats */}
        <div style={s.card}>
          <div style={{ ...s.h2, marginBottom: 10 }}>Your stats</div>
          {stats ? (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              <StatCard label="Total analyzed" value={stats.total || 0} />
              <StatCard label="High risk" value={stats.high || 0} color="#E24B4A" />
              <StatCard label="Medium risk" value={stats.medium || 0} color="#EF9F27" />
              <StatCard label="Safe" value={stats.low || 0} color="#639922" />
            </div>
          ) : <div style={{ fontSize: 12, color: "#999" }}>Loading stats…</div>}
        </div>

        {/* Recent */}
        <div style={s.card}>
          <div style={{ ...s.h2, marginBottom: 10 }}>Recent analyses</div>
          {recent.length === 0
            ? <div style={{ fontSize: 12, color: "#999" }}>No analyses yet.</div>
            : recent.map(r => (
              <div key={r.id} style={s.histRow}>
                <div>
                  <div style={s.histText}>{r.message_text}</div>
                  <div style={s.histTime}>{new Date(r.analyzed_at).toLocaleString()}</div>
                </div>
                <div style={s.histMeta}>
                  <span style={{ fontSize: 9, background: "#f3f4f6", color: "#666", padding: "2px 5px", borderRadius: 3 }}>{r.channel}</span>
                  <span style={{ fontSize: 10, fontWeight: 700, background: badgeColor[r.classification] + "22", color: badgeColor[r.classification], padding: "2px 7px", borderRadius: 99 }}>
                    {r.classification.split(" ")[0]}
                  </span>
                </div>
              </div>
            ))
          }
        </div>

        {/* Twilio tip */}
        <div style={{ background: "#E6F1FB", border: "1px solid #B5D4F4", borderRadius: 10, padding: "12px 14px", fontSize: 12, color: "#0C447C", lineHeight: 1.6 }}>
          <strong>SMS channel:</strong> Forward suspicious texts to your Twilio number and receive the same analysis via SMS reply — no login required.
        </div>
      </div>
    </div>
  );
}
