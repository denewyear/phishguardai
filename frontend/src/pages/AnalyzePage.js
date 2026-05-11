import React, { useState, useEffect } from "react";
import { api, getWarningImage } from "../api/mockApi";
import { T, RISK } from "../styles";
import RiskBadge from "../components/RiskBadge";
import ShareModal from "../components/ShareModal";

// ── Score dial ────────────────────────────────────────────────────
function ScoreDial({ score, color }) {
  return (
    <div style={{
      width: 72, height: 72, borderRadius: "50%",
      border: `4px solid ${color}`,
      display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      background: T.bg, flexShrink: 0,
    }}>
      <div style={{ fontSize: 22, fontWeight: 900, color, lineHeight: 1 }}>{score}</div>
      <div style={{ fontSize: 9, color: T.slate }}>/ 100</div>
    </div>
  );
}

// ── Analysis result card ──────────────────────────────────────────
function ResultCard({ result, lastId, onShareSuccess }) {
  const r = RISK[result.classification] || RISK["LOW RISK"];
  const [showShare, setShowShare] = useState(false);
  const [shared,    setShared]    = useState(false);

  // S3 warning image — use result.warning_image_url (from backend) or fallback
  const imgUrl = result.warning_image_url || getWarningImage(result.classification);

  function handleShareSuccess(shareResult) {
    setShared(true);
    onShareSuccess?.(shareResult);
  }

  return (
    <div style={{ border: `1.5px solid ${r.color}`, borderRadius: 14, overflow: "hidden", marginTop: 20, background: r.dim }}>

      {/* ── S3 Warning image ── */}
      <img
        src={imgUrl}
        alt={`${result.classification} warning`}
        style={{ width: "100%", maxHeight: 100, objectFit: "cover", display: "block" }}
      />

      {/* ── Score + classification ── */}
      <div style={{ padding: "16px 20px", display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: `1px solid ${r.color}22` }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 900, color: r.color, marginBottom: 8 }}>
            {r.icon} {result.classification}
          </div>
          <RiskBadge classification={result.classification} score={result.risk_score} size="lg" />
        </div>
        <ScoreDial score={result.risk_score} color={r.color} />
      </div>

      {/* ── Patterns ── */}
      <div style={{ padding: "16px 20px" }}>
        {result.patterns_detected?.length > 0 ? (
          <>
            <div style={{ fontSize: 10, fontWeight: 700, color: T.slate, textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 10 }}>
              Patterns detected ({result.patterns_detected.length})
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 7, marginBottom: 14 }}>
              {result.patterns_detected.map((p, i) => (
                <span key={i} style={{ background: r.color + "18", color: r.color, border: `1px solid ${r.color}44`, borderRadius: 6, padding: "4px 10px", fontSize: 12, fontWeight: 600 }}>
                  {p}
                </span>
              ))}
            </div>
          </>
        ) : (
          <div style={{ fontSize: 13, color: T.slate, marginBottom: 14 }}>No suspicious patterns detected.</div>
        )}

        {/* Recommendation */}
        <div style={{ padding: "11px 15px", background: T.bg, borderRadius: 9, fontSize: 13, color: T.silver, lineHeight: 1.7, borderLeft: `3px solid ${r.color}`, marginBottom: 16 }}>
          {result.recommendation}
        </div>

        {/* Share button */}
        {shared ? (
          <div style={{ fontSize: 13, color: T.lime, fontWeight: 600 }}>
            ✓ Shared to community feed!
          </div>
        ) : (
          <button
            onClick={() => setShowShare(true)}
            style={{ background: "transparent", border: `1px solid ${T.teal}`, color: T.teal, borderRadius: 9, padding: "9px 20px", fontSize: 13, fontWeight: 700, cursor: "pointer" }}
          >
            🔗 Share this phish →
          </button>
        )}
      </div>

      {showShare && (
        <ShareModal
          messageId={lastId}
          onClose={() => setShowShare(false)}
          onSuccess={handleShareSuccess}
        />
      )}
    </div>
  );
}

// ── Stat sidebar card ─────────────────────────────────────────────
function StatPill({ label, value, color }) {
  return (
    <div style={{ background: T.border, borderRadius: 10, padding: "12px 14px", flex: 1 }}>
      <div style={{ fontSize: 10, color: T.slate, marginBottom: 3, textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 800, color: color || T.white }}>{value}</div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────
export default function AnalyzePage() {
  const [message, setMessage]   = useState("");
  const [result,  setResult]    = useState(null);
  const [lastId,  setLastId]    = useState(null);
  const [error,   setError]     = useState("");
  const [loading, setLoading]   = useState(false);
  const [recent,  setRecent]    = useState([]);

  // Load recent history for sidebar on mount
  useEffect(() => {
    api.getHistory(5, 0).then(setRecent).catch(() => {});
  }, [result]);

  async function handleAnalyze(e) {
    e.preventDefault();
    if (!message.trim()) return;
    setError(""); setLoading(true); setResult(null);
    try {
      const data = await api.analyze(message.trim());
      setResult(data);
      setLastId(Date.now()); // mock id — real backend returns actual DB id
    } catch (err) {
      setError(err.message || "Analysis failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ background: T.bg, minHeight: "calc(100vh - 54px)" }}>
      <div style={{ maxWidth: 1120, margin: "0 auto", padding: "28px 20px", display: "grid", gridTemplateColumns: "1fr 290px", gap: 24 }}>

        {/* ── Left: Analyzer ── */}
        <div>
          <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 14, padding: 26 }}>
            {/* Header */}
            <div style={{ marginBottom: 18 }}>
              <div style={{ fontSize: 20, fontWeight: 800, color: T.white, marginBottom: 5 }}>
                Analyze a suspicious message
              </div>
              <div style={{ fontSize: 13, color: T.slate, lineHeight: 1.7 }}>
                Paste any suspicious SMS, email, or message. We'll score it 0–100 across 8 phishing pattern categories and display a warning image based on the risk level.
              </div>
            </div>

            {/* Input */}
            <form onSubmit={handleAnalyze}>
              <textarea
                value={message}
                onChange={e => setMessage(e.target.value)}
                placeholder="Paste suspicious message here…&#10;&#10;e.g. URGENT: Your Amazon account has been SUSPENDED. Verify your SSN: https://bit.ly/verify123"
                style={{
                  width: "100%", height: 130, resize: "vertical",
                  background: T.bg, border: `1px solid ${T.border}`,
                  borderRadius: 10, padding: "12px 15px", fontSize: 13,
                  color: T.silver, fontFamily: "inherit", lineHeight: 1.6,
                  outline: "none", boxSizing: "border-box",
                  transition: "border-color .15s",
                }}
                onFocus={e => e.target.style.borderColor = T.teal}
                onBlur={e  => e.target.style.borderColor = T.border}
              />

              <button
                type="submit"
                disabled={loading || !message.trim()}
                style={{
                  marginTop: 12, width: "100%", padding: "13px 0",
                  background: loading || !message.trim() ? T.border : T.teal,
                  color: loading || !message.trim() ? T.slate : T.bg,
                  border: "none", borderRadius: 10, fontSize: 15,
                  fontWeight: 800, cursor: loading ? "default" : "pointer",
                  transition: "background .15s",
                }}
              >
                {loading ? "🔍 Analyzing…" : "Analyze message →"}
              </button>
            </form>

            {/* Error */}
            {error && (
              <div style={{ background: "#1a0505", color: T.red, padding: "11px 15px", borderRadius: 9, fontSize: 12, marginTop: 14, border: `1px solid ${T.red}33` }}>
                {error}
              </div>
            )}

            {/* Result */}
            {result && (
              <ResultCard
                result={result}
                lastId={lastId}
                onShareSuccess={() => {}}
              />
            )}
          </div>
        </div>

        {/* ── Right: Sidebar ── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

          {/* Quick stats */}
          <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 14, padding: 18 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: T.white, marginBottom: 12 }}>Your stats</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              <StatPill label="Analyzed" value={Array.isArray(recent) ? recent.length : 0} />
              <StatPill label="High risk" value={Array.isArray(recent) ? recent.filter(r => r.classification === "HIGH RISK").length : 0} color={T.red} />
            </div>
          </div>

          {/* Recent analyses */}
          <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 14, padding: 18 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: T.white, marginBottom: 12 }}>Recent analyses</div>
            {(!recent || recent.length === 0) ? (
  		<div style={{ fontSize: 12, color: T.slate }}>No analyses yet.</div>
) : Array.isArray(recent) && recent.map(r => {
              const rc = { "HIGH RISK": T.red, "MEDIUM RISK": T.amber, "LOW RISK": T.lime }[r.classification] || "#888";
              return (
                <div key={r.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: `1px solid ${T.border}` }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 11, color: T.silver, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 165 }}>{r.message_text}</div>
                    <div style={{ fontSize: 10, color: T.slate, marginTop: 2 }}>{new Date(r.analyzed_at).toLocaleString()}</div>
                  </div>
                  <span style={{ fontSize: 11, fontWeight: 700, background: rc + "22", color: rc, padding: "2px 7px", borderRadius: 99, flexShrink: 0, marginLeft: 8, border: `1px solid ${rc}44` }}>
                    {r.risk_score}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Mock badge */}
          <div style={{ background: T.teal + "11", border: `1px solid ${T.teal}33`, borderRadius: 11, padding: "12px 14px", fontSize: 11, color: T.slate, lineHeight: 1.7 }}>
            <strong style={{ color: T.teal }}>🔧 Mock mode ON</strong><br />
            Using mock data. Set <code style={{ color: T.teal }}>USE_MOCK = false</code> in <code>mockApi.js</code> to connect to the real backend on Sunday.
          </div>
        </div>
      </div>
    </div>
  );
}
