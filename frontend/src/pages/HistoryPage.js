import React, { useState, useEffect } from "react";
import { api, getWarningImage } from "../api/mockApi";
import { T, RISK } from "../styles";
import RiskBadge from "../components/RiskBadge";
import ShareModal from "../components/ShareModal";

// ── Detail drawer (click row to expand) ──────────────────────────
function DetailDrawer({ item, onClose, onShare }) {
  const r      = RISK[item.classification] || RISK["LOW RISK"];
  const imgUrl = getWarningImage(item.classification);
  const [shared, setShared] = useState(false);

  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "#000000bb", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 200 }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{ background: T.panel, border: `1px solid ${r.color}`, borderRadius: 16, width: 520, maxHeight: "85vh", overflowY: "auto", boxShadow: "0 24px 48px #00000066" }}
      >
        {/* S3 warning image */}
        <img src={imgUrl} alt="Risk level" style={{ width: "100%", maxHeight: 100, objectFit: "cover", borderRadius: "16px 16px 0 0" }} />

        <div style={{ padding: 24 }}>
          {/* Header */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
            <div>
              <div style={{ fontSize: 18, fontWeight: 800, color: r.color, marginBottom: 8 }}>{r.icon} {item.classification}</div>
              <RiskBadge classification={item.classification} score={item.risk_score} size="lg" />
            </div>
            <button onClick={onClose} style={{ background: "transparent", border: "none", color: T.slate, fontSize: 22, cursor: "pointer" }}>×</button>
          </div>

          {/* Full message */}
          <div style={{ fontSize: 11, fontWeight: 700, color: T.slate, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>Full message</div>
          <div style={{ background: T.bg, padding: "12px 15px", borderRadius: 9, fontSize: 13, color: T.silver, lineHeight: 1.7, marginBottom: 16, wordBreak: "break-word", borderLeft: `3px solid ${r.color}` }}>
            {item.message_text}
          </div>

          {/* Patterns */}
          {item.patterns?.length > 0 && (
            <>
              <div style={{ fontSize: 11, fontWeight: 700, color: T.slate, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>Patterns detected</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 7, marginBottom: 16 }}>
                {item.patterns.map((p, i) => (
                  <span key={i} style={{ background: r.color + "18", color: r.color, border: `1px solid ${r.color}44`, borderRadius: 6, padding: "4px 10px", fontSize: 12 }}>{p}</span>
                ))}
              </div>
            </>
          )}

          {/* Recommendation */}
          <div style={{ padding: "11px 15px", background: T.bg, borderRadius: 9, fontSize: 13, color: T.silver, lineHeight: 1.7, borderLeft: `3px solid ${r.color}`, marginBottom: 16 }}>
            {item.recommendation}
          </div>

          {/* Date */}
          <div style={{ fontSize: 11, color: T.slate, marginBottom: 20 }}>
            Analyzed: {new Date(item.analyzed_at).toLocaleString()}
          </div>

          {/* Share */}
          {shared ? (
            <div style={{ fontSize: 13, color: T.lime, fontWeight: 600 }}>✓ Shared to community feed!</div>
          ) : (
            <button
              onClick={() => onShare(item.id)}
              style={{ background: T.teal, color: T.bg, border: "none", borderRadius: 9, padding: "10px 22px", fontSize: 13, fontWeight: 800, cursor: "pointer" }}
            >
              🔗 Share this phish →
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────
export default function HistoryPage() {
  const [items,       setItems]    = useState([]);
  const [loading,     setLoading]  = useState(true);
  const [offset,      setOffset]   = useState(0);
  const [selected,    setSelected] = useState(null);   // item to show in drawer
  const [shareTarget, setShareTarget] = useState(null); // message id for share modal
  const [sharedIds,   setSharedIds]   = useState(new Set());
  const LIMIT = 10;

  async function load(off = 0) {
    setLoading(true);
    try { setItems(await api.getHistory(LIMIT, off)); setOffset(off); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(0); }, []);

  function openShare(id) {
    setSelected(null);       // close detail drawer first
    setShareTarget(id);
  }

  function onShared(id) {
    setSharedIds(prev => new Set([...prev, id]));
  }

  const bc = { "HIGH RISK": T.red, "MEDIUM RISK": T.amber, "LOW RISK": T.lime };

  return (
    <div style={{ background: T.bg, minHeight: "calc(100vh - 54px)" }}>
      <div style={{ maxWidth: 960, margin: "0 auto", padding: "28px 20px" }}>

        {/* Page header */}
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 22, fontWeight: 800, color: T.white, marginBottom: 5 }}>Analysis History</div>
          <div style={{ fontSize: 13, color: T.slate }}>
            All messages you've analyzed. Click any row to view full details and share to the community.
          </div>
        </div>

        {loading ? (
          <div style={{ color: T.slate, textAlign: "center", padding: 40 }}>Loading…</div>
        ) : items.length === 0 ? (
          <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 14, padding: 48, textAlign: "center" }}>
            <div style={{ fontSize: 32, marginBottom: 12 }}>📭</div>
            <div style={{ fontSize: 16, fontWeight: 700, color: T.white, marginBottom: 6 }}>No analyses yet</div>
            <div style={{ fontSize: 13, color: T.slate }}>Go analyze a message first!</div>
          </div>
        ) : (
          <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 14, overflow: "hidden" }}>
            {/* Column headers */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 100px 160px 150px 100px", padding: "11px 18px", background: T.bg, borderBottom: `1px solid ${T.border}` }}>
              {["Message", "Score", "Risk Level", "Analyzed At", ""].map(h => (
                <div key={h} style={{ fontSize: 10, fontWeight: 700, color: T.slate, textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</div>
              ))}
            </div>

            {items.map((r, idx) => {
              const col      = bc[r.classification] || "#888";
              const isShared = sharedIds.has(r.id);
              return (
                <div
                  key={r.id}
                  onClick={() => setSelected(r)}
                  style={{
                    display: "grid", gridTemplateColumns: "1fr 100px 160px 150px 100px",
                    padding: "13px 18px", alignItems: "center",
                    borderBottom: idx < items.length - 1 ? `1px solid ${T.border}` : "none",
                    cursor: "pointer", transition: "background .12s",
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = T.border + "55"}
                  onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                >
                  {/* Message preview */}
                  <div style={{ fontSize: 13, color: T.silver, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", paddingRight: 14 }}>
                    {r.message_text}
                  </div>

                  {/* Score */}
                  <div style={{ fontSize: 15, fontWeight: 800, color: col }}>{r.risk_score}</div>

                  {/* Badge */}
                  <div><RiskBadge classification={r.classification} /></div>

                  {/* Date */}
                  <div style={{ fontSize: 11, color: T.slate }}>{new Date(r.analyzed_at).toLocaleString()}</div>

                  {/* Share button */}
                  <div onClick={e => { e.stopPropagation(); openShare(r.id); }}>
                    {isShared ? (
                      <span style={{ fontSize: 11, color: T.lime }}>✓ Shared</span>
                    ) : (
                      <button style={{ background: "transparent", border: `1px solid ${T.teal}44`, color: T.teal, borderRadius: 6, padding: "4px 10px", fontSize: 11, cursor: "pointer" }}>
                        Share
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Pagination */}
        <div style={{ display: "flex", gap: 10, marginTop: 18, justifyContent: "flex-end" }}>
          {offset > 0 && (
            <button onClick={() => load(offset - LIMIT)} style={{ padding: "8px 18px", border: `1px solid ${T.border}`, borderRadius: 8, background: T.panel, color: T.slate, cursor: "pointer" }}>
              ← Previous
            </button>
          )}
          {items.length === LIMIT && (
            <button onClick={() => load(offset + LIMIT)} style={{ padding: "8px 18px", border: `1px solid ${T.border}`, borderRadius: 8, background: T.panel, color: T.slate, cursor: "pointer" }}>
              Next →
            </button>
          )}
        </div>
      </div>

      {/* Detail drawer */}
      {selected && (
        <DetailDrawer
          item={selected}
          onClose={() => setSelected(null)}
          onShare={(id) => { setSelected(null); setShareTarget(id); }}
        />
      )}

      {/* Share modal */}
      {shareTarget && (
        <ShareModal
          messageId={shareTarget}
          onClose={() => setShareTarget(null)}
          onSuccess={() => { onShared(shareTarget); setShareTarget(null); }}
        />
      )}
    </div>
  );
}
