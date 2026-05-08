import React, { useState, useEffect } from "react";
import { api, getWarningImage } from "../api/mockApi";
import { T, RISK } from "../styles";
import RiskBadge from "../components/RiskBadge";

// ── Full message modal ────────────────────────────────────────────
function MessageModal({ item, onClose }) {
  const r      = RISK[item.classification] || RISK["LOW RISK"];
  const imgUrl = getWarningImage(item.classification);

  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "#000000cc", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 300 }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{ background: T.panel, border: `1px solid ${r.color}`, borderRadius: 16, width: 540, maxHeight: "85vh", overflowY: "auto", boxShadow: "0 24px 48px #00000066" }}
      >
        {/* S3 Warning image */}
        <img src={imgUrl} alt="Risk level" style={{ width: "100%", maxHeight: 100, objectFit: "cover", borderRadius: "16px 16px 0 0", display: "block" }} />

        <div style={{ padding: 26 }}>
          {/* Header */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
            <div>
              {item.title && <div style={{ fontSize: 18, fontWeight: 800, color: T.white, marginBottom: 6 }}>{item.title}</div>}
              <RiskBadge classification={item.classification} score={item.risk_score} size="lg" />
            </div>
            <button onClick={onClose} style={{ background: "transparent", border: "none", color: T.slate, fontSize: 22, cursor: "pointer", lineHeight: 1 }}>×</button>
          </div>

          {/* Description */}
          {item.description && (
            <div style={{ fontSize: 13, color: T.slate, fontStyle: "italic", marginBottom: 16, lineHeight: 1.6 }}>{item.description}</div>
          )}

          {/* Full message */}
          <div style={{ fontSize: 11, fontWeight: 700, color: T.slate, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>Full message</div>
          <div style={{ background: T.bg, padding: "13px 16px", borderRadius: 9, fontSize: 13, color: T.silver, lineHeight: 1.7, marginBottom: 16, wordBreak: "break-word", borderLeft: `3px solid ${r.color}` }}>
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

          {/* Meta */}
          <div style={{ fontSize: 11, color: T.slate, display: "flex", gap: 16 }}>
            <span>Shared by <strong style={{ color: T.silver }}>{item.shared_by}</strong></span>
            <span>{new Date(item.shared_at).toLocaleString()}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Gallery card ──────────────────────────────────────────────────
function GalleryCard({ item, onClick }) {
  const r      = RISK[item.classification] || RISK["LOW RISK"];
  const imgUrl = getWarningImage(item.classification);

  return (
    <div
      onClick={onClick}
      style={{
        background: T.panel, border: `1px solid ${r.color}33`,
        borderRadius: 13, overflow: "hidden",
        cursor: "pointer", transition: "transform .12s, border-color .12s",
        borderLeft: `3px solid ${r.color}`,
      }}
      onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.borderColor = r.color; }}
      onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.borderColor = r.color + "33"; }}
    >
      {/* S3 Warning image integrated into card */}
      <img src={imgUrl} alt="Risk level" style={{ width: "100%", height: 60, objectFit: "cover", display: "block" }} />

      <div style={{ padding: "14px 16px" }}>
        {/* Title + badge row */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8, gap: 8 }}>
          <div style={{ fontWeight: 700, fontSize: 14, color: T.white, flex: 1 }}>
            {item.title || "Untitled"}
          </div>
          <RiskBadge classification={item.classification} score={item.risk_score} />
        </div>

        {/* Description */}
        {item.description && (
          <div style={{ fontSize: 12, color: T.slate, fontStyle: "italic", marginBottom: 10, lineHeight: 1.5 }}>
            {item.description}
          </div>
        )}

        {/* Message preview */}
        <div style={{ fontSize: 12, color: T.silver, background: T.bg, padding: "8px 11px", borderRadius: 7, lineHeight: 1.6, marginBottom: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {item.message_text}
        </div>

        {/* Pattern tags */}
        {item.patterns?.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 10 }}>
            {item.patterns.slice(0, 3).map((p, i) => (
              <span key={i} style={{ background: T.border, color: T.slate, fontSize: 10, padding: "2px 7px", borderRadius: 4 }}>{p}</span>
            ))}
            {item.patterns.length > 3 && (
              <span style={{ background: T.border, color: T.slate, fontSize: 10, padding: "2px 7px", borderRadius: 4 }}>+{item.patterns.length - 3}</span>
            )}
          </div>
        )}

        {/* Footer */}
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: T.slate }}>
          <span>{item.shared_by?.split("@")[0]}</span>
          <span>{new Date(item.shared_at).toLocaleDateString()}</span>
        </div>

        {/* Click hint */}
        <div style={{ marginTop: 10, fontSize: 11, color: T.teal, fontWeight: 600 }}>Click to view full message →</div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────
export default function SharedGalleryPage() {
  const [items,    setItems]   = useState([]);
  const [loading,  setLoading] = useState(true);
  const [offset,   setOffset]  = useState(0);
  const [selected, setSelected] = useState(null);
  const LIMIT = 12;

  async function load(off = 0) {
    setLoading(true);
    try { setItems(await api.getShared(LIMIT, off)); setOffset(off); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(0); }, []);

  // Filter state
  const [filter, setFilter] = useState("ALL");
  const filters = ["ALL", "HIGH RISK", "MEDIUM RISK", "LOW RISK"];
  const filtered = filter === "ALL" ? items : items.filter(i => i.classification === filter);

  return (
    <div style={{ background: T.bg, minHeight: "calc(100vh - 54px)" }}>
      <div style={{ maxWidth: 1060, margin: "0 auto", padding: "28px 20px" }}>

        {/* Page header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 }}>
          <div>
            <div style={{ fontSize: 22, fontWeight: 800, color: T.white, marginBottom: 5 }}>🔗 Shared Gallery</div>
            <div style={{ fontSize: 13, color: T.slate, lineHeight: 1.7 }}>
              Phishing examples shared by users. Click any card to see the full message and patterns.
              Analyze a message and click <strong style={{ color: T.teal }}>Share</strong> to contribute.
            </div>
          </div>
          {/* Risk filter */}
          <div style={{ display: "flex", gap: 5, flexShrink: 0, flexWrap: "wrap", justifyContent: "flex-end" }}>
            {filters.map(f => {
              const active = filter === f;
              const col    = f === "HIGH RISK" ? T.red : f === "MEDIUM RISK" ? T.amber : f === "LOW RISK" ? T.lime : T.teal;
              return (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  style={{ padding: "6px 13px", borderRadius: 7, border: `1px solid ${active ? col : T.border}`, background: active ? col + "22" : "transparent", color: active ? col : T.slate, fontSize: 11, fontWeight: 700, cursor: "pointer" }}
                >
                  {f === "ALL" ? "All" : f.split(" ")[0]}
                </button>
              );
            })}
          </div>
        </div>

        {loading ? (
          <div style={{ color: T.slate, textAlign: "center", padding: 48 }}>Loading…</div>
        ) : filtered.length === 0 ? (
          <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 14, padding: 48, textAlign: "center" }}>
            <div style={{ fontSize: 36, marginBottom: 12 }}>🛡️</div>
            <div style={{ fontSize: 16, fontWeight: 700, color: T.white, marginBottom: 8 }}>Nothing here yet</div>
            <div style={{ fontSize: 13, color: T.slate }}>Be the first — analyze a message and share it!</div>
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 16 }}>
            {filtered.map(item => (
              <GalleryCard key={item.id} item={item} onClick={() => setSelected(item)} />
            ))}
          </div>
        )}

        {/* Pagination */}
        <div style={{ display: "flex", gap: 10, marginTop: 24, justifyContent: "flex-end" }}>
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

      {/* Detail modal */}
      {selected && <MessageModal item={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
