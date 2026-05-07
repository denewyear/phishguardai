import React, { useState, useEffect } from "react";
import { api } from "../api/client";

const BADGE = { "HIGH RISK": "#E24B4A", "MEDIUM RISK": "#EF9F27", "LOW RISK": "#639922" };

export default function HistoryPage() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [offset, setOffset] = useState(0);
  const LIMIT = 15;

  async function load(off = 0) {
    setLoading(true);
    try {
      const data = await api.history(LIMIT, off);
      setItems(data.items || []);
      setOffset(off);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(0); }, []);

  async function handleDelete(id) {
    if (!window.confirm("Delete this analysis?")) return;
    try {
      await api.deleteMessage(id);
      setItems(prev => prev.filter(i => i.id !== id));
    } catch (e) {
      alert(e.message);
    }
  }

  const s = {
    page: { maxWidth: 860, margin: "0 auto", padding: "28px 20px" },
    h1: { fontSize: 20, fontWeight: 700, color: "#111", marginBottom: 4 },
    sub: { fontSize: 13, color: "#888", marginBottom: 20 },
    table: { width: "100%", borderCollapse: "collapse", background: "white", border: "1px solid #e5e7eb", borderRadius: 12, overflow: "hidden" },
    th: { padding: "12px 14px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#888", textTransform: "uppercase", letterSpacing: "0.05em", background: "#f9fafb", borderBottom: "1px solid #e5e7eb" },
    td: { padding: "11px 14px", fontSize: 13, color: "#333", borderBottom: "1px solid #f3f4f6", verticalAlign: "top" },
    msg: { maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
    del: { background: "transparent", border: "1px solid #ddd", color: "#888", borderRadius: 6, padding: "3px 10px", fontSize: 11, cursor: "pointer" },
    pag: { display: "flex", gap: 10, marginTop: 16, justifyContent: "flex-end" },
    pbtn: { padding: "7px 16px", border: "1px solid #ddd", borderRadius: 7, background: "white", fontSize: 13, cursor: "pointer" },
  };

  return (
    <div style={s.page}>
      <div style={s.h1}>Analysis history</div>
      <div style={s.sub}>All messages you've analyzed. Click delete to remove an entry.</div>

      {loading ? (
        <div style={{ color: "#888", fontSize: 13 }}>Loading…</div>
      ) : items.length === 0 ? (
        <div style={{ color: "#888", fontSize: 13 }}>No analyses found.</div>
      ) : (
        <table style={s.table}>
          <thead>
            <tr>
              <th style={s.th}>Message</th>
              <th style={s.th}>Score</th>
              <th style={s.th}>Classification</th>
              <th style={s.th}>Channel</th>
              <th style={s.th}>Analyzed at</th>
              <th style={s.th}></th>
            </tr>
          </thead>
          <tbody>
            {items.map(r => (
              <tr key={r.id}>
                <td style={{ ...s.td, ...s.msg }}>{r.message_text}</td>
                <td style={s.td}>{r.risk_score}</td>
                <td style={s.td}>
                  <span style={{ background: (BADGE[r.classification] || "#888") + "22", color: BADGE[r.classification] || "#888", padding: "3px 9px", borderRadius: 99, fontSize: 11, fontWeight: 700 }}>
                    {r.classification}
                  </span>
                </td>
                <td style={s.td}>
                  <span style={{ background: "#f3f4f6", color: "#666", padding: "2px 7px", borderRadius: 4, fontSize: 11 }}>{r.channel}</span>
                </td>
                <td style={{ ...s.td, fontSize: 11, color: "#888" }}>{new Date(r.analyzed_at).toLocaleString()}</td>
                <td style={s.td}>
                  <button style={s.del} onClick={() => handleDelete(r.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={s.pag}>
        {offset > 0 && <button style={s.pbtn} onClick={() => load(offset - LIMIT)}>← Previous</button>}
        {items.length === LIMIT && <button style={s.pbtn} onClick={() => load(offset + LIMIT)}>Next →</button>}
      </div>
    </div>
  );
}
