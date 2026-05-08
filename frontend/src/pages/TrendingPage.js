import React, { useState, useEffect } from "react";
import { api } from "../api/mockApi";
import { T } from "../styles";

const FILTERS = [
  { label: "24 hours", days: 1  },
  { label: "7 days",   days: 7  },
  { label: "30 days",  days: 30 },
];

const MEDALS = ["🥇", "🥈", "🥉"];

// Colour the bar by how dominant the pattern is
function barColor(percentage) {
  if (percentage >= 25) return T.red;
  if (percentage >= 15) return T.amber;
  return T.teal;
}

function PatternBar({ item, maxCount, rank }) {
  const pct    = maxCount > 0 ? (item.count / maxCount) * 100 : 0;
  const color  = barColor(item.percentage);
  const medal  = MEDALS[rank] || null;

  return (
    <div style={{ padding: "14px 0", borderBottom: `1px solid ${T.border}`, display: "flex", alignItems: "center", gap: 14 }}>
      {/* Rank / medal */}
      <div style={{ width: 34, textAlign: "center", flexShrink: 0 }}>
        {medal
          ? <span style={{ fontSize: 20 }}>{medal}</span>
          : <span style={{ fontSize: 13, fontWeight: 700, color: T.slate }}>{rank + 1}</span>
        }
      </div>

      <div style={{ flex: 1, minWidth: 0 }}>
        {/* Label + numbers */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: T.silver }}>{item.pattern}</span>
          <div style={{ display: "flex", gap: 12, alignItems: "center", flexShrink: 0, marginLeft: 10 }}>
            <span style={{ fontSize: 11, color: T.slate }}>{item.percentage}% of all</span>
            <span style={{ fontSize: 14, fontWeight: 800, color: T.white, minWidth: 28, textAlign: "right" }}>{item.count}</span>
          </div>
        </div>

        {/* Progress bar */}
        <div style={{ height: 9, background: T.border, borderRadius: 99, overflow: "hidden" }}>
          <div style={{
            height: "100%", width: `${pct}%`,
            background: color, borderRadius: 99,
            transition: "width .7s ease",
          }} />
        </div>
      </div>
    </div>
  );
}

export default function TrendingPage() {
  const [items,   setItems]   = useState([]);
  const [days,    setDays]    = useState(7);
  const [loading, setLoading] = useState(true);

  async function load(d) {
    setLoading(true);
    try { setItems(await api.getTrending(d, 10)); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(days); }, [days]);

  const maxCount = items.length > 0 ? items[0].count : 1;
  const total    = items.reduce((s, x) => s + x.count, 0);

  return (
    <div style={{ background: T.bg, minHeight: "calc(100vh - 54px)" }}>
      <div style={{ maxWidth: 780, margin: "0 auto", padding: "28px 20px" }}>

        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24 }}>
          <div>
            <div style={{ fontSize: 22, fontWeight: 800, color: T.white, marginBottom: 5 }}>📊 Trending Patterns</div>
            <div style={{ fontSize: 13, color: T.slate, lineHeight: 1.7 }}>
              The most common phishing techniques detected across all user analyses.
            </div>
          </div>

          {/* Time filter pills */}
          <div style={{ display: "flex", gap: 5, background: T.panel, padding: 5, borderRadius: 10, border: `1px solid ${T.border}`, flexShrink: 0 }}>
            {FILTERS.map(f => (
              <button
                key={f.days}
                onClick={() => setDays(f.days)}
                style={{
                  padding: "6px 15px", borderRadius: 7, border: "none",
                  background: days === f.days ? T.teal : "transparent",
                  color:      days === f.days ? T.bg   : T.slate,
                  fontSize: 12, fontWeight: 700, cursor: "pointer",
                  transition: "background .15s",
                }}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {/* Summary cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 24 }}>
          {[
            { label: "Total occurrences", value: total,        color: T.teal  },
            { label: "Unique patterns",   value: items.length, color: T.silver },
            { label: "Most common",       value: items[0]?.pattern?.split(" ")[0] || "—", color: T.amber },
          ].map(s => (
            <div key={s.label} style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 12, padding: "16px 18px" }}>
              <div style={{ fontSize: 10, color: T.slate, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 5 }}>{s.label}</div>
              <div style={{ fontSize: 22, fontWeight: 800, color: s.color }}>{s.value}</div>
            </div>
          ))}
        </div>

        {/* Bar chart */}
        <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 14, padding: "20px 24px" }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: T.white, marginBottom: 3 }}>
            Pattern frequency — last {FILTERS.find(f => f.days === days)?.label}
          </div>
          <div style={{ fontSize: 11, color: T.slate, marginBottom: 16 }}>
            Bar length = share of total occurrences · Count shown on right
          </div>

          {loading ? (
            <div style={{ color: T.slate, padding: "24px 0", textAlign: "center" }}>Loading…</div>
          ) : items.length === 0 ? (
            <div style={{ color: T.slate, padding: "32px 0", textAlign: "center" }}>
              No pattern data yet — analyze some messages first!
            </div>
          ) : (
            items.map((item, i) => (
              <PatternBar key={item.pattern} item={item} maxCount={maxCount} rank={i} />
            ))
          )}
        </div>

        {/* Legend */}
        <div style={{ marginTop: 14, display: "flex", gap: 20, fontSize: 11, color: T.slate }}>
          {[
            { color: T.red,   label: "≥25% of analyses" },
            { color: T.amber, label: "15–25%" },
            { color: T.teal,  label: "<15%" },
          ].map(l => (
            <div key={l.label} style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <div style={{ width: 12, height: 8, background: l.color, borderRadius: 2 }} />
              <span>{l.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
