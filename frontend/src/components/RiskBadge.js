import React from "react";
import { RISK } from "../styles";

export default function RiskBadge({ classification, score, size = "md" }) {
  const r   = RISK[classification] || RISK["LOW RISK"];
  const pad = size === "lg" ? "4px 14px" : "2px 10px";
  const fs  = size === "lg" ? 13 : 11;

  return (
    <span style={{
      background:   r.color + "22",
      color:        r.color,
      border:       `1px solid ${r.color}55`,
      borderRadius: 99,
      padding:      pad,
      fontSize:     fs,
      fontWeight:   700,
      display:      "inline-flex",
      alignItems:   "center",
      gap:          5,
      whiteSpace:   "nowrap",
    }}>
      {r.icon} {classification}{score !== undefined ? ` · ${score}/100` : ""}
    </span>
  );
}
