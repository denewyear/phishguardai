import React, { useState } from "react";
import { T } from "../styles";
import { api } from "../api/mockApi";

export default function ShareModal({ messageId, onClose, onSuccess }) {
  const [title, setTitle]       = useState("");
  const [description, setDesc]  = useState("");
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState("");

  async function handleShare() {
    if (!title.trim() && !description.trim()) {
      // allow sharing without title/description — both are optional per contract
    }
    setLoading(true); setError("");
    try {
      const result = await api.sharePhish(messageId, title || null, description || null);
      onSuccess(result);
      onClose();
    } catch (e) {
      setError(e.message || "Share failed");
    } finally {
      setLoading(false);
    }
  }

  const inputStyle = {
    width: "100%", padding: "10px 13px",
    background: T.bg, border: `1px solid ${T.border}`,
    borderRadius: 9, color: T.white, fontSize: 13,
    outline: "none", boxSizing: "border-box",
  };

  return (
    // Backdrop
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "#000000cc", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 300 }}
    >
      {/* Card — stop click propagation so clicking inside doesn't close */}
      <div
        onClick={e => e.stopPropagation()}
        style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 16, padding: 28, width: 440, boxShadow: "0 24px 48px #00000066" }}
      >
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <div style={{ fontSize: 17, fontWeight: 800, color: T.white }}>Share to Community</div>
          <button onClick={onClose} style={{ background: "transparent", border: "none", color: T.slate, fontSize: 18, cursor: "pointer", lineHeight: 1 }}>×</button>
        </div>
        <div style={{ fontSize: 12, color: T.slate, marginBottom: 22, lineHeight: 1.6 }}>
          Help protect others by sharing this phishing example to the public gallery. Both fields are optional.
        </div>

        {error && (
          <div style={{ background: "#1a0505", color: T.red, padding: "9px 13px", borderRadius: 8, fontSize: 12, marginBottom: 16, border: `1px solid ${T.red}33` }}>
            {error}
          </div>
        )}

        <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: T.slate, marginBottom: 6 }}>
          Title <span style={{ color: T.border }}>optional</span>
        </label>
        <input
          value={title}
          onChange={e => setTitle(e.target.value)}
          placeholder="e.g. Fake Amazon security alert"
          maxLength={200}
          style={{ ...inputStyle, marginBottom: 16 }}
        />

        <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: T.slate, marginBottom: 6 }}>
          Description <span style={{ color: T.border }}>optional</span>
        </label>
        <textarea
          value={description}
          onChange={e => setDesc(e.target.value)}
          placeholder="What makes this phishing? What should people watch out for?"
          rows={3}
          style={{ ...inputStyle, resize: "vertical", fontFamily: "inherit", lineHeight: 1.6, marginBottom: 22 }}
        />

        <div style={{ display: "flex", gap: 10 }}>
          <button
            onClick={onClose}
            style={{ flex: 1, padding: "11px 0", background: "transparent", border: `1px solid ${T.border}`, color: T.slate, borderRadius: 9, cursor: "pointer", fontSize: 13 }}
          >
            Cancel
          </button>
          <button
            onClick={handleShare}
            disabled={loading}
            style={{ flex: 2, padding: "11px 0", background: loading ? T.border : T.teal, color: T.bg, border: "none", borderRadius: 9, fontWeight: 800, cursor: loading ? "default" : "pointer", fontSize: 13 }}
          >
            {loading ? "Sharing…" : "Share this phish →"}
          </button>
        </div>
      </div>
    </div>
  );
}
