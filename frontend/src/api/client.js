const BASE = process.env.REACT_APP_API_URL || "";

function getToken() {
  return localStorage.getItem("pg_token");
}

async function request(path, options = {}) {
  const token = getToken();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(err.detail || "Request failed");
  }
  return res.json();
}

export const api = {
  register: (email, password) =>
    request("/auth/register", { method: "POST", body: JSON.stringify({ email, password }) }),

  login: (email, password) =>
    request("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),

  analyze: (message) =>
    request("/analyze", { method: "POST", body: JSON.stringify({ message }) }),

  history: (limit = 20, offset = 0) =>
    request(`/history?limit=${limit}&offset=${offset}`),

  deleteMessage: (id) =>
    request(`/history/${id}`, { method: "DELETE" }),

  stats: () => request("/stats"),
};
