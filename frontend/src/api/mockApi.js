// Toggle between mock and real API
const USE_MOCK = false;  // Set to false when backend is deployed!

const API_BASE = 'http://3.17.25.164:8000'; 

// Mock responses matching API contract
const mockData = {
  analyze: {
    risk_score: 85,
    classification: "HIGH RISK",
    patterns_detected: [
      "Suspicious URL", 
      "Requests sensitive info", 
      "Urgency language"
    ],
    recommendation: "⚠️ DO NOT click links or provide information"
  },
  
  history: [
    {
      id: 1,
      message_text: "URGENT: Verify your account at bit.ly/verify NOW",
      risk_score: 85,
      classification: "HIGH RISK",
      patterns: ["Suspicious URL", "Urgency language"],
      recommendation: "Do not click links",
      analyzed_at: "2026-05-08T10:30:00Z"
    },
    {
      id: 2,
      message_text: "Hey, are we still on for lunch tomorrow?",
      risk_score: 5,
      classification: "LOW RISK",
      patterns: [],
      recommendation: "Looks safe",
      analyzed_at: "2026-05-08T09:15:00Z"
    },
    {
      id: 3,
      message_text: "Your package requires urgent action",
      risk_score: 55,
      classification: "MEDIUM RISK",
      patterns: ["Urgency language"],
      recommendation: "Exercise caution",
      analyzed_at: "2026-05-08T08:45:00Z"
    }
  ],
  
  trending: [
    { pattern: "Suspicious URL", count: 45, percentage: 32.1 },
    { pattern: "Urgency language", count: 38, percentage: 27.1 },
    { pattern: "Requests sensitive info", count: 29, percentage: 20.7 },
    { pattern: "Generic greeting", count: 18, percentage: 12.9 }
  ],
  
  shared: [
    {
      id: 1,
      title: "Classic Bank Scam",
      description: "Account verification phishing attempt",
      message_text: "Your account will be closed! Click here to verify",
      risk_score: 95,
      classification: "HIGH RISK",
      patterns: ["Suspicious URL", "Urgency language", "Financial language"],
      shared_by: "user@example.com",
      shared_at: "2026-05-07T14:20:00Z"
    },
    {
      id: 2,
      title: "Package Delivery Scam",
      description: "Fake delivery notification",
      message_text: "Your package is waiting. Track here: bit.ly/pkg123",
      risk_score: 78,
      classification: "HIGH RISK",
      patterns: ["Suspicious URL", "Creates urgency"],
      shared_by: "security@example.com",
      shared_at: "2026-05-07T12:10:00Z"
    }
  ]
};

// Simulate network delay
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

export const WARNING_IMAGES = {
  "HIGH RISK":   "https://placehold.co/600x100/FF4757/ffffff?text=HIGH+RISK+%E2%80%94+Do+not+click+any+links",
  "MEDIUM RISK": "https://placehold.co/600x100/FFA502/ffffff?text=MEDIUM+RISK+%E2%80%94+Proceed+with+caution",
  "LOW RISK":    "https://placehold.co/600x100/2ED573/ffffff?text=LOW+RISK+%E2%80%94+Looks+safe",
};

export function getWarningImage(classification) {
  return WARNING_IMAGES[classification] || WARNING_IMAGES["LOW RISK"];
}

// API functions
export const api = {
  register: async (email, password) => {
    if (USE_MOCK) {
      await delay(500);
      return { message: "User created", user_id: 1 };
    }
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Registration failed');
    }
    return res.json();
  },

  login: async (email, password) => {
    if (USE_MOCK) {
      await delay(500);
      return { access_token: "mock_token_12345", token_type: "bearer" };
    }
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.detail || 'Login failed');
    }
    return res.json();
  },

  analyze: async (message) => {
    if (USE_MOCK) {
      await delay(500);
      return mockData.analyze;
    }
    const token = localStorage.getItem('token');
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ message })
    });
    if (!res.ok) throw new Error('Analysis failed');
    return res.json();
  },
  
getHistory: async (limit = 20, offset = 0) => {
  if (USE_MOCK) {
    await delay(300);
    return mockData.history;
  }
  const token = localStorage.getItem('token');
  const res = await fetch(
    `${API_BASE}/api/history?limit=${limit}&offset=${offset}`,
    { headers: { 'Authorization': `Bearer ${token}` }}
  );
  if (!res.ok) {
    // Return empty array on error instead of throwing
    return [];
  }
  return res.json();
},
  
 getTrending: async (days = 7, limit = 10) => {
  if (USE_MOCK) {
    await delay(300);
    return mockData.trending;
  }
  const res = await fetch(
    `${API_BASE}/api/trending?days=${days}&limit=${limit}`
  );
  const data = await res.json();
  return data.patterns || [];
},

sharePhish: async (messageId, title, description) => {
  if (USE_MOCK) {
    await delay(400);
    return { id: 99, shared_at: new Date().toISOString() };
  }
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_BASE}/api/share`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ message_id: messageId, title, description })
  });
  return res.json();
},

getShared: async (limit = 20, offset = 0) => {
  if (USE_MOCK) {
    await delay(300);
    return mockData.shared;
  }
  const res = await fetch(
    `${API_BASE}/api/shared?limit=${limit}&offset=${offset}`
  );
  const data = await res.json();
  return data.items || [];
}
};