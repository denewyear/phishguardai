// API_CONTRACT.md 

BASE_URL: http://localhost:8000 (dev) → http://your-ec2-ip:8000 (prod)

// Authentication
All protected endpoints require:
  Header: Authorization: Bearer <token>

// POST /api/analyze
Request:  { message: string }
Response: { 
  risk_score: number,           // 0-100
  classification: string,       // "HIGH RISK" | "MEDIUM RISK" | "LOW RISK"
  patterns_detected: string[],  // ["Suspicious URL", "Urgency language"]
  recommendation: string
}

// GET /api/history?limit=20&offset=0
Response: [{
  id: number,
  message_text: string,
  risk_score: number,
  classification: string,
  patterns: string[],
  recommendation: string,
  analyzed_at: string  // ISO 8601: "2026-05-08T10:30:00Z"
}]

// GET /api/trending?days=7&limit=10
Response: [{
  pattern: string,       // "Suspicious URL"
  count: number,         // 45
  percentage: number     // 32.1
}]

// POST /api/share
Request:  { 
  message_id: number, 
  title?: string,          // Optional
  description?: string     // Optional
}
Response: { 
  id: number, 
  shared_at: string 
}

// GET /api/shared?limit=20&offset=0
Response: [{
  id: number,
  title: string,
  description: string,
  message_text: string,
  risk_score: number,
  classification: string,
  patterns: string[],
  shared_by: string,      // Email of user who shared
  shared_at: string
}]

// GET /api/stats (optional - user dashboard)
Response: {
  total: number,
  high: number,
  medium: number,
  low: number,
  avg_score: number
}