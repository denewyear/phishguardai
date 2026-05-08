# PhishGuard Web

A real-time phishing detection platform with community-driven threat intelligence.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![React](https://img.shields.io/badge/react-18-blue.svg)

**Live Demo:** [phishguard.example.com](https://your-url-here.com)

---

## Features

- 🔍 **Instant Phishing Detection** — Analyze suspicious messages in real-time using pattern-based detection
- 📊 **Trending Threats** — See what phishing tactics are most prevalent right now
- 🤝 **Community Sharing** — Contribute and learn from a public gallery of phishing examples
- 📈 **Personal Dashboard** — Track your analysis history and security insights
- ☁️ **Cloud Native** — Built on AWS infrastructure (EC2, RDS, S3)

---

## How It Works

PhishGuard analyzes messages across 6+ pattern categories:

1. **Suspicious URLs** - Shortened links, misleading domains, IP-based URLs
2. **Urgency Language** - Pressure tactics like "URGENT", "ACT NOW"
3. **Sensitive Information Requests** - Asks for passwords, SSN, credit cards
4. **Generic Greetings** - Impersonal "Dear Customer" openings
5. **Financial Threats** - Account suspension, payment verification claims
6. **Authority Impersonation** - Fake government, bank, or tech support

**Risk Scoring:**
- **0-30:** LOW RISK ✅ — Appears safe
- **31-60:** MEDIUM RISK ⚠️ — Exercise caution
- **61-100:** HIGH RISK 🚨 — Likely phishing attempt

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- PostgreSQL 14+

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/phishguard.git
cd phishguard

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your database credentials
python main.py

# Frontend setup (in new terminal)
cd frontend
npm install
npm start
```

Backend: `http://localhost:8000`  
Frontend: `http://localhost:3000`  
API Docs: `http://localhost:8000/docs`

---

## API Reference

### Authentication

```bash
# Register
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure_password"
}

# Login
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure_password"
}
```

### Analysis (Requires JWT Token)

```bash
# Analyze message
POST /api/analyze
Authorization: Bearer <token>
Content-Type: application/json

{
  "message": "URGENT: Your account will be suspended! Click here: bit.ly/verify"
}

# Response
{
  "risk_score": 85,
  "classification": "HIGH RISK",
  "patterns_detected": [
    "Suspicious URL",
    "Urgency language",
    "Requests sensitive info"
  ],
  "recommendation": "⚠️ DO NOT click links or provide information"
}
```

### Community Features

```bash
# Get trending patterns
GET /api/trending?days=7&limit=10

# Share phishing example
POST /api/share
Authorization: Bearer <token>

{
  "message_id": 123,
  "title": "Bank Account Scam",
  "description": "Classic phishing attempt impersonating Chase Bank"
}

# Browse shared examples
GET /api/shared?limit=20&offset=0
```

Full API documentation: `/docs` (FastAPI automatic docs)

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | FastAPI (Python 3.11) |
| Frontend | React 18 |
| Database | PostgreSQL 14 |
| Authentication | JWT + bcrypt |
| Rate Limiting | slowapi |
| Cloud Storage | AWS S3 |
| Hosting | AWS EC2 + RDS |

---

## Deployment

### AWS Infrastructure

```bash
# 1. Create RDS PostgreSQL database
aws rds create-db-instance \
  --db-instance-identifier phishguard-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --master-username postgres \
  --master-user-password your-password \
  --allocated-storage 20

# 2. Launch EC2 instance
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t2.micro \
  --key-name your-key-pair \
  --security-groups phishguard-sg

# 3. Deploy backend
ssh -i your-key.pem ubuntu@your-ec2-ip
git clone https://github.com/yourusername/phishguard.git
cd phishguard/backend
pip install -r requirements.txt
python main.py

# 4. Build and deploy frontend
cd ../frontend
npm run build
# Upload to S3 or serve with nginx
```

---

## Configuration

Create `backend/.env`:

```env
DB_HOST=your-rds-endpoint.amazonaws.com
DB_NAME=phishguard
DB_USER=postgres
DB_PASS=your-password
DB_PORT=5432

SECRET_KEY=your-jwt-secret-key

ALLOWED_ORIGINS=https://your-frontend-url.com
```

---

## Database Schema

```sql
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Messages table
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    message_text TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    classification VARCHAR(20) NOT NULL,
    patterns TEXT[],
    recommendation TEXT,
    analyzed_at TIMESTAMP DEFAULT NOW()
);

-- Shared phishes table
CREATE TABLE shared_phishes (
    id SERIAL PRIMARY KEY,
    message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
    shared_by_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255),
    description TEXT,
    is_public BOOLEAN DEFAULT TRUE,
    shared_at TIMESTAMP DEFAULT NOW()
);
```

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Security

- All passwords are hashed using bcrypt
- JWT tokens expire after 7 days
- Rate limiting prevents abuse
- SQL injection protection via parameterized queries
- CORS configured for trusted origins only

**Found a security issue?** Please email security@example.com instead of opening a public issue.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Detection patterns inspired by APWG phishing trends reports
- Built with FastAPI and React
- Deployed on AWS infrastructure

---

## Contact

- **Website:** [phishguard.example.com](https://your-url-here.com)
- **Issues:** [GitHub Issues](https://github.com/yourusername/phishguard/issues)
- **Email:** contact@example.com

---

**⚠️ Disclaimer:** PhishGuard is an educational tool and should not be relied upon as the sole method of phishing detection. Always exercise caution with suspicious messages.
