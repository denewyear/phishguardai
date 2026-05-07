# PhishGuard AI

Real-time phishing and smishing detection platform.
- **Web dashboard** — paste suspicious messages, get instant risk scores
- **Twilio SMS** — forward suspicious texts to our number, get analysis via SMS reply
- **JWT auth** — per-user history, private and account-scoped
- **FastAPI + React + PostgreSQL** — deployed on AWS EC2 + RDS

---

## Project Structure

```
phishguard/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── detect.py            # Phishing pattern detection engine
│   ├── database.py          # All PostgreSQL operations (psycopg2)
│   ├── auth.py              # JWT token + bcrypt password handling
│   ├── requirements.txt
│   ├── .env.example         # Copy to .env and fill in values
│   └── routers/
│       ├── auth_router.py   # POST /auth/register, POST /auth/login
│       ├── analyze_router.py# POST /analyze, GET /history, GET /stats
│       └── sms_router.py    # POST /sms (Twilio webhook)
├── frontend/
│   ├── src/
│   │   ├── App.js           # Routing + auth context
│   │   ├── api/client.js    # Fetch wrapper for all API calls
│   │   └── pages/
│   │       ├── LoginPage.js
│   │       ├── RegisterPage.js
│   │       ├── AnalyzePage.js  # Main dashboard
│   │       └── HistoryPage.js  # Full history + delete
│   └── package.json
├── Dockerfile
├── docker-compose.yml       # Local development with Postgres
└── .github/workflows/
    └── deploy.yml           # CI/CD: build + deploy to EC2
```

---

## Local Development

### Prerequisites
- Docker + Docker Compose
- Node.js 20+
- Python 3.11+

### 1. Clone and configure

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
cp backend/.env.example backend/.env
# Edit backend/.env with your values
```

### 2. Start everything with Docker Compose

```bash
docker-compose up --build
```

- Backend: http://localhost:8000
- Frontend: http://localhost:3000
- API docs: http://localhost:8000/docs

### 3. Run backend only (faster for development)

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# Make sure Postgres is running (docker-compose up db)
python main.py
```

### 4. Run frontend only

```bash
cd frontend
npm install
npm start
```

---

## Environment Variables

Copy `backend/.env.example` to `backend/.env`:

```env
DB_HOST=localhost           # RDS endpoint in production
DB_NAME=phishguard
DB_USER=postgres
DB_PASS=password
DB_PORT=5432

JWT_SECRET=your-long-random-secret

TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=+15551234567

ALLOWED_ORIGINS=http://localhost:3000
```

---

## AWS Deployment (EC2 + RDS)

### 1. Create RDS PostgreSQL

```
AWS Console → RDS → Create database
Engine: PostgreSQL 15
Instance: db.t3.micro (free tier)
DB name: phishguard
Security group: allow port 5432 from EC2 security group only
```

### 2. Launch EC2

```
AMI: Amazon Linux 2
Instance type: t2.micro (free tier)
Security group: open port 80 inbound
Assign Elastic IP
```

### 3. SSH and install Docker

```bash
ssh -i your-key.pem ec2-user@YOUR_EC2_IP
sudo yum install -y docker git
sudo service docker start
sudo usermod -aG docker ec2-user
# Log out and back in
```

### 4. Clone repo and set up .env

```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
nano backend/.env   # fill in RDS credentials + JWT secret + Twilio
```

### 5. Build and run

```bash
cd frontend && npm ci && REACT_APP_API_URL="" npm run build && cd ..
docker build -t phishguard .
docker run -d --name phishguard --restart unless-stopped \
  -p 80:8000 --env-file backend/.env phishguard
```

### 6. Configure Twilio webhook

In Twilio Console → Phone Numbers → your number → Messaging:
```
Webhook URL: http://YOUR_EC2_IP/sms
HTTP Method: POST
```

### 7. Set GitHub Secrets for CI/CD

In your GitHub repo → Settings → Secrets:
```
EC2_HOST     = your EC2 public IP
EC2_USER     = ec2-user
EC2_SSH_KEY  = (contents of your .pem file)
```

---

## API Reference

### Auth

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| POST | `/auth/register` | `{"email":"...","password":"..."}` | `{"token":"...","email":"..."}` |
| POST | `/auth/login` | `{"email":"...","password":"..."}` | `{"token":"...","email":"..."}` |

### Analyze (requires `Authorization: Bearer <token>`)

| Method | Endpoint | Body / Params | Response |
|--------|----------|---------------|----------|
| POST | `/analyze` | `{"message":"..."}` | `{"risk_score":85,"classification":"HIGH RISK","patterns_detected":[...],"recommendation":"..."}` |
| GET | `/history` | `?limit=20&offset=0` | `{"items":[...]}` |
| DELETE | `/history/{id}` | — | `{"deleted":true}` |
| GET | `/stats` | — | `{"total":10,"high":5,"medium":3,"low":2}` |

### SMS (Twilio webhook)

| Method | Endpoint | Auth |
|--------|----------|------|
| POST | `/sms` | Twilio signature header |

### Health

| Method | Endpoint |
|--------|----------|
| GET | `/health` |

---

## Rate Limits

| Endpoint | Limit | Key |
|----------|-------|-----|
| POST /analyze | 10 / minute | Client IP |
| POST /auth/login | 5 / minute | Client IP |
| POST /sms | 10 / hour | Sender phone (DB query) |
| GET /history | 30 / minute | Client IP |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python 3.11) |
| Frontend | React 18 |
| Database | PostgreSQL 15 on AWS RDS |
| Auth | JWT (python-jose) + bcrypt (passlib) |
| Rate limiting | slowapi |
| SMS | Twilio |
| Containerisation | Docker |
| CI/CD | GitHub Actions |
| Hosting | AWS EC2 (t2.micro) |

---

## Both Partners — Git Workflow

```bash
# Never commit directly to main
git checkout -b feature/your-feature
# make changes
git add .
git commit -m "descriptive message"
git push origin feature/your-feature
# open pull request → merge to main → CI/CD auto-deploys
```

Both partners must have meaningful commits. The grader checks `git log`.
