# PhishGuard AI

A cloud-deployed phishing detection system that analyzes suspicious messages, assigns a 0–100 risk score, and flags the specific patterns that make a message dangerous.

Built as a two-person project with a FastAPI backend, a React frontend, and a full AWS deployment (EC2, RDS, S3). Infrastructure was decommissioned after the project period; the sections below describe the architecture as deployed.

<!-- Add a screenshot of the analysis UI here — 
![PhishGuard analysis screen](docs/screenshot.png) -->

## What it does

A user pastes a suspicious message (an email, SMS, or DM) and PhishGuard returns a risk score, a classification, and the concrete signals behind the score — suspicious URLs, urgency language, impersonation cues, and other common phishing patterns. Analyzed messages are saved to a per-user history, and users can contribute notable examples to a shared gallery. A trending view surfaces the most common phishing techniques over rolling time windows.

## Architecture

```
React (S3)  ──►  FastAPI on EC2  ──►  PostgreSQL (RDS)
                       │
                       └─►  detect.py — risk-scoring engine
```

- **Frontend** — React single-page app served from AWS S3 static hosting.
- **Backend** — FastAPI service, containerized with Docker, running on EC2.
- **Database** — PostgreSQL on AWS RDS, accessed via parameterized queries.
- **Risk engine** — `detect.py`, a rule-based analyzer that scores messages and returns the patterns it matched.

## Key features

- **Risk scoring** — every message gets a 0–100 score and a HIGH / MEDIUM / LOW classification, with the matched patterns returned alongside so the result is explainable rather than a black box.
- **Pattern detection** — identifies 6+ phishing signals (suspicious URLs, urgency language, impersonation, and more).
- **Authentication** — JWT-based registration and login, with bcrypt-hashed passwords.
- **History & analytics** — paginated per-user history and personal risk breakdowns.
- **Community gallery** — users can share notable phishing examples; a trending view aggregates the most common patterns over 1/7/30-day windows.
- **Rate limiting** — per-endpoint throttling to protect the API.

## Security

Security was a first-class concern given the subject matter:

- JWT authentication with bcrypt password hashing
- Parameterized queries throughout (SQL-injection prevention)
- Pydantic input validation on every endpoint
- CORS restricted to an allowlist
- Per-endpoint rate limiting via slowapi
- Secrets kept in environment variables, never committed to source

## Tech stack

**Backend** — FastAPI (Python), PostgreSQL (psycopg2), JWT auth (python-jose, passlib, bcrypt), slowapi, Docker
**Frontend** — React 18, React Router v6
**Infrastructure** — AWS EC2, RDS (PostgreSQL), S3

## Running locally

**Prerequisites:** Python 3.9+, Node.js 16+, and a PostgreSQL instance (local or remote).

**Backend**

```bash
cd backend
python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env                # then fill in your own values
python main.py                      # runs on http://localhost:8000
```

The `.env` file holds your database connection, JWT secret, and allowed origins. See `.env.example` for the required keys — never commit a real `.env`.

**Frontend**

```bash
cd frontend
npm install
npm start                           # runs on http://localhost:3000
```

Point the frontend at your backend by setting the API base URL in `src/api/` (`USE_MOCK = false`).

## API overview

The backend exposes auth, analysis, and community endpoints. A representative call:

```
POST /api/analyze          (requires a Bearer token)
Request:   { "message": "URGENT! Click here to verify your account" }
Response:  {
  "risk_score": 75,
  "classification": "HIGH RISK",
  "patterns_detected": ["Suspicious URL", "Urgency language"],
  "recommendation": "Do not click links"
}
```

Other endpoints cover registration and login (`/auth/*`), message history and stats (`/api/history`, `/api/stats`), and the shared gallery and trending patterns (`/api/shared`, `/api/trending`). Full request/response shapes live in the route handlers under `backend/routers/`.

## Project structure

```
phishguardai/
├── backend/
│   ├── main.py              # FastAPI application entry point
│   ├── detect.py            # risk-scoring engine
│   ├── database.py          # database access layer
│   ├── auth.py              # JWT / password utilities
│   ├── routers/             # auth and analysis endpoints
│   ├── Dockerfile
│   └── requirements.txt
└── frontend/
    ├── src/                 # pages, components, API client
    └── package.json
```

## Team & my role

A two-person project. I owned the **backend and infrastructure**:

- FastAPI service design and all API endpoints
- The `detect.py` risk-scoring and pattern-detection engine
- JWT authentication and password hashing
- PostgreSQL schema and data-access layer
- Docker containerization and AWS deployment (EC2, RDS, S3)

My teammate built the React frontend, UI/UX, and component architecture.

## Possible extensions

Directions the project could grow: a machine-learning detection model to complement the rule-based engine, a browser extension for in-context scanning, and email-forwarding integration.