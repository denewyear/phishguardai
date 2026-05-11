# PhishGuard AI

A cloud-deployed phishing detection system that analyzes suspicious messages and provides risk scoring with pattern detection.

## 🌐 Live Application

**Frontend (S3):** http://phishguard-frontend-827297749354-us-east-2-an.s3-website.us-east-2.amazonaws.com/

**Backend (EC2):** http://3.17.25.164:8000

**Health Check:** http://3.17.25.164:8000/health

## 🏗️ Architecture

**Deployment Path:** Traditional (Path A)
- **Frontend:** React app hosted on AWS S3 Static Website Hosting
- **Backend:** FastAPI application containerized with Docker, deployed on AWS EC2 (Amazon Linux 2023)
- **Database:** PostgreSQL hosted on AWS RDS
- **Storage:** AWS S3 for static assets

**Data Flow:**
User → S3 Frontend → EC2 Backend (FastAPI) → RDS PostgreSQL
↓
detect.py (Risk Analysis Engine)

## ✨ Features

### Core Features
- **User Authentication:** JWT-based registration and login system
- **Phishing Analysis:** Real-time message analysis with 0-100 risk scoring
- **Pattern Detection:** Identifies 6+ phishing patterns (suspicious URLs, urgency language, impersonation, etc.)
- **Message History:** Paginated history of all analyzed messages
- **Rate Limiting:** API endpoint protection via slowapi
- **Community Sharing:** Share phishing examples to public gallery

### Analytics
- **Trending Patterns:** Most common phishing techniques over 1/7/30 day windows
- **User Statistics:** Personal analysis counts and risk breakdowns
- **Shared Gallery:** Browse community-contributed phishing examples with filtering

## 🔌 API Endpoints

### Authentication
- `POST /auth/register` - Create new user account
```json
  Request: {"email": "user@example.com", "password": "password123"}
  Response: {"message": "User created", "user_id": 1}
```

- `POST /auth/login` - Get JWT access token
```json
  Request: {"email": "user@example.com", "password": "password123"}
  Response: {"access_token": "eyJ...", "token_type": "bearer"}
```

### Analysis (Requires Authentication)
- `POST /api/analyze` - Analyze a message
```json
  Request: {"message": "URGENT! Click here to verify your account"}
  Response: {
    "risk_score": 75,
    "classification": "HIGH RISK",
    "patterns_detected": ["Suspicious URL", "Urgency language"],
    "recommendation": "Do not click links"
  }
```

- `GET /api/history?limit=20&offset=0` - Get user's analysis history
- `GET /api/stats` - Get user statistics (total analyzed, risk breakdown)
- `DELETE /api/history/{id}` - Delete a message from history

### Community
- `GET /api/trending?days=7&limit=10` - Most common phishing patterns
```json
  Response: {
    "patterns": [
      {"pattern": "Suspicious URL", "count": 45, "percentage": 32.1},
      {"pattern": "Urgency language", "count": 38, "percentage": 27.1}
    ],
    "days": 7
  }
```

- `POST /api/share` - Share a phishing example to gallery (requires auth)
```json
  Request: {"message_id": 123, "title": "Classic Bank Scam", "description": "..."}
```

- `GET /api/shared?limit=20&offset=0` - Browse shared examples
```json
  Response: {
    "items": [
      {
        "id": 1,
        "title": "...",
        "message_text": "...",
        "risk_score": 95,
        "patterns": ["..."],
        "shared_at": "2026-05-10T..."
      }
    ]
  }
```

## 💻 Tech Stack

### Backend
- **Framework:** FastAPI (Python 3.9)
- **Database:** PostgreSQL (psycopg2)
- **Authentication:** JWT tokens (python-jose, passlib, bcrypt)
- **Rate Limiting:** slowapi
- **CORS:** FastAPI middleware
- **Deployment:** Docker container on EC2

### Frontend
- **Framework:** React 18
- **Routing:** React Router v6
- **API Client:** Fetch API
- **Styling:** Inline styles with design system
- **Deployment:** S3 Static Website Hosting

### Infrastructure
- **Compute:** AWS EC2 t2.micro (Amazon Linux 2023)
- **Database:** AWS RDS PostgreSQL (db.t3.micro)
- **Storage:** AWS S3
- **Networking:** VPC, Security Groups, Elastic IP

## 🚀 Local Development

### Prerequisites
- Python 3.9+
- Node.js 16+
- PostgreSQL (or use RDS connection)

### Backend Setup
```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cat > .env << EOF
DB_HOST=phishguard-db.cxkyymwse1hm.us-east-2.rds.amazonaws.com
DB_NAME=phishguard
DB_USER=postgres
DB_PASS=REMOVED_ROTATED_CREDENTIAL
DB_PORT=5432
SECRET_KEY=your-secret-key-here
ALLOWED_ORIGINS=http://localhost:3000
EOF

# Run server
python main.py
# Backend runs on http://localhost:8000
```

### Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Update API endpoint in src/api/mockApi.js
# Set USE_MOCK = false
# Set API_BASE = 'http://localhost:8000'

# Run development server
npm start
# Frontend runs on http://localhost:3000
```

## 🧪 Testing

### Using the Live Application
1. Go to: http://phishguard-frontend-827297749354-us-east-2-an.s3-website.us-east-2.amazonaws.com/
2. Click **Sign up** and create an account
3. Paste a suspicious message and click **Analyze**
4. Check **My History**, **Trending**, and **Gallery** pages

### Using Postman
Import and test API endpoints:
1. Health check: `GET http://3.17.25.164:8000/health`
2. Register: `POST http://3.17.25.164:8000/auth/register`
3. Login: `POST http://3.17.25.164:8000/auth/login`
4. Analyze: `POST http://3.17.25.164:8000/api/analyze` (with Bearer token)

### Example Test Messages
HIGH RISK:
URGENT! Your account will be suspended. Click here NOW: http://verify-account.com
MEDIUM RISK:
Your package delivery failed. Update address: amzn-delivery.com/update
LOW RISK:
Hey! Are we still meeting for coffee at 3pm?

## 📊 Database Schema

### users
- `id` (SERIAL PRIMARY KEY)
- `email` (VARCHAR UNIQUE)
- `hashed_password` (VARCHAR)
- `created_at` (TIMESTAMP)

### messages
- `id` (SERIAL PRIMARY KEY)
- `user_id` (INTEGER FK)
- `message_text` (TEXT)
- `risk_score` (INTEGER)
- `classification` (VARCHAR)
- `patterns` (TEXT[])
- `recommendation` (TEXT)
- `analyzed_at` (TIMESTAMP)

### shared_phishes
- `id` (SERIAL PRIMARY KEY)
- `message_id` (INTEGER FK)
- `shared_by_user_id` (INTEGER FK)
- `title` (VARCHAR)
- `description` (TEXT)
- `is_public` (BOOLEAN)
- `shared_at` (TIMESTAMP)

## 👥 Team

**Partner 1 (Backend/Infrastructure):**
- Backend API development (FastAPI)
- Database design and RDS setup
- EC2 deployment and configuration
- Docker containerization
- API endpoint implementation

**Partner 2 (Frontend/Presentation):**
- React frontend development
- UI/UX design
- Component architecture
- S3 deployment
- Presentation materials

## 📝 Project Structure
phishguardai/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── database.py          # Database functions
│   ├── auth.py              # Authentication utilities
│   ├── detect.py            # Risk analysis engine
│   ├── routers/
│   │   ├── auth_router.py   # Auth endpoints
│   │   └── analyze_router.py # Analysis endpoints
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env
├── frontend/
│   ├── src/
│   │   ├── pages/           # React pages
│   │   ├── components/      # Reusable components
│   │   ├── api/             # API client
│   │   ├── styles.js        # Design system
│   │   └── App.js           # Main app component
│   ├── public/
│   │   └── _redirects       # Netlify/S3 routing
│   └── package.json
└── README.md

## 🔐 Security Features

- JWT-based authentication with secure password hashing (bcrypt)
- Rate limiting on all API endpoints
- CORS protection with whitelist
- SQL injection prevention via parameterized queries
- Input validation with Pydantic models

## 📦 Deployment

### Backend (EC2)
```bash
# SSH into EC2
ssh -i your-key.pem ec2-user@3.17.25.164

# Clone repository
git clone https://github.com/denewyear/phishguardai.git
cd phishguardai/backend

# Setup and run
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
nohup venv/bin/python main.py > backend.log 2>&1 &
```

### Frontend (S3)
```bash
# Build production bundle
cd frontend
npm run build

# Upload to S3 bucket
# Use AWS Console or AWS CLI to upload build/ contents
```

## 🎯 Future Enhancements

- Machine learning model for improved detection
- Email forwarding integration
- Browser extension
- Mobile app
- Multi-language support
- Advanced reporting and analytics

---

**Live Demo:** http://phishguard-frontend-827297749354-us-east-2-an.s3-website.us-east-2.amazonaws.com/

**GitHub:** https://github.com/denewyear/phishguardai