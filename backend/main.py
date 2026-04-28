import os
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database import init_db
from routers.auth_router import router as auth_router
from routers.analyze_router import router as analyze_router, limiter
from routers.sms_router import router as sms_router

app = FastAPI(title="PhishGuard AI", version="1.0.0")

# Rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — allow React dev server locally, restrict in prod
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth_router)
app.include_router(analyze_router)
app.include_router(sms_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "PhishGuard AI"}


# Serve React build in production
FRONTEND_BUILD = os.path.join(os.path.dirname(__file__), "..", "frontend", "build")
if os.path.isdir(FRONTEND_BUILD):
    app.mount("/static", StaticFiles(directory=os.path.join(FRONTEND_BUILD, "static")), name="static")

    @app.get("/{full_path:path}")
    def serve_react(full_path: str):
        index = os.path.join(FRONTEND_BUILD, "index.html")
        return FileResponse(index)


@app.on_event("startup")
def startup():
    init_db()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
