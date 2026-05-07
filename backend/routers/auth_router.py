from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
from database import create_user, get_user_by_email
from auth import hash_password, verify_password, create_token

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@router.post("/register", status_code=201)
def register(body: RegisterRequest):
    if len(body.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if get_user_by_email(body.email):
        raise HTTPException(400, "Email already registered")
    user = create_user(body.email, hash_password(body.password))
    token = create_token(user["id"], user["email"])
    return {"token": token, "email": user["email"], "id": user["id"]}


@router.post("/login")
def login(body: LoginRequest):
    user = get_user_by_email(body.email)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    token = create_token(user["id"], user["email"])
    return {"token": token, "email": user["email"], "id": user["id"]}
