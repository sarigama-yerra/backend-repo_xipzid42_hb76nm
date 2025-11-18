import os
import hashlib
import secrets
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional
from database import db, create_document, get_documents
from schemas import AuthUser, User, Product

app = FastAPI(title="Interview & Surveys SaaS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Backend for Interviews & Surveys SaaS is running"}


# --------- Auth Logic (demo-grade) ---------
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    token: str
    name: str
    email: EmailStr

COLL_AUTH = "authuser"  # from AuthUser schema name lowercased

def _hash_password(password: str, salt: Optional[str] = None):
    if not salt:
        salt = secrets.token_hex(16)
    hash_hex = hashlib.sha256((salt + password).encode()).hexdigest()
    return hash_hex, salt

@app.post("/api/auth/register", response_model=AuthResponse)
def register_user(payload: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    # Check if exists
    existing = list(db[COLL_AUTH].find({"email": payload.email}).limit(1))
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    pwd_hash, salt = _hash_password(payload.password)
    doc = AuthUser(email=payload.email, name=payload.name, password_hash=pwd_hash, salt=salt)
    _id = create_document(COLL_AUTH, doc)

    # Simple token = hash(email + salt)
    token = hashlib.sha256((payload.email + salt).encode()).hexdigest()
    return AuthResponse(token=token, name=payload.name, email=payload.email)

@app.post("/api/auth/login", response_model=AuthResponse)
def login_user(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    user = db[COLL_AUTH].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    test_hash, _ = _hash_password(payload.password, user.get("salt"))
    if test_hash != user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = hashlib.sha256((payload.email + user.get("salt", "")).encode()).hexdigest()
    return AuthResponse(token=token, name=user.get("name"), email=payload.email)


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# Provide schema endpoint for viewer
@app.get("/schema")
def get_schema():
    # Describe available pydantic models (names only) for the viewer
    return {
        "models": [
            {"name": "User"},
            {"name": "Product"},
            {"name": "AuthUser"}
        ]
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
