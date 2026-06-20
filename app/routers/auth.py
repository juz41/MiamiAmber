"""Registration and login endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..schemas import LoginRequest, RegisterRequest
from ..security import create_access_token, get_password_hash, validate_username, verify_password

router = APIRouter(tags=["auth"])


@router.post("/api/register")
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    username = validate_username(request.username.strip())
    if db.query(User).filter(User.name == username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(name=username, hash=get_password_hash(request.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "Registration successful", "id": user.id}


@router.post("/api/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.name == request.username).first()
    if not user or not verify_password(request.password, user.hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"id": user.id, "name": user.name})
    return {"token": token}
