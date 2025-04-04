import re
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import timedelta

from src.database.models import User
from src.database.session import get_db
from src.security import get_password_hash, verify_password, create_access_token
from src.config import settings

router = APIRouter()

USERNAME_PASSWORD_REGEX = re.compile(r"^[a-zA-Z0-9_]{4,15}$")

class UserRegister(BaseModel):
    username: str
    password: str
    photo: str = None

class UserLogin(BaseModel):
    username: str
    password: str

@router.post("/register")
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    if not USERNAME_PASSWORD_REGEX.match(user_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be 4 to 15 characters long and contain only letters, digits, or underscore (_)."
        )
    if not USERNAME_PASSWORD_REGEX.match(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be 4 to 15 characters long and contain only letters, digits, or underscore (_)."
        )
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    hashed_password = get_password_hash(user_data.password)
    new_user = User(
        username=user_data.username,
        password_hash=hashed_password,
        photo=user_data.photo
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "User registered successfully", "user_id": new_user.id}

@router.post("/login")
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not verify_password(user_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id
    }