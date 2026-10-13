"""
Authentication REST API
Endpoints for user login, session inspection, quick account switching, and tier upgrades.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from ..db.session import get_db
from ..db.models import User
from ..services.auth_service import (
    verify_password,
    create_access_token,
    get_current_user,
    seed_default_users
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    email: str
    password: str

class SwitchAccountRequest(BaseModel):
    role: str  # "pro" or "standard"

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

@router.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """Authenticates user with email and password and returns bearer JWT."""
    # Ensure seed users exist in DB
    seed_default_users(db)

    email = req.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token({
        "sub": user.email,
        "user_id": user.id,
        "role": user.role,
        "name": user.full_name
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active
        }
    }

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Returns profile for currently authenticated user."""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "is_active": current_user.is_active
    }

@router.get("/demo-accounts")
def get_demo_accounts():
    """Provides pre-seeded user credentials for seamless testing and demonstration."""
    return [
        {
            "role": "pro",
            "email": "pro@hackingly.io",
            "password": "Pro@123456",
            "name": "Pro Security Engineer",
            "plan": "Pro Tier",
            "badge": "Full Autonomous AI Playbooks & Analytical PDF Patches Unlocked"
        },
        {
            "role": "standard",
            "email": "user@hackingly.io",
            "password": "User@123456",
            "name": "Standard Analyst",
            "plan": "Standard Tier",
            "badge": "Standard Posture Scans & Basic Reports"
        }
    ]

@router.post("/switch-account", response_model=LoginResponse)
def switch_account(req: SwitchAccountRequest, db: Session = Depends(get_db)):
    """1-Click account switcher between Pro and Standard demo users."""
    seed_default_users(db)
    target_role = req.role.lower().strip()
    target_email = "pro@hackingly.io" if target_role == "pro" else "user@hackingly.io"

    user = db.query(User).filter(User.email == target_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Demo account not found")

    token = create_access_token({
        "sub": user.email,
        "user_id": user.id,
        "role": user.role,
        "name": user.full_name
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_active": user.is_active
        }
    }

@router.post("/upgrade")
def upgrade_user(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Upgrades current user to Pro tier."""
    current_user.role = "pro"
    db.commit()
    db.refresh(current_user)

    new_token = create_access_token({
        "sub": current_user.email,
        "user_id": current_user.id,
        "role": "pro",
        "name": current_user.full_name
    })

    return {
        "status": "success",
        "message": "Successfully upgraded to Pro Subscription!",
        "access_token": new_token,
        "role": current_user.role
    }
