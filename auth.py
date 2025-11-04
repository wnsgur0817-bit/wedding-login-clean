#auth.py
import os, time, jwt
from argon2 import PasswordHasher

ph = PasswordHasher()
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALG = "HS256"
JWT_TTL = 60*60  # 1h

def hash_pw(raw: str) -> str:
    return ph.hash(raw)

def verify_pw(raw: str, hashed: str) -> bool:
    try:
        ph.verify(hashed, raw); return True
    except Exception:
        return False

def make_access_token(*, sub: str, tenant_code: str, role: str, token_version: int) -> str:  # NEW
    now = int(time.time())
    payload = {
        "sub": sub,
        "tenant_id": tenant_code,
        "role": role,
        "tv": token_version,      # NEW: 세션 버전
        "iat": now,
        "exp": now + JWT_TTL
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

# ── NEW: 토큰 검증(자동 로그아웃 반영용) ─────────────────────────────
from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select
from models import Tenant

def verify_access_token(token: str, s: Session):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(401, "invalid token")

    tenant_code = payload.get("tenant_id")
    tv = payload.get("tv")
    if not tenant_code or tv is None:
        raise HTTPException(401, "invalid claims")

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(401, "tenant not found")

    # 토큰 발급 시 버전(tv)과 현재 테넌트 버전이 다르면 → 자동 로그아웃
    if tv != tenant.token_version:
        raise HTTPException(401, "session expired (password changed)")

    return payload  # 필요하면 엔드포인트에서 사용
