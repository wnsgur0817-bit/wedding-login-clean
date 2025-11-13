# auth.py
import os, time, jwt
from argon2 import PasswordHasher
from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select
from models import Tenant

ph = PasswordHasher()

JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALG = "HS256"
JWT_TTL = 60 * 60  # 1시간


def hash_pw(raw: str) -> str:
    return ph.hash(raw)


def verify_pw(raw: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, raw)
    except Exception:
        return False


# ----------------------------------------------------------
# JWT 생성
# ----------------------------------------------------------
def make_access_token(
    *,
    sub: str,           # user.id
    tenant_code: str,   # 예: T-0001
    role: str,          # admin or staff
    token_version: int, # tenant.token_version
    device_code: str    # D-A01, D-ADMIN 등
) -> str:
    now = int(time.time())
    payload = {
        "sub": sub,
        "tenant_id": tenant_code,
        "role": role,
        "device_code": device_code,
        "tv": token_version,
        "iat": now,
        "exp": now + JWT_TTL,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


# ----------------------------------------------------------
# JWT 검증 (로그인 유지 + 비밀번호 변경 시 강제 로그아웃)
# ----------------------------------------------------------
def verify_access_token(token: str, s: Session):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(401, "invalid token")

    tenant_code = payload.get("tenant_id")
    tv = payload.get("tv")

    if tenant_code is None or tv is None:
        raise HTTPException(401, "invalid claims")

    tenant = (
        s.scalars(select(Tenant).where(Tenant.code == tenant_code))
        .first()
    )
    if not tenant:
        raise HTTPException(401, "tenant not found")

    # 비밀번호 변경되면 모든 토큰 즉시 무효화
    if tv != tenant.token_version:
        raise HTTPException(401, "session expired (token version mismatch)")

    return payload

