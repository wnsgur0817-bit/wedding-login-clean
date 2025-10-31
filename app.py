﻿# app.py
import os, re
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models import Base, Tenant, User, Device, DeviceClaim
from schemas import (
    LoginReq, LoginResp, ChangePwReq,
    DeviceAvailability, ClaimReq, ReleaseReq
)
from auth import verify_pw, make_access_token, hash_pw, verify_access_token
from manage_generate import seed_if_empty

# ─────────────────────────────────────────────
# DB
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
engine = create_engine(DATABASE_URL, future=True)
Base.metadata.create_all(engine)

def db():
    with Session(engine) as s:
        yield s

# ─────────────────────────────────────────────
# APP
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_headers=["*"],
    allow_methods=["*"],
)

@app.on_event("startup")
def _maybe_seed():
    if os.getenv("AUTO_SEED", "false").lower() == "true":
        seeded = seed_if_empty(engine)
        print(f"[AUTO_SEED] seeded={seeded}")

# ─────────────────────────────────────────────
# 인증 의존성 (비번 변경 시 즉시 401)
def require_auth(authorization: str = Header(None), s: Session = Depends(db)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.split(" ", 1)[1]
    claims = verify_access_token(token, s)  # sub/tenant_code/token_version 포함

    tenant = s.scalars(select(Tenant).where(Tenant.code == claims["tenant_code"])).first()
    if not tenant:
        raise HTTPException(401, "tenant not found")
    current_tv = tenant.token_version or 1
    if current_tv != claims.get("token_version", 0):
        raise HTTPException(401, "token revoked")
    return claims

# ─────────────────────────────────────────────
# 로그인/계정
def resolve_tenant_user_by_login_id(s: Session, login_id: str):
    rows = s.execute(
        select(User, Tenant)
        .join(Tenant, Tenant.id == User.tenant_id)
        .where(User.login_id == login_id)
    ).all()

    if len(rows) == 1:
        user, tenant = rows[0]
        return tenant, user
    if len(rows) > 1:
        raise HTTPException(409, "ambiguous login_id across tenants")

    m = re.fullmatch(r"gen(\d{3})", login_id)
    if m:
        num = int(m.group(1))
        code = f"T-{num:04d}"
        tenant = s.scalars(select(Tenant).where(Tenant.code == code)).first()
        if tenant:
            user = s.scalars(
                select(User).where(User.tenant_id == tenant.id, User.login_id == login_id)
            ).first()
            if user:
                return tenant, user
    raise HTTPException(401, "invalid credentials")

@app.post("/auth/login", response_model=LoginResp)
def login(body: LoginReq, s: Session = Depends(db)):
    try:
        tenant, user = resolve_tenant_user_by_login_id(s, body.login_id)

        if not tenant.pw_hash:
            raise HTTPException(500, "tenant password not initialized")
        if not verify_pw(body.password, tenant.pw_hash):
            raise HTTPException(401, "invalid credentials")

        tv = tenant.token_version or 1
        token = make_access_token(
            sub=str(user.id),
            tenant_code=tenant.code,
            role=user.role,
            token_version=tv,
        )
        return {
            "access_token": token,
            "claims": {"tenant_id": tenant.code, "role": user.role}
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"login failed: {e}")

@app.post("/auth/change_password")
def change_password(body: ChangePwReq, s: Session = Depends(db)):
    try:
        tenant, _user = resolve_tenant_user_by_login_id(s, body.login_id)

        if not tenant.pw_hash:
            raise HTTPException(500, "tenant password not initialized")
        if not verify_pw(body.current_password, tenant.pw_hash):
            raise HTTPException(401, "invalid")

        tenant.pw_hash = hash_pw(body.new_password)
        tenant.token_version = (tenant.token_version or 1) + 1  # 모든 토큰 즉시 무효
        s.commit()
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"change_password failed: {e}")

@app.get("/auth/me")
def me(claims=Depends(require_auth)):
    return {"ok": True, "claims": claims}

# ─────────────────────────────────────────────
# Device Claim(점유) + TTL/Heartbeat
def _gc_expired_claims(s: Session):
    s.query(DeviceClaim).filter(
        DeviceClaim.expires_at.isnot(None),
        DeviceClaim.expires_at < datetime.utcnow()
    ).delete(synchronize_session=False)
    s.commit()

@app.get("/devices", response_model=list[DeviceAvailability])
def list_devices(tenant_id: str, s: Session = Depends(db)):
    _gc_expired_claims(s)

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_id)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    devices = s.scalars(
        select(Device).where(Device.tenant_id == tenant.id)
    ).all()

    claims = s.scalars(
        select(DeviceClaim.device_code).where(DeviceClaim.tenant_id == tenant.id)
    ).all()
    claimed_set = set(claims)

    codes = [d.device_code for d in devices]
    if 'D-ADMIN' not in codes:
        codes.insert(0, 'D-ADMIN')

    return [{"code": c, "available": (c not in claimed_set)} for c in codes]

@app.post("/devices/claim")
def claim_device(body: ClaimReq, s: Session = Depends(db)):
    _gc_expired_claims(s)

    tenant = s.scalars(select(Tenant).where(Tenant.code == body.tenant_id)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    if body.device_code != "D-ADMIN":
        exists = s.scalars(
            select(Device).where(
                Device.tenant_id == tenant.id,
                Device.device_code == body.device_code
            )
        ).first()
        if not exists:
            raise HTTPException(404, "device not found")

    # TTL(분) 환경변수, 기본 0=만료없음. 운영에선 2~5분 권장
    ttl_minutes = int(os.getenv("DEVICE_CLAIM_TTL_MINUTES", "0"))
    expires_at = None
    if ttl_minutes > 0:
        expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)

    claim = DeviceClaim(
        tenant_id=tenant.id,
        device_code=body.device_code,
        session_id=body.session_id,
        expires_at=expires_at,
    )
    try:
        s.add(claim)
        s.commit()
        return {"ok": True}
    except IntegrityError:
        s.rollback()
        raise HTTPException(409, "device already in use")

@app.post("/devices/release")
def release_device(body: ReleaseReq, s: Session = Depends(db)):
    tenant = s.scalars(select(Tenant).where(Tenant.code == body.tenant_id)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    deleted = s.query(DeviceClaim).filter(
        DeviceClaim.tenant_id == tenant.id,
        DeviceClaim.device_code == body.device_code,
        DeviceClaim.session_id == body.session_id,
    ).delete(synchronize_session=False)
    s.commit()
    return {"ok": bool(deleted)}

@app.post("/devices/heartbeat")
def heartbeat(body: ClaimReq, s: Session = Depends(db)):
    """주기적으로 호출하여 expires_at 연장 (앱에서 30~60초 간격 권장)"""
    ttl_minutes = int(os.getenv("DEVICE_CLAIM_TTL_MINUTES", "0"))
    if ttl_minutes <= 0:
        return {"ok": True}  # TTL 사용 안 하면 noop

    tenant = s.scalars(select(Tenant).where(Tenant.code == body.tenant_id)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    claim = s.query(DeviceClaim).filter(
        DeviceClaim.tenant_id == tenant.id,
        DeviceClaim.device_code == body.device_code,
        DeviceClaim.session_id == body.session_id,
    ).first()
    if not claim:
        raise HTTPException(404, "claim not found")

    claim.expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    s.commit()
    return {"ok": True, "expires_at": claim.expires_at.isoformat()}

# ─────────────────────────────────────────────
@app.get("/healthz")
def healthz():
    return {"ok": True}
