import os
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session
from models import Base, Tenant, User, Device
from schemas import LoginReq, LoginResp, ChangePwReq, DeviceActivateReq
from auth import verify_pw, make_access_token, hash_pw, verify_access_token
from manage_generate import seed_if_empty

# ─────────────────────────────────────────────
# ✅ 데이터베이스 연결
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
engine = create_engine(DATABASE_URL, future=True)
Base.metadata.create_all(engine)

# ─────────────────────────────────────────────
# ✅ FastAPI 앱 생성
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_headers=["*"],
    allow_methods=["*"],
)

# ─────────────────────────────────────────────
# ✅ 자동 시드 (AUTO_SEED=true 일 때만)
@app.on_event("startup")
def _maybe_seed():
    if os.getenv("AUTO_SEED", "false").lower() == "true":
        seeded = seed_if_empty(engine)
        print(f"[AUTO_SEED] seeded={seeded}")

# ─────────────────────────────────────────────
def db():
    with Session(engine) as s:
        yield s

# ─────────────────────────────────────────────
# (선택) 보호용 의존성: Authorization 헤더에서 토큰 꺼내 검증
def require_auth(authorization: str = Header(None), s: Session = Depends(db)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.split(" ", 1)[1]
    return verify_access_token(token, s)  # payload 반환

# ─────────────────────────────────────────────
@app.post("/auth/login", response_model=LoginResp)
def login(body: LoginReq, s: Session = Depends(db)):
    # 1) 테넌트 조회
    tenant = s.scalars(select(Tenant).where(Tenant.code == body.tenant_code)).first()
    if not tenant:
        raise HTTPException(401, "invalid credentials")

    # 2) 해당 테넌트 내 사용자 조회
    user = s.scalars(
        select(User).where(User.tenant_id == tenant.id, User.login_id == body.login_id)
    ).first()
    if not user:
        raise HTTPException(401, "invalid credentials")

    # 3) 비번 검증은 '테넌트 비번'으로
    if not verify_pw(body.password, tenant.pw_hash):
        raise HTTPException(401, "invalid credentials")

    # 4) 토큰 발급 시 현재 token_version 포함
    token = make_access_token(
        sub=str(user.id),
        tenant_code=tenant.code,
        role=user.role,
        token_version=tenant.token_version,   # ← 중요
    )
    return {"access_token": token, "claims": {"tenant_id": tenant.code, "role": user.role}}

# ─────────────────────────────────────────────
@app.post("/auth/change_password")
def change_password(body: ChangePwReq, s: Session = Depends(db)):
    # 1) 테넌트 + 사용자 확인
    tenant = s.scalars(select(Tenant).where(Tenant.code == body.tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    user = s.scalars(
        select(User).where(User.tenant_id == tenant.id, User.login_id == body.login_id)
    ).first()
    if not user:
        raise HTTPException(401, "invalid")

    # 2) 현재 비번 검증: 테넌트 비번 기준
    if not verify_pw(body.current_password, tenant.pw_hash):
        raise HTTPException(401, "invalid")

    # 3) 테넌트 비번 갱신 + token_version 증가 → 전체 자동 로그아웃
    tenant.pw_hash = hash_pw(body.new_password)
    tenant.token_version = (tenant.token_version or 1) + 1  # ← 핵심
    # pw_updated_at은 onupdate=func.now()로 자동 갱신
    s.commit()
    return {"ok": True}

# ─────────────────────────────────────────────
@app.post("/devices/activate")
def device_activate(body: DeviceActivateReq, s: Session = Depends(db)):
    q = select(Device, Tenant).join(Tenant, Tenant.id == Device.tenant_id).where(Device.activation_code == body.activation_code)
    row = s.execute(q).first()
    if not row:
        raise HTTPException(404, "activation code not found")
    device, tenant = row
    device.active = 1
    s.commit()
    return {"tenant_id": tenant.code, "device_code": device.device_code, "active": True}

# ─────────────────────────────────────────────
@app.get("/healthz")
def healthz():
    return {"ok": True}
