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
    try:
        tenant = s.scalars(select(Tenant).where(Tenant.code == body.tenant_code)).first()
        if not tenant:
            raise HTTPException(401, "invalid credentials")

        user = s.scalars(
            select(User).where(User.tenant_id == tenant.id, User.login_id == body.login_id)
        ).first()
        if not user:
            raise HTTPException(401, "invalid credentials")

        if not tenant.pw_hash:
            # 마이그레이션 누락 등으로 테넌트 비번이 비어있을 때
            raise HTTPException(500, "tenant password not initialized")

        if not verify_pw(body.password, tenant.pw_hash):
            raise HTTPException(401, "invalid credentials")

        # token_version이 None일 경우 대비
        tv = tenant.token_version or 1

        token = make_access_token(
            sub=str(user.id),
            tenant_code=tenant.code,
            role=user.role,
            token_version=tv,
        )
        return {"access_token": token, "claims": {"tenant_id": tenant.code, "role": user.role}}
    except HTTPException:
        raise
    except Exception as e:
        # 원인 파악을 위해 500으로 올리되 메시지 남김
        raise HTTPException(500, f"login failed: {e}")

# ─────────────────────────────────────────────
@app.post("/auth/change_password")
def change_password(body: ChangePwReq, s: Session = Depends(db)):
    try:
        tenant = s.scalars(select(Tenant).where(Tenant.code == body.tenant_code)).first()
        if not tenant:
            raise HTTPException(404, "tenant not found")

        user = s.scalars(
            select(User).where(User.tenant_id == tenant.id, User.login_id == body.login_id)
        ).first()
        if not user:
            raise HTTPException(401, "invalid")

        if not tenant.pw_hash:
            raise HTTPException(500, "tenant password not initialized")

        if not verify_pw(body.current_password, tenant.pw_hash):
            raise HTTPException(401, "invalid")

        tenant.pw_hash = hash_pw(body.new_password)
        tenant.token_version = (tenant.token_version or 1) + 1
        s.commit()
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"change_password failed: {e}")


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
