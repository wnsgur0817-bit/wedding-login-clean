import os, re
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, select
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
# ✅ (선택) 보호용 의존성: Authorization 헤더에서 토큰 검증
def require_auth(authorization: str = Header(None), s: Session = Depends(db)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.split(" ", 1)[1]
    return verify_access_token(token, s)

# ─────────────────────────────────────────────
# ✅ login_id 로 테넌트 자동 유추 함수
def resolve_tenant_user_by_login_id(s: Session, login_id: str):
    # 1️⃣ DB에서 직접 매칭
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

    # 2️⃣ 규칙으로 유추 (예: gen001 → T-0001)
    m = re.fullmatch(r"gen(\d{3})", login_id)
    if m:
        num = int(m.group(1))
        code = f"T-{num:04d}"
        tenant = s.scalars(select(Tenant).where(Tenant.code == code)).first()
        if tenant:
            user = s.scalars(
                select(User)
                .where(User.tenant_id == tenant.id, User.login_id == login_id)
            ).first()
            if user:
                return tenant, user

    raise HTTPException(401, "invalid credentials")

# ─────────────────────────────────────────────
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
        return {"access_token": token, "claims": {"tenant_id": tenant.code, "role": user.role}}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"login failed: {e}")

# ─────────────────────────────────────────────
@app.post("/auth/change_password")
def change_password(body: ChangePwReq, s: Session = Depends(db)):
    try:
        tenant, user = resolve_tenant_user_by_login_id(s, body.login_id)

        if not tenant.pw_hash:
            raise HTTPException(500, "tenant password not initialized")

        if not verify_pw(body.current_password, tenant.pw_hash):
            raise HTTPException(401, "invalid")

        tenant.pw_hash = hash_pw(body.new_password)
        tenant.token_version = (tenant.token_version or 1) + 1  # 자동 로그아웃 트리거
        s.commit()
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"change_password failed: {e}")

# ─────────────────────────────────────────────
@app.post("/devices/activate")
def device_activate(body: DeviceActivateReq, s: Session = Depends(db)):
    q = (
        select(Device, Tenant)
        .join(Tenant, Tenant.id == Device.tenant_id)
        .where(Device.activation_code == body.activation_code)
    )
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

