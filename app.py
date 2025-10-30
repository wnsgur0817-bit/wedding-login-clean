import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from models import Base, Tenant, User, Device
from schemas import LoginReq, LoginResp, ChangePwReq, DeviceActivateReq
from auth import verify_pw, make_access_token, hash_pw
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
@app.post("/auth/login", response_model=LoginResp)
def login(body: LoginReq, s: Session = Depends(db)):
    q = (select(User, Tenant)
         .join(Tenant, Tenant.id == User.tenant_id)
         .where(User.login_id == body.login_id))
    row = s.execute(q).first()
    if not row:
        raise HTTPException(401, "invalid credentials")
    user, tenant = row
    if not verify_pw(body.password, user.pw_hash):
        raise HTTPException(401, "invalid credentials")
    token = make_access_token(sub=str(user.id), tenant_code=tenant.code, role=user.role)
    return {"access_token": token, "claims": {"tenant_id": tenant.code, "role": user.role}}

# ─────────────────────────────────────────────
@app.post("/auth/change_password")
def change_password(body: ChangePwReq, s: Session = Depends(db)):
    q = select(User).where(User.login_id == body.login_id)
    user = s.scalars(q).first()
    if not user or not verify_pw(body.current_password, user.pw_hash):
        raise HTTPException(401, "invalid")
    user.pw_hash = hash_pw(body.new_password)
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
