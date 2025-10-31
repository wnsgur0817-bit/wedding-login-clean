import os, re
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, select, and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from models import Base, Tenant, User, Device, DeviceClaim
from schemas import LoginReq, LoginResp, ChangePwReq, DeviceActivateReq,DeviceAvailability, ClaimReq, ReleaseReq
from auth import verify_pw, make_access_token, hash_pw, verify_access_token
from manage_generate import seed_if_empty
from datetime import datetime, timedelta




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

@app.get("/auth/me")
def me(claims=Depends(require_auth)):
    # 필요시 사용자/테넌트 정보 더 포함 가능
    return {"ok": True, "claims": claims}

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
    claims = verify_access_token(token, s)  # ← 여기서 sub/tenant_code/token_version 파싱

    # ★ 추가: 서버의 현재 token_version 과 토큰의 token_version 일치 여부 확인
    tenant = s.scalars(select(Tenant).where(Tenant.code == claims["tenant_code"])).first()
    current_tv = (tenant.token_version or 1)
    if current_tv != claims.get("token_version", 0):
        raise HTTPException(401, "token revoked")  # 비번변경 등으로 무효화된 토큰

    return claims

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

# 만료된 클레임을 정리(선택): expires_at이 지났으면 삭제
def _gc_expired_claims(s: Session):
    s.query(DeviceClaim).filter(
        DeviceClaim.expires_at.isnot(None),
        DeviceClaim.expires_at < datetime.utcnow()
    ).delete(synchronize_session=False)
    s.commit()

@app.get("/devices", response_model=list[DeviceAvailability])
def list_devices(tenant_id: str, s: Session = Depends(db)):
    # 선택: 만료 정리
    _gc_expired_claims(s)

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_id)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    # 이 테넌트의 등록된 디바이스 목록
    devices = s.scalars(
        select(Device).where(Device.tenant_id == tenant.id)
    ).all()

    # 점유 중인 디바이스 조회
    claims = s.scalars(
        select(DeviceClaim.device_code).where(DeviceClaim.tenant_id == tenant.id)
    ).all()
    claimed_set = set(claims)

    # 관리자 'D-ADMIN'을 목록에 강제로 포함시키고 싶으면 여기에 추가해도 됨
    codes = [d.device_code for d in devices]
    if 'D-ADMIN' not in codes:
        codes.insert(0, 'D-ADMIN')

    result = [
        {"code": c, "available": (c not in claimed_set)}
        for c in codes
    ]
    return result

@app.post("/devices/claim")
def claim_device(body: ClaimReq, s: Session = Depends(db)):
    # 선택: 만료 정리
    _gc_expired_claims(s)

    tenant = s.scalars(select(Tenant).where(Tenant.code == body.tenant_id)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    # 디바이스 존재 체크: 'D-ADMIN'은 가상 디바이스로 허용
    if body.device_code != "D-ADMIN":
        exists = s.scalars(
            select(Device).where(
                Device.tenant_id == tenant.id,
                Device.device_code == body.device_code
            )
        ).first()
        if not exists:
            raise HTTPException(404, "device not found")

    # 만료 정책(선택): 2분 후 만료
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
        # 이미 누가 점유 중
        raise HTTPException(409, "device already in use")


# ─────────────────────────────────────────────
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

# ─────────────────────────────────────────────
@app.get("/healthz")
def healthz():
    return {"ok": True}

