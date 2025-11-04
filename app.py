# app.py
import os, re
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models import Base, Tenant, User, Device, DeviceClaim,WeddingEvent, TicketStat, TicketPrice
from schemas import (
    LoginReq, LoginResp, ChangePwReq,
    DeviceAvailability, ClaimReq, ReleaseReq,WeddingEventIn, WeddingEventOut
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

    # auth.py 에서 토큰 검증 + tenant/token_version 체크까지 이미 함
    payload = verify_access_token(token, s)  # payload 안에는 tenant_id, tv 가 들어있음

    tenant_code = payload.get("tenant_id")
    tv = payload.get("tv")

    if not tenant_code or tv is None:
        raise HTTPException(401, "invalid claims")

    # 나머지 코드에서 편하게 쓰라고 키 이름을 통일해서 리턴
    # (기존 코드와 호환되도록 alias 추가)
    return {
        **payload,
        "tenant_code": tenant_code,
        "token_version": tv,
    }

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

@app.post("/auth/verify_password")
def verify_password(data: dict, s: Session = Depends(db), claims=Depends(require_auth)):
    tenant_code = claims["tenant_code"]
    password = data.get("password")
    if not password:
        raise HTTPException(400, "password required")

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    # ✅ 비밀번호 검증
    if not verify_pw(password, tenant.pw_hash):
        return {"valid": False}
    return {"valid": True}



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

# ✅ 여기에 추가
@app.get("/devices/list")
def list_devices_by_tenant(tenant: str, s: Session = Depends(db)):
    tenant_obj = s.scalars(select(Tenant).where(Tenant.code == tenant)).first()
    if not tenant_obj:
        raise HTTPException(404, "tenant not found")
    devices = s.scalars(select(Device).where(Device.tenant_id == tenant_obj.id)).all()
    return [
        {"id": d.id, "tenant_code": tenant, "code": d.device_code,
         "active": bool(d.active), "activation_code": d.activation_code}
        for d in devices
    ]

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


@app.post("/wedding/event", response_model=WeddingEventOut)
def create_wedding_event(
    data: WeddingEventIn,
    claims=Depends(require_auth),
    s: Session = Depends(db)
):
    tenant_code = claims["tenant_code"]
    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    event = WeddingEvent(
        tenant_id=tenant.id,
        event_date=data.event_date,
        start_time=data.start_time,
        title=data.title,
        groom_name=data.groom_name,
        bride_name=data.bride_name,
        child_min_age=data.child_min_age or 0,
        child_max_age=data.child_max_age or 0,
    )
    s.add(event)
    s.commit()
    s.refresh(event)
    return event


@app.get("/wedding/event/list", response_model=list[WeddingEventOut])
def list_wedding_events(
    claims=Depends(require_auth),
    s: Session = Depends(db)
):
    tenant_code = claims["tenant_code"]
    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    events = (
        s.query(WeddingEvent)
        .filter(WeddingEvent.tenant_id == tenant.id)
        .order_by(WeddingEvent.event_date.desc(), WeddingEvent.start_time.asc())
        .all()
    )
    return events

@app.delete("/wedding/event/{event_id}")
def delete_wedding_event(
    event_id: int,
    claims=Depends(require_auth),
    s: Session = Depends(db)
):
    tenant_code = claims["tenant_code"]

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    event = (
        s.query(WeddingEvent)
        .filter(WeddingEvent.tenant_id == tenant.id)
        .filter(WeddingEvent.id == event_id)
        .first()
    )
    if not event:
        raise HTTPException(404, "event not found")

    s.delete(event)
    s.commit()
    return {"ok": True, "deleted_id": event_id}

# ✅ 식권 발급 기록 및 누적 조회 -----------------------------

@app.post("/wedding/ticket/issue")
def issue_ticket(data: dict, s: Session = Depends(db), claims=Depends(require_auth)):
    tenant_code = claims["tenant_code"]
    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    event_title = data.get("event_title")
    ttype = data.get("type")
    count = int(data.get("count", 0))

    if not event_title or ttype not in ("성인", "어린이"):
        raise HTTPException(400, "invalid data")

    stat = (
        s.query(TicketStat)
        .filter(TicketStat.tenant_id == tenant.id)
        .filter(TicketStat.event_title == event_title)
        .first()
    )

    if not stat:
        stat = TicketStat(tenant_id=tenant.id, event_title=event_title)
        s.add(stat)

    if ttype == "성인":
        stat.adult_count += count
    else:
        stat.child_count += count

    s.commit()
    s.refresh(stat)
    return {"ok": True, "adult_count": stat.adult_count, "child_count": stat.child_count}


@app.get("/wedding/ticket/stats")
def get_ticket_stats(s: Session = Depends(db), claims=Depends(require_auth)):
    tenant_code = claims["tenant_code"]
    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    stat = (
        s.query(TicketStat)
        .filter(TicketStat.tenant_id == tenant.id)
        .order_by(TicketStat.id.desc())
        .first()
    )
    if not stat:
        # 데이터가 없으면 전부 0 반환
        return {
            "adult_count": 0,
            "child_count": 0,
            "adult_total": 0,
            "child_total": 0,
            "total_sum": 0
        }

    # ✅ 가격 불러오기
    price = (
        s.query(TicketPrice)
        .filter(TicketPrice.tenant_id == tenant.id)
        .first()
    )

    adult_total = stat.adult_count * (price.adult_price if price else 0)
    child_total = stat.child_count * (price.child_price if price else 0)
    total_sum = adult_total + child_total

    return {
        "adult_count": stat.adult_count,
        "child_count": stat.child_count,
        "adult_total": adult_total,
        "child_total": child_total,
        "total_sum": total_sum
    }

# ✅ 식권 가격 설정/조회 ---------------------------------------------------------

@app.post("/wedding/ticket/price")
def set_ticket_price(data: dict, s: Session = Depends(db), claims=Depends(require_auth)):
    tenant_code = claims["tenant_code"]
    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    adult_price = int(data.get("adult_price", 0))
    child_price = int(data.get("child_price", 0))

    price = (
        s.query(TicketPrice)
        .filter(TicketPrice.tenant_id == tenant.id)
        .first()
    )

    if not price:
        price = TicketPrice(
            tenant_id=tenant.id,
            adult_price=adult_price,
            child_price=child_price,
        )
        s.add(price)
    else:
        price.adult_price = adult_price
        price.child_price = child_price

    s.commit()
    s.refresh(price)
    return {"ok": True, "adult_price": price.adult_price, "child_price": price.child_price}


@app.get("/wedding/ticket/price")
def get_ticket_price(s: Session = Depends(db), claims=Depends(require_auth)):
    tenant_code = claims["tenant_code"]
    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    price = (
        s.query(TicketPrice)
        .filter(TicketPrice.tenant_id == tenant.id)
        .first()
    )
    if not price:
        return {"adult_price": 0, "child_price": 0}
    return {"adult_price": price.adult_price, "child_price": price.child_price}

# ─────────────────────────────────────────────
@app.get("/health")
def health():
    """Render keep-alive 엔드포인트"""
    return {
        "status": "ok",
        "server_time": datetime.now().isoformat()
    }