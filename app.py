# app.py#
import os, re
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Header,APIRouter
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
DATABASE_URL = "postgresql+psycopg2://postgres:1q2w3e4R!@34.64.98.207:5432/wedding_db"
engine = create_engine(DATABASE_URL, future=True)
Base.metadata.create_all(engine)
router = APIRouter(prefix="/wedding/ticket", tags=["wedding-ticket"])
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

@app.get("/")
def root():
    return {"message": "Wedding backend running ✅"}

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

        # ✅ device_code를 클라이언트에서 받은 값으로 사용
        device_code = getattr(body, "device_code", "unknown")

        token = make_access_token(
            sub=str(user.id),
            tenant_code=tenant.code,
            role=user.role,
            token_version=tv,
            device_code=device_code,  # ✅ 수정됨
        )

        return {
            "access_token": token,
            "claims": {
                "tenant_id": tenant.code,
                "role": user.role,
                "device_code": device_code,  # ✅ 추가하면 Flutter에서 디버깅 편함
            },
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
    device_code = claims.get("device_code")
    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    hall_name = (data.hall_name or "").strip()
    if not hall_name:
        raise HTTPException(400, "hall_name required")
    event = WeddingEvent(
        tenant_id=tenant.id,
        device_code=device_code,
        owner_type=data.owner_type,
        hall_name=data.hall_name,  # ✅ 추가
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
def list_wedding_events(claims=Depends(require_auth), s: Session = Depends(db)):
    tenant_code = claims["tenant_code"]
    device_code = claims.get("device_code")

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    q = s.query(WeddingEvent).filter(WeddingEvent.tenant_id == tenant.id)

    # ✅ 부조석은 자기 디바이스만
    if device_code != "D-ADMIN":
        q = q.filter(WeddingEvent.device_code == device_code)

    events = q.order_by(WeddingEvent.event_date.desc(), WeddingEvent.start_time.asc()).all()

    # ✅ 관리자일 경우 중복 예식 묶기
    if device_code == "D-ADMIN":
        merged = {}
        for e in events:
            key = (e.hall_name, e.event_date, e.start_time, e.groom_name, e.bride_name)
            if key not in merged:
                merged[key] = e
            else:
                # 신랑/신부 조합이 이미 존재하면 생략 (중복 제거 효과)
                continue
        events = list(merged.values())

    return events

@app.delete("/wedding/event/{event_id}")
def delete_wedding_event(
    event_id: int,
    claims=Depends(require_auth),
    s: Session = Depends(db)
):
    tenant_code = claims["tenant_code"]
    device_code = claims.get("device_code")

    # ✅ 관리자 전용 보호
    if device_code != "D-ADMIN":
        raise HTTPException(403, "Access denied: not admin device")

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

    # ✅ 관련 통계 데이터(식권 발급 내역 포함) 모두 삭제
    s.query(TicketStat).filter(TicketStat.event_id == event_id).delete()

    # ✅ 예식 자체 삭제
    s.delete(event)
    s.commit()

    return {"ok": True, "deleted_id": event_id}


# ✅ 식권 발급 기록 및 누적 조회 -----------------------------

@app.post("/wedding/ticket/issue")
def issue_ticket(data: dict, s: Session = Depends(db), claims=Depends(require_auth)):
    tenant_code = claims["tenant_code"]
    device_code = claims.get("device_code")
    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    event_id = data.get("event_id")  # ✅ event_id 기준으로 분리
    event_title = data.get("event_title")
    hall_name = data.get("hall_name")
    ttype = data.get("type")
    count = int(data.get("count", 0))

    if not event_id:
        raise HTTPException(400, "event_id is required")

    # ✅ event_id 기준으로 TicketStat을 찾음 (중복 예식 분리)
    stat = (
        s.query(TicketStat)
        .filter(TicketStat.tenant_id == tenant.id)
        .filter(TicketStat.event_id == event_id)  # ✅ 추가
        .filter(TicketStat.device_code == device_code)
        .first()
    )

    # ✅ 없으면 새로 생성
    if not stat:
        stat = TicketStat(
            tenant_id=tenant.id,
            event_id=event_id,  # ✅ 저장
            device_code=device_code,
            hall_name=hall_name,
            event_title=event_title,
            adult_count=0,
            child_count=0,
        )
        s.add(stat)

    # ✅ 발급 수량 처리
    if ttype == "성인":
        stat.adult_count += count
    elif ttype == "어린이":
        stat.child_count += count
    else:
        raise HTTPException(400, f"Unknown ticket type: {ttype}")

    s.commit()
    s.refresh(stat)

    # ✅ 해당 예식 통계 갱신
    update_stats_for_event(s, event_id)

    return {
        "ok": True,
        "event_id": event_id,
        "adult_count": stat.adult_count,
        "child_count": stat.child_count,
    }


@app.get("/wedding/ticket/event_summary/{event_id}")
def get_event_summary(event_id: int, s: Session = Depends(db), claims=Depends(require_auth)):
    event = s.query(WeddingEvent).filter(WeddingEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    groom_stats = (
        s.query(TicketStat)
        .filter_by(event_id=event_id)
        .filter(WeddingEvent.owner_type == "groom")
        .all()
    )
    bride_stats = (
        s.query(TicketStat)
        .filter_by(event_id=event_id)
        .filter(WeddingEvent.owner_type == "bride")
        .all()
    )

    return {
        "event": {
            "title": event.title,
            "hall_name": event.hall_name,
            "date": event.event_date,
        },
        "groom": {
            "adult": sum(s_.adult_count for s_ in groom_stats),
            "child": sum(s_.child_count for s_ in groom_stats),
        },
        "bride": {
            "adult": sum(s_.adult_count for s_ in bride_stats),
            "child": sum(s_.child_count for s_ in bride_stats),
        },
    }




def update_stats_for_event(s: Session, event_id: int):
    """예식별 통계 자동 집계"""
    event = s.query(WeddingEvent).filter(WeddingEvent.id == event_id).first()
    if not event:
        return

    tenant = s.query(Tenant).filter(Tenant.id == event.tenant_id).first()
    if not tenant:
        return

    # ✅ 단가 조회
    price = s.query(TicketPrice).filter(TicketPrice.tenant_id == tenant.id).first()
    adult_price = price.adult_price if price else 0
    child_price = price.child_price if price else 0

    # ✅ 신랑/신부 구분은 WeddingEvent 기준으로 join 해서 조회
    groom_records = (
        s.query(TicketStat)
        .join(WeddingEvent, WeddingEvent.id == TicketStat.event_id)
        .filter(TicketStat.tenant_id == tenant.id)
        .filter(WeddingEvent.id == event_id)
        .filter(WeddingEvent.owner_type == "groom")
        .all()
    )
    bride_records = (
        s.query(TicketStat)
        .join(WeddingEvent, WeddingEvent.id == TicketStat.event_id)
        .filter(TicketStat.tenant_id == tenant.id)
        .filter(WeddingEvent.id == event_id)
        .filter(WeddingEvent.owner_type == "bride")
        .all()
    )

    def base():
        return {
            "adult": 0,
            "child": 0,
            "restaurant_adult": 0,
            "restaurant_child": 0,
            "gift_adult": 0,
            "gift_child": 0,
        }

    groom_data = base()
    bride_data = base()

    def group_by_device(device_code):
        if device_code.startswith("D-A"):  # 부조석
            return "booth"
        elif device_code.startswith("D-R"):  # 식당
            return "restaurant"
        elif device_code.startswith("D-G"):  # 답례품
            return "gift"
        return "unknown"

    # ✅ 신랑
    for r in groom_records:
        category = group_by_device(r.device_code)
        if category == "booth":
            groom_data["adult"] += r.adult_count
            groom_data["child"] += r.child_count
        elif category == "restaurant":
            groom_data["restaurant_adult"] += r.adult_count
            groom_data["restaurant_child"] += r.child_count
        elif category == "gift":
            groom_data["gift_adult"] += r.adult_count
            groom_data["gift_child"] += r.child_count

    # ✅ 신부
    for r in bride_records:
        category = group_by_device(r.device_code)
        if category == "booth":
            bride_data["adult"] += r.adult_count
            bride_data["child"] += r.child_count
        elif category == "restaurant":
            bride_data["restaurant_adult"] += r.adult_count
            bride_data["restaurant_child"] += r.child_count
        elif category == "gift":
            bride_data["gift_adult"] += r.adult_count
            bride_data["gift_child"] += r.child_count

    def compute_unused(d):
        total_adult = d["adult"]
        total_child = d["child"]
        used_adult = d["restaurant_adult"] + d["gift_adult"]
        used_child = d["restaurant_child"] + d["gift_child"]
        return {
            "unused_adult": max(total_adult - used_adult, 0),
            "unused_child": max(total_child - used_child, 0),
            "unused_total": max(
                (total_adult + total_child) - (used_adult + used_child), 0
            ),
        }

    groom_unused = compute_unused(groom_data)
    bride_unused = compute_unused(bride_data)

    groom_price = (groom_data["adult"] * adult_price) + (groom_data["child"] * child_price)
    bride_price = (bride_data["adult"] * adult_price) + (bride_data["child"] * child_price)

    s.commit()





@app.get("/wedding/ticket/admin_summary")
def get_admin_summary(s: Session = Depends(db), claims=Depends(require_auth)):
    tenant_code = claims["tenant_code"]
    device_code = claims.get("device_code")

    if device_code != "D-ADMIN":
        raise HTTPException(403, "Access denied: not admin device")

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    # ✅ 항상 최신 가격 불러오기
    price = s.query(TicketPrice).filter(TicketPrice.tenant_id == tenant.id).first()
    adult_price = price.adult_price if price else 0
    child_price = price.child_price if price else 0

    # ✅ TicketStat + WeddingEvent JOIN
    stats = (
        s.query(TicketStat, WeddingEvent)
        .join(WeddingEvent, WeddingEvent.id == TicketStat.event_id)
        .filter(TicketStat.tenant_id == tenant.id)
        .all()
    )

    # ✅ 예식별 합산 구조 (신랑/신부 통합)
    summary = {}
    for st, ev in stats:
        key = (ev.hall_name, ev.event_date, ev.start_time, ev.title)
        if key not in summary:
            summary[key] = {
                "hall": ev.hall_name,
                "title": ev.title,
                "date": ev.event_date,
                "time": ev.start_time,
                "groom_name": ev.groom_name,
                "bride_name": ev.bride_name,
                "groom_adult": 0, "groom_child": 0,
                "bride_adult": 0, "bride_child": 0,
                "adult_price": adult_price,  # ✅ 가격도 표시
                "child_price": child_price,
            }

        if ev.owner_type == "groom":
            summary[key]["groom_adult"] += st.adult_count
            summary[key]["groom_child"] += st.child_count
        elif ev.owner_type == "bride":
            summary[key]["bride_adult"] += st.adult_count
            summary[key]["bride_child"] += st.child_count

    # ✅ 금액 계산 포함
    result = []
    for v in summary.values():
        groom_total = (v["groom_adult"] * adult_price) + (v["groom_child"] * child_price)
        bride_total = (v["bride_adult"] * adult_price) + (v["bride_child"] * child_price)

        v["total_adult"] = v["groom_adult"] + v["bride_adult"]
        v["total_child"] = v["groom_child"] + v["bride_child"]
        v["total_tickets"] = v["total_adult"] + v["total_child"]  # ✅ 총 식권 수 계산 추가
        v["groom_total"] = groom_total
        v["bride_total"] = bride_total
        v["total_sum"] = groom_total + bride_total

        result.append(v)

    return result




@app.get("/wedding/ticket/stats")
def get_ticket_stats(s: Session = Depends(db), claims=Depends(require_auth)):
    tenant_code = claims["tenant_code"]
    device_code = claims.get("device_code")  # ✅ 추가

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    # ✅ D-ADMIN(관리자)인 경우 전체 합계 반환
    if device_code == "D-ADMIN":
        stats = s.query(TicketStat).filter(TicketStat.tenant_id == tenant.id).all()
        if not stats:
            return {"adult_count": 0, "child_count": 0, "adult_total": 0, "child_total": 0, "total_sum": 0}

        # 가격 불러오기
        price = s.query(TicketPrice).filter(TicketPrice.tenant_id == tenant.id).first()
        adult_price = price.adult_price if price else 0
        child_price = price.child_price if price else 0

        # ✅ 전체 디바이스 합산
        adult_sum = sum(s.adult_count for s in stats)
        child_sum = sum(s.child_count for s in stats)
        adult_total = adult_sum * adult_price
        child_total = child_sum * child_price
        total_sum = adult_total + child_total

        return {
            "adult_count": adult_sum,
            "child_count": child_sum,
            "adult_total": adult_total,
            "child_total": child_total,
            "total_sum": total_sum
        }

    # ✅ 일반 디바이스는 자기 데이터만
    stat = (
        s.query(TicketStat)
        .filter(TicketStat.tenant_id == tenant.id)
        .filter(TicketStat.device_code == device_code)  # ✅ 디바이스별 분리
        .order_by(TicketStat.id.desc())
        .first()
    )
    if not stat:
        return {
            "adult_count": 0,
            "child_count": 0,
            "adult_total": 0,
            "child_total": 0,
            "total_sum": 0
        }

    price = s.query(TicketPrice).filter(TicketPrice.tenant_id == tenant.id).first()
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

@app.post("/wedding/ticket/scan")
def scan_ticket(data: dict, db: Session = Depends(db), claims=Depends(require_auth)):
    """
    ✅ QR 스캔 처리 (식당 / 답례품 디바이스 공용)
    data = {
        "event_id": 18,
        "device_code": "D-R1",  # 예: 식당 / 답례품 / 기타
        "type": "성인" or "어린이"
    }
    """
    event_id = data.get("event_id")
    device_code = data.get("device_code")
    ttype = data.get("type")
    count = int(data.get("count", 1))

    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(404, "event not found")

    tenant = db.query(Tenant).filter(Tenant.id == event.tenant_id).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    stat = (
        db.query(TicketStat)
        .filter(TicketStat.tenant_id == tenant.id)
        .filter(TicketStat.event_title == event.title)
        .filter(TicketStat.hall_name == event.hall_name)
        .filter(TicketStat.device_code == device_code)
        .first()
    )

    if not stat:
        stat = TicketStat(
            tenant_id=tenant.id,
            device_code=device_code,
            hall_name=event.hall_name,
            event_title=event.title,
            adult_count=0,
            child_count=0
        )
        db.add(stat)

    # ✅ 식당/답례품 기기면 발급된 식권을 사용한 것으로 처리
    if device_code.startswith("D-R") or device_code.startswith("D-G"):
        if ttype == "성인":
            stat.adult_count += count
        else:
            stat.child_count += count

    db.commit()
    db.refresh(stat)

    # ✅ 미사용 갱신 포함 자동 집계
    update_stats_for_event(db, event_id)

    return {"ok": True, "device_code": device_code, "updated": True}


@router.get("/event_summary/{event_id}")
def get_event_summary(event_id: int, db: Session = Depends(db)):
    # ✅ 예식 존재 여부 확인
    event = db.query(WeddingEvent).filter(WeddingEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # ✅ 해당 예식의 통계 데이터 가져오기
    groom = db.query(TicketStat).filter(
        TicketStat.event_id == event_id, TicketStat.side == "groom"
    ).first()
    bride = db.query(TicketStat).filter(
        TicketStat.event_id == event_id, TicketStat.side == "bride"
    ).first()

    # ✅ 데이터 기본값 처리
    def safe(d):
        return d if d else {
            "adult": 0,
            "child": 0,
            "total_tickets": 0,
            "price": 0,
            "restaurant_adult": 0,
            "restaurant_child": 0,
            "gift_adult": 0,
            "gift_child": 0,
            "unused_adult": 0,
            "unused_child": 0,
            "unused_total": 0,
            "grand_total": 0,
        }

    groom_data = safe(groom.__dict__ if groom else None)
    bride_data = safe(bride.__dict__ if bride else None)

    totals = {
        "grand_total": groom_data["grand_total"] + bride_data["grand_total"],
    }

    return {"groom": groom_data, "bride": bride_data, "totals": totals}






# ─────────────────────────────────────────────
@app.get("/health")
def health():
    """Render keep-alive 엔드포인트"""
    return {
        "status": "ok",
        "server_time": datetime.now().isoformat()
    }
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8080)
