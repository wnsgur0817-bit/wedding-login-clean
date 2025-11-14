# app.py#
import os, re
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Depends, Header,APIRouter, Body
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import create_engine, select, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models import Base, Tenant, User, Device, DeviceClaim,WeddingEvent, TicketStat, TicketPrice,RequestedUser
from schemas import (
    LoginReq, LoginResp, ChangePwReq,
    DeviceAvailability, ClaimReq, ReleaseReq,WeddingEventIn, WeddingEventOut
)
from auth import verify_pw, make_access_token, hash_pw, verify_access_token
import traceback

# ─────────────────────────────────────────────
# DB
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////tmp/app.db")
#DATABASE_URL = os.getenv(
#    "DATABASE_URL",
#    "postgresql+psycopg2://postgres:%25121q2w3e4R@/wedding_db?host=/cloudsql/groovy-plating-477407-p3:asia-northeast3:wedding-db")
engine = create_engine(DATABASE_URL, future=True)
Base.metadata.create_all(engine)
router = APIRouter(prefix="/wedding/ticket", tags=["wedding-ticket"])
KST = timezone(timedelta(hours=9))
today_kst = datetime.now(KST).date()

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



# ===========================================================
# 인증 공통 처리
# ===========================================================
def require_auth(
    authorization: str = Header(None),
    x_device_code: str = Header(None),
    s: Session = Depends(db)
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")

    token = authorization.split(" ", 1)[1]
    payload = verify_access_token(token, s)

    device_code = x_device_code or payload.get("device_code", "D-ADMIN")

    return {
        **payload,
        "device_code": device_code,
    }

# ===========================================================
# 로그인
# ===========================================================
def resolve_tenant_user_by_login_id(s: Session, login_id: str):
    # 1) 정확한 login_id 검색
    rows = (
        s.execute(
            select(User, Tenant)
            .join(Tenant, Tenant.id == User.tenant_id)
            .where(User.login_id == login_id)
        )
        .all()
    )

    if len(rows) == 1:
        user, tenant = rows[0]
        return tenant, user

    if len(rows) > 1:
        raise HTTPException(409, "duplicate login id across tenants")

    raise HTTPException(401, "invalid credentials")

@app.post("/auth/approve_user")
def approve_user(data: dict, s: Session = Depends(db), claims=Depends(require_auth)):
    # 최고관리자 권한 검사
    if claims["tenant_id"] != "T-0000" or claims["role"] != "admin":
        raise HTTPException(403, "not admin")

    login_id = data.get("login_id")
    if not login_id:
        raise HTTPException(400, "login_id required")

    # 대기 사용자 조회
    req_user = (
        s.query(RequestedUser)
        .filter(RequestedUser.login_id == login_id)
        .first()
    )
    if not req_user:
        raise HTTPException(404, "request not found")

    # 다음 테넌트 코드 생성
    last = (
        s.query(Tenant)
        .filter(Tenant.code != "T-0000")
        .order_by(Tenant.id.desc())
        .first()
    )

    last_num = int(last.code.split("-")[1]) if last else 0
    new_code = f"T-{last_num + 1:04d}"

    # 새 테넌트 생성
    tenant = Tenant(
        code=new_code,
        name=f"WeddingHall {new_code}",
        pw_hash=req_user.pw_hash,
    )
    s.add(tenant)
    s.flush()

    # staff 사용자 생성
    user = User(
        tenant_id=tenant.id,
        login_id=req_user.login_id,
        pw_hash=req_user.pw_hash,
        role="staff"
    )
    s.add(user)

    # ⭐ D-ADMIN만 자동 생성
    admin_device = Device(
        tenant_id=tenant.id,
        device_code="D-ADMIN",
        activation_code=os.urandom(16).hex(),
        active=0,
    )
    s.add(admin_device)

    # 대기목록에서 삭제
    s.delete(req_user)

    s.commit()

    return {"ok": True, "tenant_code": new_code, "login_id": login_id}

@app.post("/auth/login", response_model=LoginResp)
def login(body: LoginReq, s: Session = Depends(db)):
    try:
        tenant, user = resolve_tenant_user_by_login_id(s, body.login_id)

        # tenant 비밀번호 비교
        if not verify_pw(body.password, tenant.pw_hash):
            raise HTTPException(401, "invalid password")

        tv = tenant.token_version if hasattr(tenant, "token_version") else 1

        token = make_access_token(
            sub=str(user.id),
            tenant_code=tenant.code,
            role=user.role,
            token_version=tv,
            device_code="D-ADMIN",  # 로그인 시 기본값
        )

        return {
            "access_token": token,
            "claims": {
                "tenant_id": tenant.code,
                "role": user.role,
                "device_code": "D-ADMIN",
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"login failed: {e}")


# ===========================================================
# 회원가입 요청 (사용자)
# ===========================================================
@app.post("/auth/register")
def register_user(body: dict, s: Session = Depends(db)):
    login_id = body.get("login_id")
    password = body.get("password")

    if not login_id or not password:
        raise HTTPException(400, "login_id and password required")

    exists = s.scalars(
        select(RequestedUser).where(RequestedUser.login_id == login_id)
    ).first()

    if exists:
        raise HTTPException(409, "ID already requested")

    user = RequestedUser(
        login_id=login_id,
        pw_hash=hash_pw(password),
    )

    s.add(user)
    s.commit()

    return {"ok": True, "message": "registration pending"}





# ===========================================================
# 디바이스 리스트(디바이스 선택 화면)
# ===========================================================
@app.get("/devices/list")
def list_devices_for_flutter(tenant: str, claims=Depends(require_auth), s: Session = Depends(db)):
    if claims["tenant_id"] != tenant:
        raise HTTPException(403, "not allowed")

    tenant_obj = s.scalars(select(Tenant).where(Tenant.code == tenant)).first()
    if not tenant_obj:
        raise HTTPException(404, "tenant not found")

    devices = s.scalars(
        select(Device).where(Device.tenant_id == tenant_obj.id)
    ).all()

    return [{"code": d.device_code} for d in devices]


# ===========================================================
# 디바이스 생성 (관리자 or 테넌트 직원)
# ===========================================================
@app.post("/devices/create_next")
def create_next_device(data: dict, claims=Depends(require_auth), s: Session = Depends(db)):
    tenant_code = data.get("tenant_code")
    if claims["tenant_id"] != tenant_code:
        raise HTTPException(403, "not allowed")

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    existing = (
        s.query(Device)
        .filter(Device.tenant_id == tenant.id)
        .filter(Device.device_code.like("D-A%"))
        .all()
    )

    nums = []
    for dev in existing:
        try:
            nums.append(int(dev.device_code[4:]))
        except:
            pass

    next_num = max(nums, default=0) + 1
    new_code = f"D-A{next_num:02d}"

    new_dev = Device(
        tenant_id=tenant.id,
        device_code=new_code,
        activation_code=os.urandom(16).hex(),
        active=0,
    )
    s.add(new_dev)
    s.commit()

    return {"ok": True, "device_code": new_code}

# ===========================================================
# 디바이스 점유/해제/하트비트
# ===========================================================
@app.post("/devices/claim")
def claim_device(body: ClaimReq, s: Session = Depends(db)):
    tenant = s.scalars(
        select(Tenant).where(Tenant.code == body.tenant_id)
    ).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    claim = DeviceClaim(
        tenant_id=tenant.id,
        device_code=body.device_code,
        session_id=body.session_id,
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
    tenant = s.scalars(
        select(Tenant).where(Tenant.code == body.tenant_id)
    ).first()

    deleted = s.query(DeviceClaim).filter(
        DeviceClaim.tenant_id == tenant.id,
        DeviceClaim.device_code == body.device_code,
        DeviceClaim.session_id == body.session_id,
    ).delete(synchronize_session=False)

    s.commit()
    return {"ok": bool(deleted)}


@app.post("/devices/heartbeat")
def heartbeat(body: ClaimReq, s: Session = Depends(db)):
    return {"ok": True}











@app.post("/wedding/event", response_model=WeddingEventOut)
def create_wedding_event(data: WeddingEventIn, claims=Depends(require_auth), s: Session = Depends(db)):
    tenant_code = claims["tenant_code"]
    device_code = claims.get("device_code")

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")
    if not data.hall_name:
        raise HTTPException(400, "hall_name required")

    event = WeddingEvent(
        tenant_id=tenant.id,
        device_code=device_code,
        owner_type=data.owner_type,
        hall_name=(data.hall_name or "").strip(),
        event_date=datetime.now(KST).date(),
        start_time=(data.start_time or "").strip(),     # ✅
        title=(data.title or "").strip(),               # ✅ (선택)
        groom_name=(data.groom_name or "").strip(),     # ✅
        bride_name=(data.bride_name or "").strip(),     # ✅
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

    # 기본: 같은 테넌트의 모든 event 조회
    q = s.query(WeddingEvent).filter(WeddingEvent.tenant_id == tenant.id)

    # ✔ 부조석이면 자기 디바이스의 데이터만
    if device_code and device_code != "D-ADMIN":
        q = q.filter(WeddingEvent.device_code == device_code)

    events = q.order_by(
        WeddingEvent.event_date.desc(),
        WeddingEvent.start_time.asc(),
        WeddingEvent.hall_name.asc()
    ).all()

    # ✔ 관리자 전용: 중복 예식 묶기(5개 기준)
    if device_code == "D-ADMIN":
        dedup = {}

        for e in events:
            # 정규화(공백 제거, 소문자 통일)
            key = (
                (e.hall_name or "").strip().lower(),
                str(e.event_date),                # YYYY-MM-DD 로 고정
                (e.start_time or "").strip(),     # 시간 문자열
                (e.groom_name or "").strip().lower(),
                (e.bride_name or "").strip().lower(),
            )

            # 09:30 포맷 보정
            time_str = key[2]
            if len(time_str) == 4 and time_str[1] == ":":
                time_str = "0" + time_str
            # 보정된 값으로 key 재생성
            key = (
                key[0], key[1], time_str, key[3], key[4]
            )

            # 첫 번째 것만 저장
            if key not in dedup:
                dedup[key] = e

        # dedup 결과를 events 로 교체
        events = list(dedup.values())

    return events


        ###관라자 페이지 선택삭제
@app.post("/wedding/event/bulk_delete")
def delete_multiple_wedding_events(
    body: dict = Body(...),
    claims=Depends(require_auth),
    s: Session = Depends(db)
):
    try:
        event_ids = body.get("event_ids", [])
        if not isinstance(event_ids, list):
            raise HTTPException(400, "Invalid request body")

        tenant_code = claims["tenant_code"]
        tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
        if not tenant:
            raise HTTPException(404, "tenant not found")

        deleted_count = 0
        for eid in event_ids:
            event = (
                s.query(WeddingEvent)
                .filter(WeddingEvent.tenant_id == tenant.id, WeddingEvent.id == eid)
                .first()
            )
            if not event:
                continue

            s.query(TicketStat).filter(TicketStat.event_id == eid).delete()
            s.delete(event)
            deleted_count += 1

        s.commit()

        # ✅ 최신 데이터 포함 응답
        remaining = (
            s.query(WeddingEvent)
            .filter(WeddingEvent.tenant_id == tenant.id)
            .order_by(WeddingEvent.event_date.desc())
            .all()
        )

        return {
            "ok": True,
            "deleted_count": deleted_count,
            "events": [
                {
                    "id": e.id,
                    "hall_name": e.hall_name,
                    "event_date": e.event_date,
                    "start_time": e.start_time,
                    "title": e.title,
                    "groom_name": e.groom_name,
                    "bride_name": e.bride_name,
                }
                for e in remaining
            ],
        }

    except Exception as e:
        s.rollback()
        raise HTTPException(status_code=500, detail=f"Delete failed: {str(e)}")





    ##관리자 페이지 통계 “예식별 한 줄 요약 리스트”
@app.get("/wedding/ticket/admin_summary")
def get_admin_summary(s: Session = Depends(db), claims=Depends(require_auth)):
    tenant_code = claims["tenant_code"]

    # ✅ 테넌트 확인
    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(404, "tenant not found")

    # ✅ 식권 단가
    price = s.query(TicketPrice).filter(TicketPrice.tenant_id == tenant.id).first()
    adult_price = price.adult_price if price else 0
    child_price = price.child_price if price else 0

    # ✅ 테넌트 내의 모든 예식 + 통계 JOIN
    stats = (
        s.query(TicketStat, WeddingEvent)
        .join(WeddingEvent, WeddingEvent.id == TicketStat.event_id)
        .filter(TicketStat.tenant_id == tenant.id)
        .all()
    )

    # ✅ 묶임 기준: 홀 + 날짜 + 시간 + 신랑 + 신부
    summary = {}
    for st, ev in stats:
        key = (
            (ev.hall_name or "").strip().lower(),
            ev.event_date,
            (ev.start_time or "").strip(),
            (ev.groom_name or "").strip().lower(),
            (ev.bride_name or "").strip().lower(),
        )

        if key not in summary:
            summary[key] = {
                "hall": ev.hall_name,
                "title": ev.title,
                "date": ev.event_date,
                "time": ev.start_time,
                "groom_name": ev.groom_name,
                "bride_name": ev.bride_name,
                "groom_adult": 0,
                "groom_child": 0,
                "bride_adult": 0,
                "bride_child": 0,
                "adult_price": adult_price,
                "child_price": child_price,
                "devices": set(),  # 어떤 부조석에서 왔는지도 추적 가능
            }

        # ✅ 신랑/신부별 합산
        if ev.owner_type == "groom":
            summary[key]["groom_adult"] += st.adult_count
            summary[key]["groom_child"] += st.child_count
        elif ev.owner_type == "bride":
            summary[key]["bride_adult"] += st.adult_count
            summary[key]["bride_child"] += st.child_count

        summary[key]["devices"].add(ev.device_code)

    # ✅ 금액 및 합계 계산
    result = []
    for v in summary.values():
        groom_total = (v["groom_adult"] * v["adult_price"]) + (v["groom_child"] * v["child_price"])
        bride_total = (v["bride_adult"] * v["adult_price"]) + (v["bride_child"] * v["child_price"])

        v["total_adult"] = v["groom_adult"] + v["bride_adult"]
        v["total_child"] = v["groom_child"] + v["bride_child"]
        v["total_tickets"] = v["total_adult"] + v["total_child"]
        v["groom_total"] = groom_total
        v["bride_total"] = bride_total
        v["total_sum"] = groom_total + bride_total

        # ✅ 디바이스 목록을 보기 좋게 표시
        v["devices"] = ", ".join(sorted(v["devices"]))
        result.append(v)

    return result







        ##화면에 최신 누적값을 보여주는 조회용 API
@app.get("/wedding/ticket/event_summary/{event_id}")
def get_event_summary(event_id: int, s: Session = Depends(db), claims=Depends(require_auth)):
    tenant_code = claims["tenant_code"]
    device_code = claims.get("device_code")

    tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="tenant not found")

    # ✅ 기준 예식
    base_event = s.query(WeddingEvent).filter(WeddingEvent.id == event_id).first()
    if not base_event:
        raise HTTPException(status_code=404, detail="Event not found")

    # ✅ 관리자면 같은 조건으로 묶기
    if device_code == "D-ADMIN":
        related_events = (
            s.query(WeddingEvent)
            .filter(WeddingEvent.tenant_id == tenant.id)
            .filter(WeddingEvent.hall_name == base_event.hall_name)
            .filter(WeddingEvent.event_date == base_event.event_date)
            .filter(WeddingEvent.start_time == base_event.start_time)
            .filter(WeddingEvent.groom_name == base_event.groom_name)
            .filter(WeddingEvent.bride_name == base_event.bride_name)
            .all()
        )
    else:
        # ✅ 부조석이면 자기 디바이스 예식만
        related_events = (
            s.query(WeddingEvent)
            .filter(WeddingEvent.tenant_id == tenant.id)
            .filter(WeddingEvent.device_code == device_code)
            .filter(WeddingEvent.hall_name == base_event.hall_name)
            .filter(WeddingEvent.event_date == base_event.event_date)
            .filter(WeddingEvent.start_time == base_event.start_time)
            .filter(WeddingEvent.groom_name == base_event.groom_name)
            .filter(WeddingEvent.bride_name == base_event.bride_name)
            .all()
        )

    event_ids = [e.id for e in related_events]

    # ✅ 신랑/신부별 누적용 딕셔너리
    def init_stat():
        return {
            "adult": 0,
            "child": 0,
            "restaurant_adult": 0,
            "restaurant_child": 0,
            "gift_adult": 0,
            "gift_child": 0,
            "unused_adult": 0,
            "unused_child": 0,
            "unused_total": 0,
            "grand_total": 0,
        }

    groom_data = init_stat()
    bride_data = init_stat()

    # ✅ TicketStat + Device join (side 확인)
    records = (
        s.query(TicketStat, Device)
        .join(Device, Device.device_code == TicketStat.device_code)
        .filter(TicketStat.event_id.in_(event_ids))
        .all()
    )

    for stat, device in records:
        side = device.side or "unknown"
        target = groom_data if side == "groom" else bride_data if side == "bride" else None
        if not target:
            continue

        target["adult"] += stat.adult_count
        target["child"] += stat.child_count
        target["restaurant_adult"] += getattr(stat, "restaurant_adult", 0)
        target["restaurant_child"] += getattr(stat, "restaurant_child", 0)
        target["gift_adult"] += getattr(stat, "gift_adult", 0)
        target["gift_child"] += getattr(stat, "gift_child", 0)
        target["unused_adult"] += getattr(stat, "unused_adult", 0)
        target["unused_child"] += getattr(stat, "unused_child", 0)
        target["unused_total"] += getattr(stat, "unused_total", 0)
        target["grand_total"] += getattr(stat, "grand_total", 0)

    # ✅ 전체 총합 계산
    totals = {
        "grand_total": groom_data["grand_total"] + bride_data["grand_total"],
    }

    # ✅ 응답
    return {
        "event": {
            "title": base_event.title,
            "hall_name": base_event.hall_name,
            "date": base_event.event_date,
            "time": base_event.start_time,
            "groom_name": base_event.groom_name,
            "bride_name": base_event.bride_name,
        },
        "groom": groom_data,
        "bride": bride_data,
        "totals": totals,
        "related_device_count": len(set(
            s.query(WeddingEvent.device_code)
            .filter(WeddingEvent.id.in_(event_ids))
            .distinct()
            .all()
        )),
    }




# ✅ 식권 발급 기록 및 누적 조회 “관리자 집계 자동 반영 로직”

@app.post("/wedding/ticket/issue")
def issue_ticket(data: dict, s: Session = Depends(db), claims=Depends(require_auth)):
    try:
        tenant_code = claims["tenant_code"]
        device_code = claims.get("device_code")
        tenant = s.scalars(select(Tenant).where(Tenant.code == tenant_code)).first()
        if not tenant:
            raise HTTPException(404, "tenant not found")

        event_id = data.get("event_id")
        event_title = data.get("event_title")
        hall_name = data.get("hall_name")
        ttype = data.get("type")
        count = int(data.get("count", 0))

        if not event_id:
            raise HTTPException(400, "event_id is required")

        # ✅ TicketStat 조회
        stat = (
            s.query(TicketStat)
            .filter(TicketStat.tenant_id == tenant.id)
            .filter(TicketStat.event_id == event_id)
            .filter(TicketStat.device_code == device_code)
            .first()
        )

        if not stat:
            stat = TicketStat(
                tenant_id=tenant.id,
                event_id=event_id,
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

        s.flush()   # ← 변경사항을 DB에 즉시 반영 (commit 전이라 rollback 가능)
        update_stats_for_event(s, event_id)
        s.commit()  # ← 마지막에 한 번만 확정 저장

        return {
            "ok": True,
            "event_id": event_id,
            "adult_count": stat.adult_count,
            "child_count": stat.child_count,
        }

    except Exception as e:
        print("[ERROR] issue_ticket failed")
        traceback.print_exc()
        raise HTTPException(500, f"Server error: {e}")







    ##관리자 통계창이 항상 최신 상태로 갱신되게 만드는 핵심 로직
def update_stats_for_event(s: Session, event_id: int):
    """
    예식별 통계 자동 집계
    (같은 홀 + 날짜 + 시간 + 신랑/신부 이름 기준으로 묶음, Device.side 기준으로 구분)
    """
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

    # ✅ 같은 홀 + 날짜 + 시간 + 신랑/신부 이름 기준으로 예식 그룹 전체 조회
    records = (
        s.query(TicketStat, Device, WeddingEvent)
        .join(Device, Device.device_code == TicketStat.device_code)
        .join(WeddingEvent, WeddingEvent.id == TicketStat.event_id)
        .filter(TicketStat.tenant_id == tenant.id)
        .filter(WeddingEvent.hall_name == event.hall_name)
        .filter(WeddingEvent.event_date == event.event_date)
        .filter(WeddingEvent.start_time == event.start_time)
        .filter(WeddingEvent.groom_name == event.groom_name)
        .filter(WeddingEvent.bride_name == event.bride_name)
        .all()
    )

    # ✅ 누적 변수 초기화
    groom_data = {
        "adult": 0, "child": 0,
        "restaurant_adult": 0, "restaurant_child": 0,
        "gift_adult": 0, "gift_child": 0,
    }
    bride_data = {
        "adult": 0, "child": 0,
        "restaurant_adult": 0, "restaurant_child": 0,
        "gift_adult": 0, "gift_child": 0,
    }

    # ✅ 기기 코드별 분류 함수
    def group_by_device(device_code: str):
        if device_code.startswith("D-A"):
            return "booth"
        elif device_code.startswith("D-R"):
            return "restaurant"
        elif device_code.startswith("D-G"):
            return "gift"
        return "unknown"

    # ✅ 통계 누적 계산 (Device.side 기준)
    for stat, device, ev in records:
        side = device.side or "unknown"
        category = group_by_device(stat.device_code)

        target = groom_data if side == "groom" else bride_data if side == "bride" else None
        if not target:
            continue

        if category == "booth":
            target["adult"] += stat.adult_count
            target["child"] += stat.child_count
        elif category == "restaurant":
            target["restaurant_adult"] += stat.adult_count
            target["restaurant_child"] += stat.child_count
        elif category == "gift":
            target["gift_adult"] += stat.adult_count
            target["gift_child"] += stat.child_count

    # ✅ 금액 계산
    groom_price = (groom_data["adult"] * adult_price) + (groom_data["child"] * child_price)
    bride_price = (bride_data["adult"] * adult_price) + (bride_data["child"] * child_price)

    # ✅ DB 반영 (같은 예식 그룹 중 하나에 누적 저장)
    event.groom_adult_total = groom_data["adult"]
    event.groom_child_total = groom_data["child"]
    event.bride_adult_total = bride_data["adult"]
    event.bride_child_total = bride_data["child"]
    event.groom_total_price = groom_price
    event.bride_total_price = bride_price

    s.add(event)
    #s.commit()




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











app.include_router(router)

if __name__ == "__main__":
    import uvicorn
  #  from manage_generate import seed_if_empty
   # seed_if_empty(engine)  # ✅ 초기 데이터 삽입
    uvicorn.run("app:app", host="0.0.0.0", port=8080)
