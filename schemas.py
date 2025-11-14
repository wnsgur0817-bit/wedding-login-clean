# schemas.py
from pydantic import BaseModel
from typing import Optional
from datetime import date, datetime

# ======================================
# 로그인
# ======================================
class LoginReq(BaseModel):
    login_id: str
    password: str
    device_code: Optional[str] = None   # 디바이스 선택 후 재로그인 시 사용


class LoginResp(BaseModel):
    access_token: str
    claims: dict


# ======================================
# 비밀번호 변경
# ======================================
class ChangePwReq(BaseModel):
    current_password: str
    new_password: str


# ======================================
# 회원가입 요청
# ======================================
class RegisterReq(BaseModel):
    login_id: str
    password: str


# ======================================
# 관리자 승인 요청
# ======================================
class ApproveReq(BaseModel):
    request_id: int   # requested_users.id


# ======================================
# 디바이스 정보
# ======================================
class DeviceAvailability(BaseModel):
    code: str
    available: bool = True


class DeviceCreateResp(BaseModel):
    device_code: str
    activation_code: str


class ClaimReq(BaseModel):
    tenant_id: str
    device_code: str
    session_id: str


class ReleaseReq(BaseModel):
    tenant_id: str
    device_code: str
    session_id: str


# ======================================
# 예식 생성 (입력)
# ======================================
class WeddingEventIn(BaseModel):
    device_code: str
    owner_type: str   # "groom" / "bride"
    hall_name: str
    event_date: date
    start_time: str
    title: str
    groom_name: str
    bride_name: str
    child_min_age: int = 0
    child_max_age: int = 0


# ======================================
# 예식 조회 (출력)
# ======================================
class WeddingEventOut(BaseModel):
    id: int
    tenant_id: int
    device_code: str
    owner_type: str
    hall_name: str
    event_date: date
    start_time: str
    title: str
    groom_name: str
    bride_name: str
    child_min_age: int
    child_max_age: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True
