# schemas.py
from pydantic import BaseModel
from typing import Optional
from datetime import date


# ======================================
# 로그인
# ======================================
class LoginReq(BaseModel):
    login_id: str
    password: str


class LoginResp(BaseModel):
    access_token: str
    claims: dict


# ======================================
# 비밀번호 변경
# (관리자 or 테넌트 관리자 기능이 필요해지면 사용)
# ======================================
class ChangePwReq(BaseModel):
    current_password: str
    new_password: str


# ======================================
# 회원가입 요청 (사용자 → 승인 대기)
# ======================================
class RegisterReq(BaseModel):
    login_id: str
    password: str


# ======================================
# 관리자 승인 (pending → approved)
# ======================================
class ApproveReq(BaseModel):
    request_id: int   # requested_users.id
    hall_name: Optional[str] = None  # 필요하면 예식장명 추가 가능


# ======================================
# 디바이스 생성 응답
# ======================================
class DeviceCreateResp(BaseModel):
    device_code: str        # 예: D-A01
    activation_code: str


# ======================================
# 예식 생성
# ======================================
class WeddingEventIn(BaseModel):
    start_time: str
    groom_name: str
    bride_name: str
    title: str
    hall_name: Optional[str] = None
    child_min_age: Optional[int] = None
    child_max_age: Optional[int] = None
    owner_type: Optional[str] = None  # "groom" / "bride"


# ======================================
# 예식 조회 (서버 응답용)
# ======================================
class WeddingEventOut(WeddingEventIn):
    id: int
    tenant_id: int
