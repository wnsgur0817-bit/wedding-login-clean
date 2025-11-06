#schemas.py
from pydantic import BaseModel
from typing import List, Optional
from datetime import date

class LoginReq(BaseModel):
    login_id: str
    password: str
    device_code: Optional[str] = "unknown"

class LoginResp(BaseModel):
    access_token: str
    claims: dict

class ChangePwReq(BaseModel):
    login_id: str
    current_password: str
    new_password: str

class DeviceActivateReq(BaseModel):
    activation_code: str

class DeviceAvailability(BaseModel):
    code: str
    available: bool

class ClaimReq(BaseModel):
    tenant_id: str      # 예: 'T-0001'
    device_code: str    # 예: 'D-A1'
    session_id: str     # 임의 세션 식별자(앱에서 생성)

class ReleaseReq(BaseModel):
    tenant_id: str
    device_code: str
    session_id: str

class WeddingEventIn(BaseModel):
    event_date: date
    start_time: str
    groom_name: str
    bride_name: str
    title: str
    hall_name: str  # ✅ 추가
    child_min_age: int | None = None
    child_max_age: int | None = None
    owner_type: str  # "groom" 또는 "bride"

class WeddingEventOut(WeddingEventIn):
    id: int
    tenant_id: int