from pydantic import BaseModel

class LoginReq(BaseModel):
    login_id: str
    password: str

class LoginResp(BaseModel):
    access_token: str
    claims: dict

class ChangePwReq(BaseModel):
    login_id: str
    current_password: str
    new_password: str

class DeviceActivateReq(BaseModel):
    activation_code: str
