import os, time, jwt
from argon2 import PasswordHasher
ph = PasswordHasher()
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALG = "HS256"
JWT_TTL = 60*60  # 1h

def hash_pw(raw: str) -> str:
    return ph.hash(raw)

def verify_pw(raw: str, hashed: str) -> bool:
    try:
        ph.verify(hashed, raw); return True
    except Exception:
        return False

def make_access_token(sub: str, tenant_code: str, role: str="staff") -> str:
    now = int(time.time())
    payload = {"sub": sub, "tenant_id": tenant_code, "role": role, "iat": now, "exp": now+JWT_TTL}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
