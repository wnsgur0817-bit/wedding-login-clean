# -*- coding: utf-8 -*-
# manage_generate.py
import csv, secrets
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, select, func
from models import Base, Tenant, User, Device
from auth import hash_pw

DB = "sqlite:///app.db"
engine = create_engine(DB, future=True)

# === 설정값 ===
TENANT_CODE = "T-0001"
TENANT_NAME = "WeddingHall 1"
PASSWORD = "0"
HALLS = ["A", "B", "C"]
BOOTHS_PER_HALL = 5          # 3 * 5 = 15개
ADMIN_DEVICE_CODE = "D-ADMIN"
USER_COUNT = 100             # gen001 ~ gen100
INCLUDE_TEST_T0000 = True    # 테스트 테넌트(T-0000) 포함 여부

def reset_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

def gen_activation(): return secrets.token_urlsafe(16)
def gen_device_code(h, b): return f"D-{h}{b}"

def seed():
    reset_db()
    rows = []  # seed_output.csv (device 중심 표)
    with Session(engine) as s:
        # ── (옵션) 테스트 테넌트 T-0000 생성: ID=0/PW=0, D-ADMIN + D-A1 ──
        if INCLUDE_TEST_T0000:
            t0 = Tenant(code="T-0000", name="TestWeddingHall")
            s.add(t0); s.flush()

            u0 = User(
                tenant_id=t0.id,
                login_id="0",
                pw_hash=hash_pw("0"),
                role="staff"
            )
            s.add(u0); s.flush()

            # D-ADMIN (맨 위)
            act_admin0 = gen_activation()
            s.add(Device(
                tenant_id=t0.id,
                device_code=ADMIN_DEVICE_CODE,
                activation_code=act_admin0,
                active=0
            ))
            rows.append(["T-0000", "0", "0", ADMIN_DEVICE_CODE, act_admin0])

            # D-A1 (부조석)
            act_a1_0 = gen_activation()
            s.add(Device(
                tenant_id=t0.id,
                device_code="D-A1",
                activation_code=act_a1_0,
                active=0
            ))
            rows.append(["T-0000", "0", "0", "D-A1", act_a1_0])

        # ── 실제 예식장 테넌트 생성 ────────────────────────────────────────
        t1 = Tenant(code=TENANT_CODE, name=TENANT_NAME)
        s.add(t1); s.flush()

        # 사용자 gen001 ~ gen100
        for i in range(1, USER_COUNT + 1):
            login_id = f"gen{i:03d}"
            s.add(User(
                tenant_id=t1.id,
                login_id=login_id,
                pw_hash=hash_pw(PASSWORD),
                role="staff"
            ))
        s.flush()

        # 관리자 기기 1개 (T-0001)
        act_admin1 = gen_activation()
        s.add(Device(
            tenant_id=t1.id,
            device_code=ADMIN_DEVICE_CODE,
            activation_code=act_admin1,
            active=0
        ))
        rows.append([TENANT_CODE, "gen001", PASSWORD, ADMIN_DEVICE_CODE, act_admin1])

        # 부조석 15개 (A1~5, B1~5, C1~5)
        for hall in HALLS:
            for booth in range(1, BOOTHS_PER_HALL + 1):
                dcode = gen_device_code(hall, booth)
                act = gen_activation()
                s.add(Device(
                    tenant_id=t1.id,
                    device_code=dcode,
                    activation_code=act,
                    active=0
                ))
                rows.append([TENANT_CODE, "gen001", PASSWORD, dcode, act])

        s.commit()

    # CSV 저장
    with open("seed_output.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tenant_id", "login_id", "password", "device_code", "activation_code"])
        w.writerows(rows)

    print("✅ seed_output.csv 생성 완료!")
    if INCLUDE_TEST_T0000:
        print("   └ 테스트 T-0000 포함: ID=0/PW=0, 기기 D-ADMIN + D-A1")
    print(f"   └ 예식장 코드: {TENANT_CODE}")
    print(f"   └ 생성된 계정 수: {USER_COUNT}")
    print(f"   └ 기기 수(T-0001): {1 + len(HALLS)*BOOTHS_PER_HALL} (관리자 1 + 부조석 15)")


def seed_if_empty(engine):
    """테이블이 비어있을 때만 안전하게 시드."""
    Base.metadata.create_all(engine)  # 테이블 없으면 생성
    with Session(engine) as s:
        # 이미 테넌트/유저가 있으면 아무 것도 안 함
        t_count = s.scalar(select(func.count()).select_from(Tenant))
        u_count = s.scalar(select(func.count()).select_from(User))
        if (t_count or u_count):
            return False  # 이미 데이터 있음

        # --- 테스트 테넌트 T-0000: (0/0), D-ADMIN + D-A1 ---
        t0 = Tenant(code="T-0000", name="TestWeddingHall")
        s.add(t0); s.flush()

        u0 = User(tenant_id=t0.id, login_id="0", pw_hash=hash_pw("0"), role="staff")
        s.add(u0); s.flush()

        s.add(Device(tenant_id=t0.id, device_code=ADMIN_DEVICE_CODE, activation_code=_gen_activation(), active=0))
        s.add(Device(tenant_id=t0.id, device_code="D-A1",          activation_code=_gen_activation(), active=0))

        # --- 실제 테넌트 T-0001: gen001~100, D-ADMIN + A1~C5 ---
        t1 = Tenant(code=TENANT_CODE, name=TENANT_NAME)
        s.add(t1); s.flush()

        for i in range(1, USER_COUNT + 1):
            s.add(User(tenant_id=t1.id, login_id=f"gen{i:03d}", pw_hash=hash_pw(PASSWORD), role="staff"))

        s.add(Device(tenant_id=t1.id, device_code=ADMIN_DEVICE_CODE, activation_code=_gen_activation(), active=0))
        for h in HALLS:
            for b in range(1, BOOTHS_PER_HALL + 1):
                s.add(Device(tenant_id=t1.id, device_code=_gen_device_code(h, b), activation_code=_gen_activation(), active=0))

        s.commit()
        return True



if __name__ == "__main__":
    seed()

