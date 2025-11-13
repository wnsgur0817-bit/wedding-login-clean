# -*- coding: utf-8 -*-
# manage_generate.py
# 관리자(0/0) + 기본 테스트 테넌트(T-0000) 생성

from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from models import Base, User, Tenant
from auth import hash_pw
import os
from seed_data import seed_if_empty

DB = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://postgres:%25121q2w3e4R@/wedding_db?host=/cloudsql/groovy-plating-477407-p3:asia-northeast3:wedding-db"
)

engine = create_engine(DB, future=True)

ADMIN_LOGIN = "0"
ADMIN_PASSWORD = "0"


def reset_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    print("🧹 DB 초기화 완료")


def seed():
    reset_db()

    with Session(engine) as s:
        # ----------------------------------------------------
        # 관리자 전용 Tenant (고정값): T-0000
        # ----------------------------------------------------
        admin_tenant = Tenant(
            code="T-0000",
            name="MasterAdminTenant",
            pw_hash=hash_pw(ADMIN_PASSWORD),
        )
        s.add(admin_tenant)
        s.flush()

        # ----------------------------------------------------
        # 관리자 User 생성
        # ----------------------------------------------------
        admin_user = User(
            tenant_id=admin_tenant.id,
            login_id=ADMIN_LOGIN,
            pw_hash=hash_pw(ADMIN_PASSWORD),
            role="admin",
        )
        s.add(admin_user)
        s.commit()

    print("✨ 관리자 계정 생성 완료")
    print(f"   ▸ ID: {ADMIN_LOGIN}, PW: {ADMIN_PASSWORD}")
    print("   ▸ Tenant = T-0000")


if __name__ == "__main__":
    seed()