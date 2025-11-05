#models.py
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship,declarative_base
from sqlalchemy import String, Integer, ForeignKey, UniqueConstraint, DateTime, func,Column
from datetime import datetime, date, time

Base = declarative_base()

class Base(DeclarativeBase): pass

class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(16), unique=True, index=True)  # 예: T-0001
    name: Mapped[str] = mapped_column(String(100))
    # ───── NEW: 테넌트 단위 비밀번호 & 세션 버전 ─────
    pw_hash: Mapped[str] = mapped_column(String(255), default="")  # NEW
    pw_updated_at: Mapped[DateTime] = mapped_column(              # NEW
        DateTime, server_default=func.now(), onupdate=func.now()
    )
    token_version: Mapped[int] = mapped_column(Integer, default=1) # NEW

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    login_id: Mapped[str] = mapped_column(String(64), index=True)   # 예: weddinghall1
    pw_hash: Mapped[str] = mapped_column(String(255))               # (과거 호환용: 더이상 검증에 안 씀)
    role: Mapped[str] = mapped_column(String(16), default="staff")  # staff only
    __table_args__ = (UniqueConstraint("tenant_id","login_id", name="uq_user_tenant_login"),)

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    device_code: Mapped[str] = mapped_column(String(32), index=True)      # D-A1 등
    activation_code: Mapped[str] = mapped_column(String(64), unique=True) # 출고시 제공
    active: Mapped[int] = mapped_column(Integer, default=0)               # 0/1
    last_seen_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    __table_args__ = (UniqueConstraint("tenant_id","device_code", name="uq_device_per_tenant"),)

class DeviceClaim(Base):
    __tablename__ = "device_claims"
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    device_code = Column(String, nullable=False)
    session_id = Column(String, nullable=False)   # 클라이언트가 만든 세션 ID(아무 문자열)
    claimed_at = Column(DateTime, nullable=False, server_default=func.now())
    expires_at = Column(DateTime, nullable=True)  # 하트비트/만료(선택)

    __table_args__ = (
        UniqueConstraint("tenant_id", "device_code", name="uq_tenant_device_claim"),
    )

class WeddingEvent(Base):
    __tablename__ = "wedding_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    device_code: Mapped[str] = mapped_column(String(32), index=True)
    owner_type: Mapped[str] = mapped_column(String(16), default="groom", nullable=False)

    hall_name: Mapped[str] = mapped_column(String(20), nullable=False)  # ✅ 추가

    event_date: Mapped[date] = mapped_column(DateTime)
    start_time: Mapped[str] = mapped_column(String(8))
    title: Mapped[str] = mapped_column(String(100))
    groom_name: Mapped[str] = mapped_column(String(50))
    bride_name: Mapped[str] = mapped_column(String(50))
    child_min_age: Mapped[int] = mapped_column(Integer, default=0)
    child_max_age: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

class TicketStat(Base):
    __tablename__ = "ticket_stats"
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"))
    device_code = Column(String, nullable=False, index=True)  # ✅ 추가
    event_title = Column(String, nullable=False)
    hall_name = Column(String, nullable=True)
    adult_count = Column(Integer, default=0, nullable=False)
    child_count = Column(Integer, default=0, nullable=False)

class TicketPrice(Base):
    __tablename__ = "ticket_prices"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    adult_price: Mapped[int] = mapped_column(Integer, default=0)
    child_price: Mapped[int] = mapped_column(Integer, default=0)

