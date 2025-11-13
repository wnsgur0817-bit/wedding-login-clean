# models.py

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, ForeignKey, DateTime, func, Date


class Base(DeclarativeBase):
    pass


# ======================================
# 관리자 전용 테넌트 (T-0000) + 일반 테넌트
# ======================================
class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(16), unique=True, index=True)  # T-0000, T-0001 ...
    name: Mapped[str] = mapped_column(String(100))


# ======================================
# 승인 대기 사용자
# ======================================
class RequestedUser(Base):
    __tablename__ = "requested_users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    login_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    pw_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())


# ======================================
# 승인된 사용자 (직원)
# ======================================
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    login_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    pw_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="staff")  # admin/staff


# ======================================
# 디바이스 (D-A01, D-A02 ...)
# ======================================
class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    device_code: Mapped[str] = mapped_column(String(16), index=True)  # D-A01 ...
    activation_code: Mapped[str] = mapped_column(String(64))
    active: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = ({"sqlite_autoincrement": True},)


# ======================================
# 예식 정보
# ======================================
class WeddingEvent(Base):
    __tablename__ = "wedding_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    device_code: Mapped[str] = mapped_column(String(16))

    owner_type: Mapped[str] = mapped_column(String(16), default="groom")
    hall_name: Mapped[str] = mapped_column(String(20))

    event_date: Mapped[Date] = mapped_column(Date)
    start_time: Mapped[str] = mapped_column(String(8))

    title: Mapped[str] = mapped_column(String(100))
    groom_name: Mapped[str] = mapped_column(String(50))
    bride_name: Mapped[str] = mapped_column(String(50))

    child_min_age: Mapped[int] = mapped_column(Integer, default=0)
    child_max_age: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    # ======================================
    # 🔥 누적 통계 저장용 필드 추가
    # ======================================
    groom_adult_total: Mapped[int] = mapped_column(Integer, default=0)
    groom_child_total: Mapped[int] = mapped_column(Integer, default=0)
    bride_adult_total: Mapped[int] = mapped_column(Integer, default=0)
    bride_child_total: Mapped[int] = mapped_column(Integer, default=0)

    groom_total_price: Mapped[int] = mapped_column(Integer, default=0)
    bride_total_price: Mapped[int] = mapped_column(Integer, default=0)

# ======================================
# 발급 통계
# ======================================
class TicketStat(Base):
    __tablename__ = "ticket_stats"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    event_id: Mapped[int] = mapped_column(ForeignKey("wedding_events.id"))
    device_code: Mapped[str] = mapped_column(String(16))

    event_title: Mapped[str] = mapped_column(String(100))
    hall_name: Mapped[str] = mapped_column(String(50))

    adult_count: Mapped[int] = mapped_column(Integer, default=0)
    child_count: Mapped[int] = mapped_column(Integer, default=0)

    restaurant_adult: Mapped[int] = mapped_column(Integer, default=0)
    restaurant_child: Mapped[int] = mapped_column(Integer, default=0)
    gift_adult: Mapped[int] = mapped_column(Integer, default=0)
    gift_child: Mapped[int] = mapped_column(Integer, default=0)

    unused_adult: Mapped[int] = mapped_column(Integer, default=0)
    unused_child: Mapped[int] = mapped_column(Integer, default=0)
    unused_total: Mapped[int] = mapped_column(Integer, default=0)
    grand_total: Mapped[int] = mapped_column(Integer, default=0)


# ======================================
# 단가 테이블
# ======================================
class TicketPrice(Base):
    __tablename__ = "ticket_prices"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    adult_price: Mapped[int] = mapped_column(Integer, default=0)
    child_price: Mapped[int] = mapped_column(Integer, default=0)
