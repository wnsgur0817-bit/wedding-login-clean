from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, ForeignKey, UniqueConstraint, DateTime, func

class Base(DeclarativeBase): pass

class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(16), unique=True, index=True)  # ��: T-0001
    name: Mapped[str] = mapped_column(String(100))

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    login_id: Mapped[str] = mapped_column(String(64), index=True)   # ��: weddinghall1
    pw_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="staff")  # staff only
    __table_args__ = (UniqueConstraint("tenant_id","login_id", name="uq_user_tenant_login"),)

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    device_code: Mapped[str] = mapped_column(String(32), index=True)      # D-A1 ��
    activation_code: Mapped[str] = mapped_column(String(64), unique=True) # ���� ����
    active: Mapped[int] = mapped_column(Integer, default=0)               # 0/1
    last_seen_at: Mapped[DateTime] = mapped_column(DateTime, server_default=func.now())
    __table_args__ = (UniqueConstraint("tenant_id","device_code", name="uq_device_per_tenant"),)
