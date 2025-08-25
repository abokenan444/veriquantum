import os
from datetime import datetime
from sqlalchemy import (
    create_engine, String, Integer, DateTime, Boolean, Text,
    ForeignKey, Numeric, func
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, relationship
from sqlalchemy.exc import OperationalError

# -------- Database URL --------
DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///veriquantum.db"
else:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

# -------- Declarative Base --------
class Base(DeclarativeBase):
    pass

# -------- Models --------
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    twofa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    idp_provider: Mapped[str | None] = mapped_column(String(50))
    idp_sub: Mapped[str | None] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Setting(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    smtp_host: Mapped[str | None] = mapped_column(String(255))
    smtp_port: Mapped[str | None] = mapped_column(String(10))
    smtp_user: Mapped[str | None] = mapped_column(String(255))
    smtp_pass: Mapped[str | None] = mapped_column(String(255))
    smtp_from: Mapped[str | None] = mapped_column(String(255))
    app_base_url: Mapped[str | None] = mapped_column(String(255))
    slack_webhook_url: Mapped[str | None] = mapped_column(Text)
    telegram_bot_token: Mapped[str | None] = mapped_column(String(255))
    telegram_chat_id: Mapped[str | None] = mapped_column(String(255))
    oidc_google_client_id: Mapped[str | None] = mapped_column(String(255))
    oidc_google_client_secret: Mapped[str | None] = mapped_column(String(255))
    oidc_google_issuer: Mapped[str | None] = mapped_column(String(255))
    oidc_azure_client_id: Mapped[str | None] = mapped_column(String(255))
    oidc_azure_client_secret: Mapped[str | None] = mapped_column(String(255))
    oidc_azure_issuer: Mapped[str | None] = mapped_column(String(255))


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sector: Mapped[str] = mapped_column(String(50), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    geo_countries_csv: Mapped[str | None] = mapped_column(Text)
    time_window: Mapped[str | None] = mapped_column(String(50))
    liveness_level: Mapped[str | None] = mapped_column(String(20))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AlertLog(Base):
    __tablename__ = "alert_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    level: Mapped[str] = mapped_column(String(20))
    channel: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uid: Mapped[int | None] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(100))
    details: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    country: Mapped[str | None] = mapped_column(String(2))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Membership(Base):
    __tablename__ = "memberships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    role: Mapped[str] = mapped_column(String(30), default="member")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    org = relationship("Organization")
    user = relationship("User")


class Country(Base):
    __tablename__ = "countries"
    code: Mapped[str] = mapped_column(String(2), primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ThemeSetting(Base):
    __tablename__ = "theme_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    brand_name: Mapped[str | None] = mapped_column(String(100))
    primary_color: Mapped[str | None] = mapped_column(String(20))
    logo_url: Mapped[str | None] = mapped_column(String(255))


class Plan(Base):
    __tablename__ = "plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    price_month: Mapped[float] = mapped_column(Numeric(10, 2), default=0)
    currency: Mapped[str] = mapped_column(String(3), default="EUR")
    features_json: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    org_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"))
    plan_id: Mapped[int] = mapped_column(ForeignKey("plans.id"))
    status: Mapped[str] = mapped_column(String(30), default="active")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stripe_customer_id: Mapped[str | None] = mapped_column(String(120))
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(120))
    billing_cycle: Mapped[str] = mapped_column(String(10), default="monthly")
    user = relationship("User")
    org = relationship("Organization")
    plan = relationship("Plan")


class Invoice(Base):
    __tablename__ = "invoices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sub_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"))
    amount: Mapped[float] = mapped_column(Numeric(10, 2))
    currency: Mapped[str] = mapped_column(String(3), default="EUR")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    method: Mapped[str] = mapped_column(String(20))
    stripe_payment_intent: Mapped[str | None] = mapped_column(String(120))
    bank_reference: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    subscription = relationship("Subscription")


class BankTransferRequest(Base):
    __tablename__ = "bank_transfer_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sub_id: Mapped[int] = mapped_column(ForeignKey("subscriptions.id"))
    amount: Mapped[float] = mapped_column(Numeric(10, 2))
    currency: Mapped[str] = mapped_column(String(3), default="EUR")
    reference_code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    subscription = relationship("Subscription")


class LegalPage(Base):
    __tablename__ = "legal_pages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(150))
    content_md: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Sector(Base):
    __tablename__ = "sectors"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class OrgPermission(Base):
    __tablename__ = "org_permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(Integer)
    user_id: Mapped[int] = mapped_column(Integer)
    scope: Mapped[str] = mapped_column(String(50))
    granted: Mapped[bool] = mapped_column(Boolean, default=True)


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    credential_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    transports: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User")

# -------- Helpers --------
def init_db():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        s = db.get(Setting, 1)
        if not s:
            s = Setting(id=1, smtp_port="587")
            db.add(s)
        # default sectors
        default_sectors = ["government", "banks", "hospitals", "companies", "individuals"]
        for sec in default_sectors:
            exists = db.query(Policy).filter(Policy.sector == sec).first()
            if not exists:
                db.add(Policy(sector=sec, enabled=True, liveness_level="medium"))
        # default plans
        if not db.query(Plan).count():
            db.add_all([
                Plan(code="free", name="Free", price_month=0, currency="EUR", features_json='{"seats":1,"biometric":"basic"}'),
                Plan(code="pro", name="Pro", price_month=29.00, currency="EUR", features_json='{"seats":10,"biometric":"advanced","alerts":true}'),
                Plan(code="enterprise", name="Enterprise", price_month=199.00, currency="EUR", features_json='{"seats":"unlimited","biometric":"max","sso":true,"sla":"99.99%"}'),
            ])
        # countries
        if not db.query(Country).count():
            db.add_all([
                Country(code="NL", name="Netherlands", enabled=True),
                Country(code="DE", name="Germany", enabled=True),
                Country(code="FR", name="France", enabled=True),
                Country(code="SA", name="Saudi Arabia", enabled=True),
            ])
        # theme
        if not db.query(ThemeSetting).count():
            db.add(ThemeSetting(id=1, brand_name="VeriQuantum", primary_color="#0b5ed7"))
        db.commit()


def db_health() -> bool:
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return True
    except OperationalError:
        return False