"""Database models and session management for Infrastructure Toolkit.

Provides SQLAlchemy models for authentication and audit logging.
"""

from datetime import datetime
from typing import Generator

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

# Database URL - using SQLite for simplicity (can be configured for PostgreSQL/MySQL)
DATABASE_URL = "sqlite:///./infra_toolkit.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # Needed for SQLite
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# Models

class User(Base):
    """User account model."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    email = Column(String(255), nullable=True, index=True)  # Email for password reset
    role = Column(String(20), nullable=False, default="viewer")  # admin, editor, viewer
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    password_reset_tokens = relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")


class Session(Base):
    """User session model for token-based authentication."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv6-compatible
    user_agent = Column(String(255), nullable=True)

    # Relationships
    user = relationship("User", back_populates="sessions")


class ApiKey(Base):
    """API key model for programmatic access."""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)  # User-friendly name
    key_hash = Column(String(64), unique=True, index=True, nullable=False)  # SHA-256 hash
    prefix = Column(String(8), nullable=False)  # First 8 chars for display
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)  # Optional expiration
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    user = relationship("User", back_populates="api_keys")


class AuditLog(Base):
    """Audit log model for tracking user actions."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Nullable for failed logins
    username = Column(String(50), nullable=True)  # Denormalized for historical record
    action = Column(String(50), nullable=False)  # login, logout, restart_service, etc.
    resource = Column(String(100), nullable=True)  # Service/resource affected
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    details = Column(Text, nullable=True)  # JSON-serialized additional context
    success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)


class PasswordResetToken(Base):
    """Password reset token model for secure password recovery."""
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)  # SHA-256 hash
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime, nullable=True)  # Track when token was used
    is_used = Column(Boolean, default=False, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IP that requested reset

    # Relationships
    user = relationship("User", back_populates="password_reset_tokens")


# Database session dependency for FastAPI

def get_db() -> Generator[Session, None, None]:
    """Get database session for dependency injection.

    Yields:
        Database session that auto-closes after request
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Database initialization

def init_db():
    """Initialize database tables and create default admin user."""
    Base.metadata.create_all(bind=engine)

    # Create default admin user if not exists
    db = SessionLocal()
    try:
        from .auth import hash_password

        admin = db.query(User).filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                password_hash=hash_password("admin"),  # CHANGE THIS IN PRODUCTION!
                role="admin",
                is_active=True,
                created_at=datetime.utcnow()
            )
            db.add(admin)
            db.commit()
            print("✅ Created default admin user (admin/admin)")
        else:
            print("ℹ️  Admin user already exists")
    except Exception as e:
        print(f"⚠️  Error creating admin user: {e}")
    finally:
        db.close()
