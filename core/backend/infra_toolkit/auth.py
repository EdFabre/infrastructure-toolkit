"""Authentication and authorization for Infrastructure Toolkit.

Provides password hashing, session token management, and user authentication.
"""

import secrets
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple, List

import bcrypt
from sqlalchemy.orm import Session

from .database import get_db, User, Session as DBSession, ApiKey, AuditLog, PasswordResetToken

logger = logging.getLogger(__name__)


# Password hashing

def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        Hashed password as string
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash.

    Args:
        password: Plain text password to verify
        password_hash: Hashed password to compare against

    Returns:
        True if password matches, False otherwise
    """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


# Session token management

def generate_session_token() -> str:
    """Generate a secure random session token.

    Returns:
        Random URL-safe token string
    """
    return secrets.token_urlsafe(32)


def create_session(
    db: Session,
    user_id: int,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    timeout_hours: int = 24
) -> str:
    """Create a new session for a user.

    Args:
        db: Database session
        user_id: User ID to create session for
        ip_address: Client IP address
        user_agent: Client user agent string
        timeout_hours: Session validity duration in hours

    Returns:
        Session token string
    """
    token = generate_session_token()
    expires_at = datetime.utcnow() + timedelta(hours=timeout_hours)

    session = DBSession(
        token=token,
        user_id=user_id,
        created_at=datetime.utcnow(),
        expires_at=expires_at,
        ip_address=ip_address,
        user_agent=user_agent
    )

    db.add(session)
    db.commit()

    logger.info(f"Created session for user_id={user_id}, expires at {expires_at}")
    return token


def get_session(db: Session, token: str) -> Optional[DBSession]:
    """Get a session by token.

    Args:
        db: Database session
        token: Session token

    Returns:
        Session object if valid and not expired, None otherwise
    """
    session = db.query(DBSession).filter_by(token=token).first()

    if not session:
        return None

    # Check if expired
    if session.expires_at < datetime.utcnow():
        logger.info(f"Session {token[:8]}... expired")
        db.delete(session)
        db.commit()
        return None

    return session


def delete_session(db: Session, token: str) -> bool:
    """Delete a session (logout).

    Args:
        db: Database session
        token: Session token to delete

    Returns:
        True if session was deleted, False if not found
    """
    session = db.query(DBSession).filter_by(token=token).first()
    if session:
        db.delete(session)
        db.commit()
        logger.info(f"Deleted session {token[:8]}...")
        return True
    return False


def cleanup_expired_sessions(db: Session) -> int:
    """Remove all expired sessions from database.

    Args:
        db: Database session

    Returns:
        Number of sessions deleted
    """
    count = db.query(DBSession).filter(DBSession.expires_at < datetime.utcnow()).delete()
    db.commit()
    if count > 0:
        logger.info(f"Cleaned up {count} expired sessions")
    return count


# User authentication

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate a user by username and password.

    Args:
        db: Database session
        username: Username
        password: Plain text password

    Returns:
        User object if authentication successful, None otherwise
    """
    user = db.query(User).filter_by(username=username).first()

    if not user:
        logger.warning(f"Authentication failed: user '{username}' not found")
        return None

    if not user.is_active:
        logger.warning(f"Authentication failed: user '{username}' is inactive")
        return None

    if not verify_password(password, user.password_hash):
        logger.warning(f"Authentication failed: invalid password for user '{username}'")
        return None

    # Update last login timestamp
    user.last_login = datetime.utcnow()
    db.commit()

    logger.info(f"User '{username}' authenticated successfully")
    return user


def get_user_from_token(db: Session, token: str) -> Optional[User]:
    """Get user from session token.

    Args:
        db: Database session
        token: Session token

    Returns:
        User object if token is valid, None otherwise
    """
    session = get_session(db, token)
    if not session:
        return None

    user = db.query(User).filter_by(id=session.user_id).first()
    if not user or not user.is_active:
        return None

    return user


# Audit logging

def log_audit(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    resource: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[str] = None,
    success: bool = True,
    error_message: Optional[str] = None
):
    """Log an action to the audit trail.

    Args:
        db: Database session
        action: Action performed (e.g., 'login', 'restart_service')
        user_id: User ID who performed the action
        username: Username (denormalized for historical record)
        resource: Resource affected (e.g., 'docker', 'network')
        ip_address: Client IP address
        details: JSON-serialized additional context
        success: Whether the action succeeded
        error_message: Error message if action failed
    """
    audit_entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        timestamp=datetime.utcnow(),
        ip_address=ip_address,
        details=details,
        success=success,
        error_message=error_message
    )

    db.add(audit_entry)
    db.commit()


# User management

def create_user(db: Session, username: str, password: str, role: str = "viewer") -> User:
    """Create a new user.

    Args:
        db: Database session
        username: Username (must be unique)
        password: Plain text password (will be hashed)
        role: User role ('admin', 'editor', 'viewer')

    Returns:
        Created User object

    Raises:
        ValueError: If username already exists
    """
    # Check if user exists
    existing = db.query(User).filter_by(username=username).first()
    if existing:
        raise ValueError(f"User '{username}' already exists")

    # Create user
    user = User(
        username=username,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
        created_at=datetime.utcnow()
    )

    db.add(user)
    db.commit()

    logger.info(f"Created user '{username}' with role '{role}'")
    return user


def change_password(db: Session, user_id: int, old_password: str, new_password: str) -> Tuple[bool, str]:
    """Change a user's password.

    Args:
        db: Database session
        user_id: User ID
        old_password: Current password for verification
        new_password: New password to set

    Returns:
        Tuple of (success: bool, message: str)
    """
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        return False, "User not found"

    # Verify old password
    if not verify_password(old_password, user.password_hash):
        return False, "Current password is incorrect"

    # Set new password
    user.password_hash = hash_password(new_password)
    db.commit()

    logger.info(f"Password changed for user '{user.username}'")
    return True, "Password changed successfully"


def reset_password_admin(db: Session, user_id: int, new_password: str) -> Tuple[bool, str]:
    """Reset a user's password (admin function).

    Args:
        db: Database session
        user_id: User ID to reset password for
        new_password: New password to set

    Returns:
        Tuple of (success: bool, message: str)
    """
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        return False, "User not found"

    user.password_hash = hash_password(new_password)
    db.commit()

    logger.info(f"Password reset for user '{user.username}' by admin")
    return True, f"Password reset for user '{user.username}'"


# API Key management

def generate_api_key() -> str:
    """Generate a secure random API key.

    Returns:
        Random URL-safe API key string (43 characters)
    """
    return secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    """Hash an API key using SHA-256.

    Args:
        api_key: Plain text API key

    Returns:
        Hashed API key as hex string
    """
    return hashlib.sha256(api_key.encode('utf-8')).hexdigest()


def create_api_key(
    db: Session,
    user_id: int,
    name: str,
    expires_days: Optional[int] = None
) -> Tuple[str, ApiKey]:
    """Create a new API key for a user.

    Args:
        db: Database session
        user_id: User ID to create API key for
        name: User-friendly name for the key
        expires_days: Optional expiration in days (None = never expires)

    Returns:
        Tuple of (plain_text_key: str, api_key_record: ApiKey)
        Note: The plain text key is only returned once and never stored
    """
    # Generate API key
    plain_key = generate_api_key()
    key_hash = hash_api_key(plain_key)
    prefix = plain_key[:8]

    # Calculate expiration
    expires_at = None
    if expires_days is not None:
        expires_at = datetime.utcnow() + timedelta(days=expires_days)

    # Create API key record
    api_key = ApiKey(
        user_id=user_id,
        name=name,
        key_hash=key_hash,
        prefix=prefix,
        created_at=datetime.utcnow(),
        expires_at=expires_at,
        is_active=True
    )

    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    logger.info(f"Created API key '{name}' (id={api_key.id}) for user_id={user_id}")
    return plain_key, api_key


def get_api_key_by_value(db: Session, api_key: str) -> Optional[ApiKey]:
    """Get an API key by its value (for authentication).

    Args:
        db: Database session
        api_key: Plain text API key

    Returns:
        ApiKey object if valid and active, None otherwise
    """
    key_hash = hash_api_key(api_key)
    api_key_record = db.query(ApiKey).filter_by(key_hash=key_hash).first()

    if not api_key_record:
        return None

    # Check if active
    if not api_key_record.is_active:
        logger.info(f"API key {api_key_record.prefix}... is inactive")
        return None

    # Check if expired
    if api_key_record.expires_at and api_key_record.expires_at < datetime.utcnow():
        logger.info(f"API key {api_key_record.prefix}... expired")
        return None

    # Update last used timestamp
    api_key_record.last_used_at = datetime.utcnow()
    db.commit()

    return api_key_record


def list_api_keys(db: Session, user_id: int) -> List[ApiKey]:
    """List all API keys for a user.

    Args:
        db: Database session
        user_id: User ID

    Returns:
        List of ApiKey objects
    """
    return db.query(ApiKey).filter_by(user_id=user_id).order_by(ApiKey.created_at.desc()).all()


def revoke_api_key(db: Session, api_key_id: int, user_id: int) -> Tuple[bool, str]:
    """Revoke (delete) an API key.

    Args:
        db: Database session
        api_key_id: API key ID to revoke
        user_id: User ID (for authorization check)

    Returns:
        Tuple of (success: bool, message: str)
    """
    api_key = db.query(ApiKey).filter_by(id=api_key_id, user_id=user_id).first()

    if not api_key:
        return False, "API key not found or access denied"

    db.delete(api_key)
    db.commit()

    logger.info(f"Revoked API key '{api_key.name}' (id={api_key_id}) for user_id={user_id}")
    return True, f"API key '{api_key.name}' revoked successfully"


def rotate_api_key(
    db: Session,
    api_key_id: int,
    user_id: int,
    expires_days: Optional[int] = None
) -> Tuple[bool, str, Optional[str]]:
    """Rotate an API key (delete old, create new with same name).

    Args:
        db: Database session
        api_key_id: API key ID to rotate
        user_id: User ID (for authorization check)
        expires_days: Optional expiration in days for new key

    Returns:
        Tuple of (success: bool, message: str, new_plain_key: Optional[str])
    """
    old_key = db.query(ApiKey).filter_by(id=api_key_id, user_id=user_id).first()

    if not old_key:
        return False, "API key not found or access denied", None

    # Save the name for the new key
    key_name = old_key.name

    # Delete old key
    db.delete(old_key)
    db.commit()

    # Create new key with same name
    plain_key, new_key = create_api_key(db, user_id, key_name, expires_days)

    logger.info(f"Rotated API key '{key_name}' for user_id={user_id}")
    return True, f"API key '{key_name}' rotated successfully", plain_key


def get_user_from_api_key(db: Session, api_key: str) -> Optional[User]:
    """Get user from API key.

    Args:
        db: Database session
        api_key: Plain text API key

    Returns:
        User object if API key is valid, None otherwise
    """
    api_key_record = get_api_key_by_value(db, api_key)
    if not api_key_record:
        return None

    user = db.query(User).filter_by(id=api_key_record.user_id).first()
    if not user or not user.is_active:
        return None

    return user


# Password Reset Token Management

def generate_reset_token() -> str:
    """Generate a secure random password reset token.

    Returns:
        Random URL-safe token string (128 bits of entropy)
    """
    return secrets.token_urlsafe(32)


def hash_reset_token(token: str) -> str:
    """Hash a password reset token using SHA-256.

    Args:
        token: Plain text reset token

    Returns:
        Hashed token as hex string
    """
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def create_password_reset_token(
    db: Session,
    email: str,
    ip_address: Optional[str] = None,
    expiry_hours: int = 1
) -> Tuple[bool, str, Optional[str]]:
    """Create a password reset token for a user by email.

    Args:
        db: Database session
        email: User's email address
        ip_address: IP address that requested the reset
        expiry_hours: Token expiration time in hours (default: 1)

    Returns:
        Tuple of (success: bool, message: str, plain_token: Optional[str])
    """
    # Find user by email
    user = db.query(User).filter_by(email=email).first()

    # Always return success to prevent email enumeration
    if not user:
        logger.warning(f"Password reset requested for non-existent email: {email}")
        return True, "If that email is registered, a password reset link has been sent", None

    if not user.is_active:
        logger.warning(f"Password reset requested for inactive user: {user.username}")
        return True, "If that email is registered, a password reset link has been sent", None

    # Check rate limiting - max 3 requests per hour
    recent_tokens = db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.created_at > datetime.utcnow() - timedelta(hours=1)
    ).count()

    if recent_tokens >= 3:
        logger.warning(f"Rate limit exceeded for password reset: {user.username}")
        return True, "If that email is registered, a password reset link has been sent", None

    # Invalidate any existing unused tokens for this user
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.is_used == False
    ).update({"is_used": True, "used_at": datetime.utcnow()})

    # Generate new token
    plain_token = generate_reset_token()
    token_hash = hash_reset_token(plain_token)
    expires_at = datetime.utcnow() + timedelta(hours=expiry_hours)

    # Create token record
    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        created_at=datetime.utcnow(),
        expires_at=expires_at,
        is_used=False,
        ip_address=ip_address
    )

    db.add(reset_token)
    db.commit()

    logger.info(f"Created password reset token for user '{user.username}'")
    return True, "If that email is registered, a password reset link has been sent", plain_token


def verify_reset_token(db: Session, token: str) -> Tuple[bool, str, Optional[User]]:
    """Verify a password reset token.

    Args:
        db: Database session
        token: Plain text reset token

    Returns:
        Tuple of (valid: bool, message: str, user: Optional[User])
    """
    token_hash = hash_reset_token(token)
    reset_token = db.query(PasswordResetToken).filter_by(token_hash=token_hash).first()

    if not reset_token:
        return False, "Invalid or expired reset token", None

    # Check if token is used
    if reset_token.is_used:
        return False, "This reset token has already been used", None

    # Check if token is expired
    if reset_token.expires_at < datetime.utcnow():
        return False, "This reset token has expired", None

    # Get user
    user = db.query(User).filter_by(id=reset_token.user_id).first()
    if not user or not user.is_active:
        return False, "Invalid or expired reset token", None

    return True, "Token is valid", user


def reset_password_with_token(
    db: Session,
    token: str,
    new_password: str
) -> Tuple[bool, str]:
    """Reset a user's password using a reset token.

    Args:
        db: Database session
        token: Plain text reset token
        new_password: New password to set

    Returns:
        Tuple of (success: bool, message: str)
    """
    # Verify token
    valid, message, user = verify_reset_token(db, token)
    if not valid or not user:
        return False, message

    # Mark token as used
    token_hash = hash_reset_token(token)
    reset_token = db.query(PasswordResetToken).filter_by(token_hash=token_hash).first()
    if reset_token:
        reset_token.is_used = True
        reset_token.used_at = datetime.utcnow()

    # Set new password
    user.password_hash = hash_password(new_password)
    db.commit()

    logger.info(f"Password reset successfully for user '{user.username}'")
    return True, "Password has been reset successfully"


def cleanup_expired_reset_tokens(db: Session) -> int:
    """Remove expired password reset tokens from database.

    Args:
        db: Database session

    Returns:
        Number of tokens deleted
    """
    # Delete tokens that are either used OR expired
    count = db.query(PasswordResetToken).filter(
        (PasswordResetToken.is_used == True) |
        (PasswordResetToken.expires_at < datetime.utcnow())
    ).delete()
    db.commit()

    if count > 0:
        logger.info(f"Cleaned up {count} expired/used password reset tokens")
    return count
