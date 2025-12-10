"""Authentication API routes."""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from pydantic import BaseModel, EmailStr

from ...database import get_db, User
from ...auth import (
    authenticate_user,
    create_session,
    delete_session,
    get_user_from_token,
    get_user_from_api_key,
    change_password,
    create_api_key,
    list_api_keys,
    revoke_api_key,
    rotate_api_key,
    log_audit,
    cleanup_expired_sessions,
    create_password_reset_token,
    verify_reset_token,
    reset_password_with_token,
    cleanup_expired_reset_tokens
)
from ...email import get_email_service, configure_email_service, EmailConfig

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["authentication"])


# Request/Response models

class LoginRequest(BaseModel):
    """Login request body."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response."""
    success: bool
    token: Optional[str] = None
    username: Optional[str] = None
    role: Optional[str] = None
    message: str


class LogoutResponse(BaseModel):
    """Logout response."""
    success: bool
    message: str


class ChangePasswordRequest(BaseModel):
    """Change password request body."""
    old_password: str
    new_password: str


class ChangePasswordResponse(BaseModel):
    """Change password response."""
    success: bool
    message: str


class CurrentUserResponse(BaseModel):
    """Current user information."""
    id: int
    username: str
    role: str
    is_active: bool


class ApiKeyCreateRequest(BaseModel):
    """API key creation request."""
    name: str
    expires_days: Optional[int] = None


class ApiKeyResponse(BaseModel):
    """API key response."""
    id: int
    name: str
    prefix: str
    created_at: str
    last_used_at: Optional[str]
    expires_at: Optional[str]
    is_active: bool


class ApiKeyCreateResponse(BaseModel):
    """API key creation response."""
    success: bool
    message: str
    api_key: Optional[str] = None  # Only returned once during creation
    key_info: Optional[ApiKeyResponse] = None


class ApiKeyListResponse(BaseModel):
    """API keys list response."""
    api_keys: list[ApiKeyResponse]


class ApiKeyRotateRequest(BaseModel):
    """API key rotation request."""
    expires_days: Optional[int] = None


# Dependency to get current user from auth header

async def get_current_user(
    authorization: Optional[str] = Header(None),
    db = Depends(get_db)
) -> User:
    """Get current user from Authorization header.

    Supports both session tokens and API keys.

    Args:
        authorization: Bearer token/key from Authorization header
        db: Database session

    Returns:
        User object

    Raises:
        HTTPException: If token/key is invalid or missing
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")

    # Extract token/key from "Bearer <token>"
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization header format")

    token_or_key = parts[1]

    # Try session token first (shorter, more common)
    user = get_user_from_token(db, token_or_key)
    if user:
        return user

    # Try API key (long-lived)
    user = get_user_from_api_key(db, token_or_key)
    if user:
        return user

    raise HTTPException(status_code=401, detail="Invalid or expired token/API key")


# Routes

@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, http_request: Request, db = Depends(get_db)):
    """Authenticate user and create session.

    Args:
        request: Login credentials
        http_request: FastAPI request for IP address
        db: Database session

    Returns:
        LoginResponse with session token if successful
    """
    # Clean up expired sessions
    cleanup_expired_sessions(db)

    # Authenticate user
    user = authenticate_user(db, request.username, request.password)

    if not user:
        # Log failed attempt
        log_audit(
            db,
            action="login",
            username=request.username,
            ip_address=http_request.client.host if http_request.client else None,
            success=False,
            error_message="Invalid credentials"
        )

        return LoginResponse(
            success=False,
            message="Invalid username or password"
        )

    # Create session
    user_agent = http_request.headers.get("user-agent")
    token = create_session(
        db,
        user_id=user.id,
        ip_address=http_request.client.host if http_request.client else None,
        user_agent=user_agent,
        timeout_hours=24
    )

    # Log successful login
    log_audit(
        db,
        action="login",
        user_id=user.id,
        username=user.username,
        ip_address=http_request.client.host if http_request.client else None,
        success=True
    )

    logger.info(f"User '{user.username}' logged in")

    return LoginResponse(
        success=True,
        token=token,
        username=user.username,
        role=user.role,
        message="Login successful"
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    http_request: Request,
    current_user: User = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
    db = Depends(get_db)
):
    """Logout user and delete session.

    Args:
        http_request: FastAPI request for IP address
        current_user: Current authenticated user
        authorization: Auth header with token
        db: Database session

    Returns:
        LogoutResponse
    """
    # Extract token
    token = authorization.split()[1] if authorization else None

    if token:
        delete_session(db, token)

    # Log logout
    log_audit(
        db,
        action="logout",
        user_id=current_user.id,
        username=current_user.username,
        ip_address=http_request.client.host if http_request.client else None,
        success=True
    )

    logger.info(f"User '{current_user.username}' logged out")

    return LogoutResponse(
        success=True,
        message="Logged out successfully"
    )


@router.post("/change-password", response_model=ChangePasswordResponse)
async def change_user_password(
    request: ChangePasswordRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Change current user's password.

    Args:
        request: Old and new passwords
        http_request: FastAPI request for IP address
        current_user: Current authenticated user
        db: Database session

    Returns:
        ChangePasswordResponse
    """
    # Change password
    success, message = change_password(
        db,
        user_id=current_user.id,
        old_password=request.old_password,
        new_password=request.new_password
    )

    # Log password change attempt
    log_audit(
        db,
        action="change_password",
        user_id=current_user.id,
        username=current_user.username,
        ip_address=http_request.client.host if http_request.client else None,
        success=success,
        error_message=None if success else message
    )

    if not success:
        raise HTTPException(status_code=400, detail=message)

    logger.info(f"User '{current_user.username}' changed password")

    return ChangePasswordResponse(
        success=True,
        message=message
    )


@router.get("/me", response_model=CurrentUserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information.

    Args:
        current_user: Current authenticated user

    Returns:
        CurrentUserResponse with user details
    """
    return CurrentUserResponse(
        id=current_user.id,
        username=current_user.username,
        role=current_user.role,
        is_active=current_user.is_active
    )


# API Key Management Routes

@router.get("/api-keys/", response_model=ApiKeyListResponse)
async def list_user_api_keys(
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """List all API keys for current user.

    Args:
        current_user: Current authenticated user
        db: Database session

    Returns:
        List of API keys
    """
    keys = list_api_keys(db, current_user.id)

    return ApiKeyListResponse(
        api_keys=[
            ApiKeyResponse(
                id=key.id,
                name=key.name,
                prefix=key.prefix,
                created_at=key.created_at.isoformat(),
                last_used_at=key.last_used_at.isoformat() if key.last_used_at else None,
                expires_at=key.expires_at.isoformat() if key.expires_at else None,
                is_active=key.is_active
            )
            for key in keys
        ]
    )


@router.post("/api-keys/", response_model=ApiKeyCreateResponse)
async def create_user_api_key(
    request: ApiKeyCreateRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Create a new API key for current user.

    Args:
        request: API key creation parameters
        http_request: FastAPI request for IP address
        current_user: Current authenticated user
        db: Database session

    Returns:
        Created API key (only time the full key is returned)
    """
    plain_key, api_key = create_api_key(
        db,
        user_id=current_user.id,
        name=request.name,
        expires_days=request.expires_days
    )

    # Log API key creation
    log_audit(
        db,
        action="create_api_key",
        user_id=current_user.id,
        username=current_user.username,
        resource=request.name,
        ip_address=http_request.client.host if http_request.client else None,
        success=True
    )

    return ApiKeyCreateResponse(
        success=True,
        message=f"API key '{request.name}' created successfully",
        api_key=plain_key,
        key_info=ApiKeyResponse(
            id=api_key.id,
            name=api_key.name,
            prefix=api_key.prefix,
            created_at=api_key.created_at.isoformat(),
            last_used_at=None,
            expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
            is_active=api_key.is_active
        )
    )


@router.delete("/api-keys/{key_id}", response_model=ChangePasswordResponse)
async def revoke_user_api_key(
    key_id: int,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Revoke an API key.

    Args:
        key_id: API key ID to revoke
        http_request: FastAPI request for IP address
        current_user: Current authenticated user
        db: Database session

    Returns:
        Success response
    """
    success, message = revoke_api_key(db, key_id, current_user.id)

    # Log API key revocation
    log_audit(
        db,
        action="revoke_api_key",
        user_id=current_user.id,
        username=current_user.username,
        resource=f"key_id_{key_id}",
        ip_address=http_request.client.host if http_request.client else None,
        success=success,
        error_message=None if success else message
    )

    if not success:
        raise HTTPException(status_code=404, detail=message)

    return ChangePasswordResponse(
        success=True,
        message=message
    )


@router.put("/api-keys/{key_id}/rotate", response_model=ApiKeyCreateResponse)
async def rotate_user_api_key(
    key_id: int,
    request: ApiKeyRotateRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Rotate an API key (invalidate old, create new with same name).

    Args:
        key_id: API key ID to rotate
        request: Rotation parameters
        http_request: FastAPI request for IP address
        current_user: Current authenticated user
        db: Database session

    Returns:
        New API key (only time the full key is returned)
    """
    success, message, plain_key = rotate_api_key(
        db,
        key_id,
        current_user.id,
        request.expires_days
    )

    # Log API key rotation
    log_audit(
        db,
        action="rotate_api_key",
        user_id=current_user.id,
        username=current_user.username,
        resource=f"key_id_{key_id}",
        ip_address=http_request.client.host if http_request.client else None,
        success=success,
        error_message=None if success else message
    )

    if not success:
        raise HTTPException(status_code=404, detail=message)

    # Get the newly created key for response
    keys = list_api_keys(db, current_user.id)
    new_key = keys[0] if keys else None  # Most recent key

    return ApiKeyCreateResponse(
        success=True,
        message=message,
        api_key=plain_key,
        key_info=ApiKeyResponse(
            id=new_key.id,
            name=new_key.name,
            prefix=new_key.prefix,
            created_at=new_key.created_at.isoformat(),
            last_used_at=None,
            expires_at=new_key.expires_at.isoformat() if new_key.expires_at else None,
            is_active=new_key.is_active
        ) if new_key else None
    )


# Password Reset Routes


class ForgotPasswordRequest(BaseModel):
    """Forgot password request body."""
    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    """Forgot password response."""
    success: bool
    message: str


class VerifyResetTokenResponse(BaseModel):
    """Verify reset token response."""
    valid: bool
    message: str


class ResetPasswordRequest(BaseModel):
    """Reset password request body."""
    token: str
    new_password: str


class ResetPasswordResponse(BaseModel):
    """Reset password response."""
    success: bool
    message: str


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
async def forgot_password(
    request: ForgotPasswordRequest,
    http_request: Request,
    db = Depends(get_db)
):
    """Request a password reset email.

    Args:
        request: Forgot password request with email
        http_request: FastAPI request for IP address
        db: Database session

    Returns:
        Generic success message (to prevent email enumeration)
    """
    # Clean up expired tokens first
    cleanup_expired_reset_tokens(db)

    # Create reset token
    success, message, plain_token = create_password_reset_token(
        db,
        email=request.email,
        ip_address=http_request.client.host if http_request.client else None
    )

    # Log the attempt (without revealing if email exists)
    log_audit(
        db,
        action="forgot_password",
        resource=request.email,
        ip_address=http_request.client.host if http_request.client else None,
        success=True  # Always log as success to prevent enumeration
    )

    # Send email if token was created
    if plain_token:
        email_service = get_email_service()
        if email_service.is_configured():
            base_url = http_request.base_url.scheme + "://" + http_request.base_url.netloc

            # Get user for username (we know it exists if we have a token)
            user = db.query(User).filter_by(email=request.email).first()
            if user:
                await email_service.send_password_reset_email(
                    to_email=request.email,
                    username=user.username,
                    reset_token=plain_token,
                    base_url=str(base_url)
                )
        else:
            logger.warning("Email service not configured - cannot send password reset email")

    return ForgotPasswordResponse(
        success=True,
        message=message
    )


@router.get("/reset-password/verify/{token}", response_model=VerifyResetTokenResponse)
async def verify_password_reset_token(
    token: str,
    db = Depends(get_db)
):
    """Verify a password reset token is valid.

    Args:
        token: Password reset token
        db: Database session

    Returns:
        Token validity status
    """
    valid, message, _ = verify_reset_token(db, token)

    return VerifyResetTokenResponse(
        valid=valid,
        message=message
    )


@router.post("/reset-password", response_model=ResetPasswordResponse)
async def reset_password(
    request: ResetPasswordRequest,
    http_request: Request,
    db = Depends(get_db)
):
    """Reset password using a reset token.

    Args:
        request: Reset password request with token and new password
        http_request: FastAPI request for IP address
        db: Database session

    Returns:
        Success/failure message
    """
    # Validate password
    if len(request.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    # Reset password
    success, message = reset_password_with_token(
        db,
        token=request.token,
        new_password=request.new_password
    )

    # Log the attempt
    log_audit(
        db,
        action="reset_password",
        ip_address=http_request.client.host if http_request.client else None,
        success=success,
        error_message=None if success else message
    )

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return ResetPasswordResponse(
        success=True,
        message=message
    )


# Email Configuration Routes (Admin Only)


class EmailConfigRequest(BaseModel):
    """Email configuration request body."""
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    from_email: EmailStr
    from_name: str = "Infrastructure Toolkit"
    use_tls: bool = True
    use_ssl: bool = False


class EmailConfigResponse(BaseModel):
    """Email configuration response."""
    success: bool
    message: str
    is_configured: bool


class TestEmailRequest(BaseModel):
    """Test email request body."""
    to_email: EmailStr
    to_name: Optional[str] = None


class TestEmailResponse(BaseModel):
    """Test email response."""
    success: bool
    message: str


@router.post("/email/config", response_model=EmailConfigResponse)
async def configure_email(
    request: EmailConfigRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Configure email settings (admin only).

    Args:
        request: Email configuration
        http_request: FastAPI request for IP address
        current_user: Current authenticated user
        db: Database session

    Returns:
        Configuration success message
    """
    # Check if user is admin
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    # Create email config
    config = EmailConfig(
        smtp_host=request.smtp_host,
        smtp_port=request.smtp_port,
        smtp_user=request.smtp_user,
        smtp_password=request.smtp_password,
        from_email=request.from_email,
        from_name=request.from_name,
        use_tls=request.use_tls,
        use_ssl=request.use_ssl
    )

    # Configure email service
    configure_email_service(config)

    # Log the action
    log_audit(
        db,
        action="configure_email",
        user_id=current_user.id,
        username=current_user.username,
        resource=request.smtp_host,
        ip_address=http_request.client.host if http_request.client else None,
        success=True
    )

    logger.info(f"Email configured by {current_user.username}")

    return EmailConfigResponse(
        success=True,
        message="Email configuration updated successfully",
        is_configured=True
    )


@router.post("/email/test", response_model=TestEmailResponse)
async def send_test_email(
    request: TestEmailRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db)
):
    """Send a test email (admin only).

    Args:
        request: Test email request
        http_request: FastAPI request for IP address
        current_user: Current authenticated user
        db: Database session

    Returns:
        Test email send result
    """
    # Check if user is admin
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    # Get email service
    email_service = get_email_service()
    if not email_service.is_configured():
        raise HTTPException(status_code=400, detail="Email service not configured")

    # Send test email
    success = await email_service.send_test_email(
        to_email=request.to_email,
        to_name=request.to_name
    )

    # Log the action
    log_audit(
        db,
        action="send_test_email",
        user_id=current_user.id,
        username=current_user.username,
        resource=request.to_email,
        ip_address=http_request.client.host if http_request.client else None,
        success=success
    )

    if not success:
        raise HTTPException(status_code=500, detail="Failed to send test email")

    return TestEmailResponse(
        success=True,
        message=f"Test email sent successfully to {request.to_email}"
    )


@router.get("/email/status", response_model=EmailConfigResponse)
async def get_email_status(
    current_user: User = Depends(get_current_user)
):
    """Get email configuration status (admin only).

    Args:
        current_user: Current authenticated user

    Returns:
        Email configuration status
    """
    # Check if user is admin
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    email_service = get_email_service()
    is_configured = email_service.is_configured()

    return EmailConfigResponse(
        success=True,
        message="Email is configured" if is_configured else "Email is not configured",
        is_configured=is_configured
    )
