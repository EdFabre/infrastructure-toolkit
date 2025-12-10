"""Email notification service for Infrastructure Toolkit.

This module provides email sending capabilities using aiosmtplib for async SMTP operations.
Supports multiple SMTP servers including ProtonMail Bridge and standard SMTP servers.
"""

import logging
import os
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Optional, Dict, Any
import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)


class EmailConfig:
    """Email configuration container."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        from_email: str,
        from_name: str = "Infrastructure Toolkit",
        use_tls: bool = True,
        use_ssl: bool = False
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_email = from_email
        self.from_name = from_name
        self.use_tls = use_tls
        self.use_ssl = use_ssl

    @classmethod
    def from_env(cls) -> Optional["EmailConfig"]:
        """Load email configuration from environment variables.

        Expected environment variables:
        - SMTP_HOST: SMTP server hostname
        - SMTP_PORT: SMTP server port (default: 587)
        - SMTP_USER: SMTP username
        - SMTP_PASSWORD: SMTP password
        - SMTP_FROM_EMAIL: From email address
        - SMTP_FROM_NAME: From name (default: "Infrastructure Toolkit")
        - SMTP_USE_TLS: Use TLS (default: true)
        - SMTP_USE_SSL: Use SSL (default: false)

        Returns:
            EmailConfig instance or None if required vars are missing
        """
        smtp_host = os.getenv("SMTP_HOST")
        smtp_user = os.getenv("SMTP_USER")
        smtp_password = os.getenv("SMTP_PASSWORD")
        from_email = os.getenv("SMTP_FROM_EMAIL")

        if not all([smtp_host, smtp_user, smtp_password, from_email]):
            logger.warning("Missing required SMTP environment variables")
            return None

        return cls(
            smtp_host=smtp_host,
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_user=smtp_user,
            smtp_password=smtp_password,
            from_email=from_email,
            from_name=os.getenv("SMTP_FROM_NAME", "Infrastructure Toolkit"),
            use_tls=os.getenv("SMTP_USE_TLS", "true").lower() == "true",
            use_ssl=os.getenv("SMTP_USE_SSL", "false").lower() == "true"
        )


class EmailService:
    """Email sending service using aiosmtplib."""

    def __init__(self, config: Optional[EmailConfig] = None):
        """Initialize email service.

        Args:
            config: Email configuration. If None, will attempt to load from env.
        """
        self.config = config or EmailConfig.from_env()
        self.templates_dir = Path(__file__).parent / "templates" / "email"

        # Initialize Jinja2 environment for email templates
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )

    async def send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
        to_name: Optional[str] = None
    ) -> bool:
        """Send an email.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text email body (optional, falls back to html_body)
            to_name: Recipient name (optional)

        Returns:
            True if email sent successfully, False otherwise
        """
        if not self.config:
            logger.error("Email service not configured")
            return False

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.config.from_name} <{self.config.from_email}>"
            msg['To'] = f"{to_name} <{to_email}>" if to_name else to_email
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')

            # Add plain text part
            text_part = MIMEText(text_body or html_body, 'plain', 'utf-8')
            msg.attach(text_part)

            # Add HTML part
            html_part = MIMEText(html_body, 'html', 'utf-8')
            msg.attach(html_part)

            # Send email
            if self.config.use_ssl:
                await aiosmtplib.send(
                    msg,
                    hostname=self.config.smtp_host,
                    port=self.config.smtp_port,
                    username=self.config.smtp_user,
                    password=self.config.smtp_password,
                    use_tls=False,
                    start_tls=False
                )
            else:
                await aiosmtplib.send(
                    msg,
                    hostname=self.config.smtp_host,
                    port=self.config.smtp_port,
                    username=self.config.smtp_user,
                    password=self.config.smtp_password,
                    use_tls=self.config.use_tls,
                    start_tls=self.config.use_tls
                )

            logger.info(f"Email sent successfully to {to_email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False

    async def send_template_email(
        self,
        to_email: str,
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        to_name: Optional[str] = None
    ) -> bool:
        """Send an email using a Jinja2 template.

        Args:
            to_email: Recipient email address
            subject: Email subject
            template_name: Name of template file (without extension)
            context: Template context variables
            to_name: Recipient name (optional)

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            # Render HTML template
            html_template = self.jinja_env.get_template(f"{template_name}.html")
            html_body = html_template.render(**context)

            # Render text template (if exists)
            text_body = None
            try:
                text_template = self.jinja_env.get_template(f"{template_name}.txt")
                text_body = text_template.render(**context)
            except Exception:
                logger.debug(f"No text template found for {template_name}")

            return await self.send_email(
                to_email=to_email,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
                to_name=to_name
            )

        except Exception as e:
            logger.error(f"Failed to render email template {template_name}: {e}")
            return False

    async def send_password_reset_email(
        self,
        to_email: str,
        username: str,
        reset_token: str,
        base_url: str
    ) -> bool:
        """Send a password reset email.

        Args:
            to_email: User's email address
            username: User's username
            reset_token: Password reset token
            base_url: Base URL of the application

        Returns:
            True if email sent successfully, False otherwise
        """
        reset_link = f"{base_url}/reset-password/{reset_token}"

        context = {
            "username": username,
            "reset_link": reset_link,
            "expiry_hours": 1,
            "current_year": datetime.utcnow().year
        }

        return await self.send_template_email(
            to_email=to_email,
            subject="Password Reset Request - Infrastructure Toolkit",
            template_name="password_reset",
            context=context,
            to_name=username
        )

    async def send_test_email(
        self,
        to_email: str,
        to_name: Optional[str] = None
    ) -> bool:
        """Send a test email to verify SMTP configuration.

        Args:
            to_email: Recipient email address
            to_name: Recipient name (optional)

        Returns:
            True if email sent successfully, False otherwise
        """
        context = {
            "test_time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            "smtp_host": self.config.smtp_host if self.config else "Unknown",
            "smtp_port": self.config.smtp_port if self.config else "Unknown",
            "current_year": datetime.utcnow().year
        }

        return await self.send_template_email(
            to_email=to_email,
            subject="Test Email - Infrastructure Toolkit",
            template_name="test_email",
            context=context,
            to_name=to_name
        )

    def is_configured(self) -> bool:
        """Check if email service is properly configured.

        Returns:
            True if configured, False otherwise
        """
        return self.config is not None


# Global email service instance
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Get the global email service instance.

    Returns:
        EmailService instance
    """
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service


def configure_email_service(config: EmailConfig) -> None:
    """Configure the global email service instance.

    Args:
        config: Email configuration
    """
    global _email_service
    _email_service = EmailService(config)
