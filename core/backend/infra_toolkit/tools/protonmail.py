"""
ProtonMail Bridge Service Tool

End-to-end SMTP and IMAP connectivity testing for ProtonMail Bridge.

Features:
- Docker container health check on boss-04
- SMTP authentication and optional test email
- IMAP authentication and mailbox listing
"""

import logging
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import yaml

from ..base_tool import BaseTool

logger = logging.getLogger(__name__)


class ProtonMailTool(BaseTool):
    """
    ProtonMail Bridge connectivity tester.

    Tests end-to-end SMTP and IMAP connectivity for ProtonMail Bridge
    running on boss-04, including Docker container status verification.
    """

    def __init__(self, config: Dict[str, Any], **kwargs):
        super().__init__(config, **kwargs)
        self.pm_config = config.get("protonmail", {})
        self.host = self.pm_config.get("host", "192.168.1.14")
        self.smtp_port = self.pm_config.get("smtp", {}).get("port")
        self.imap_port = self.pm_config.get("imap", {}).get("port")
        self.username = self.pm_config.get("credentials", {}).get("username", "")
        self.password = self.pm_config.get("credentials", {}).get("password", "")
        self.container_name = self.pm_config.get("docker", {}).get(
            "container_name", "protonmail"
        )
        self.compose_path = self.pm_config.get("docker", {}).get(
            "compose_path", "/opt/docker"
        )

    @classmethod
    def configure_parser(cls, parser):
        super().configure_parser(parser)
        subs = parser.add_subparsers(
            dest="subcommand", help="ProtonMail subcommands"
        )
        test_parser = subs.add_parser(
            "test", help="Test SMTP and IMAP connectivity"
        )
        test_parser.add_argument(
            "--smtp", action="store_true", help="Test only SMTP"
        )
        test_parser.add_argument(
            "--imap", action="store_true", help="Test only IMAP"
        )
        test_parser.add_argument(
            "--send-test",
            action="store_true",
            help="Actually send a test email",
        )
        test_parser.add_argument(
            "--no-container-check",
            action="store_true",
            help="Skip Docker container check",
        )
        subs.add_parser("health-check", help="Check container and port status")

    def check_container(self) -> Tuple[bool, str]:
        """Check if ProtonMail Docker container is running."""
        try:
            cmd = [
                "ssh",
                "-o", "ConnectTimeout=5",
                "-o", "BatchMode=yes",
                f"root@{self.host}",
                f'docker ps --filter name={self.container_name} --format "{{{{.Status}}}}"',
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return False, f"Failed to connect to {self.host}"

            status = result.stdout.strip()
            if not status:
                return False, f"Container '{self.container_name}' is not running"

            return True, f"Container running: {status}"

        except subprocess.TimeoutExpired:
            return False, f"SSH timeout connecting to {self.host}"
        except Exception as e:
            return False, str(e)

    def test_smtp(self, send_test: bool = False) -> Tuple[bool, str]:
        """Test SMTP connectivity via SSH to boss-04."""
        if not all([self.smtp_port, self.username, self.password]):
            return False, "Missing SMTP configuration"

        send_block = ""
        if send_test:
            send_block = f"""
msg = MIMEText('ProtonMail Bridge test email sent at ' + str(__import__('datetime').datetime.now()))
msg['Subject'] = 'ProtonMail Bridge Test'
msg['From'] = '{self.username}'
msg['To'] = '{self.username}'
server.send_message(msg)
print('Test email sent')
"""

        script = f"""import smtplib
from email.mime.text import MIMEText
try:
    server = smtplib.SMTP("localhost", {self.smtp_port})
    print("Connected to SMTP server")
    server.starttls()
    print("TLS started")
    server.login("{self.username}", "{self.password}")
    print("SMTP authentication successful")
    {send_block}
    server.quit()
except Exception as e:
    print("SMTP Error: " + str(e))
    exit(1)
"""
        return self._run_remote_script(script)

    def test_imap(self) -> Tuple[bool, str]:
        """Test IMAP connectivity via SSH to boss-04."""
        if not all([self.imap_port, self.username, self.password]):
            return False, "Missing IMAP configuration"

        script = f"""import imaplib, ssl
try:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    imap = imaplib.IMAP4("localhost", {self.imap_port})
    print("Connected to IMAP server")
    imap.starttls(ssl_context=context)
    print("TLS started")
    imap.login("{self.username}", "{self.password}")
    print("IMAP authentication successful")
    status, mailboxes = imap.list()
    if status == "OK":
        print("Mailboxes: " + str(len(mailboxes)))
    status, data = imap.select("INBOX")
    if status == "OK":
        print("INBOX messages: " + data[0].decode())
    imap.logout()
except Exception as e:
    print("IMAP Error: " + str(e))
    exit(1)
"""
        return self._run_remote_script(script)

    def _run_remote_script(self, script: str) -> Tuple[bool, str]:
        """Execute a Python script remotely on boss-04 via SSH."""
        try:
            temp_path = "/tmp/_infra_toolkit_test.py"
            # Write script via stdin
            write_proc = subprocess.run(
                [
                    "ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
                    f"root@{self.host}",
                    f"cat > {temp_path}",
                ],
                input=script,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if write_proc.returncode != 0:
                return False, f"Failed to write script: {write_proc.stderr}"

            # Execute and clean up
            result = subprocess.run(
                [
                    "ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
                    f"root@{self.host}",
                    f"python3 {temp_path}; rm -f {temp_path}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            output = result.stdout.strip()
            if result.returncode == 0:
                return True, output
            else:
                error = result.stderr.strip() or output
                return False, error

        except subprocess.TimeoutExpired:
            return False, "SSH timeout"
        except Exception as e:
            return False, str(e)

    def health_check(self) -> Dict[str, Any]:
        """Run all health checks."""
        checks = {}

        container_ok, container_msg = self.check_container()
        checks["container"] = {"status": container_ok, "message": container_msg}

        if container_ok:
            smtp_ok, smtp_msg = self.test_smtp()
            checks["smtp"] = {"status": smtp_ok, "message": smtp_msg}

            imap_ok, imap_msg = self.test_imap()
            checks["imap"] = {"status": imap_ok, "message": imap_msg}

            all_ok = container_ok and smtp_ok and imap_ok
        else:
            all_ok = False

        return {
            "status": "healthy" if all_ok else "unhealthy",
            "message": "All ProtonMail checks passed" if all_ok else "Some checks failed",
            "checks": checks,
        }
