"""SSH command execution via paramiko — replaces subprocess ssh calls."""

import logging
import subprocess
from pathlib import Path
from typing import Optional

import paramiko

logger = logging.getLogger(__name__)

# Default SSH key path
DEFAULT_KEY_PATH = Path.home() / ".ssh" / "id_rsa"


def run_ssh_command(
    host: str,
    command: str,
    user: str = "root",
    key_path: Optional[Path] = None,
    timeout: int = 30,
    connect_timeout: int = 10,
) -> subprocess.CompletedProcess:
    """Execute a command on a remote host via SSH using paramiko.

    Returns a subprocess.CompletedProcess-compatible result so callers
    don't need to change their result handling.

    Args:
        host: Remote host IP or hostname.
        user: SSH user (default: root).
        command: Shell command string to execute.
        key_path: Path to SSH private key (default: ~/.ssh/id_rsa).
        timeout: Command execution timeout in seconds.
        connect_timeout: SSH connection timeout in seconds.

    Returns:
        CompletedProcess with stdout, stderr, returncode.
    """
    if key_path is None:
        key_path = DEFAULT_KEY_PATH

    logger.debug(f"SSH to {user}@{host}: {command}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            username=user,
            key_filename=str(key_path),
            timeout=connect_timeout,
            allow_agent=True,
            look_for_keys=True,
        )

        stdin, stdout_ch, stderr_ch = client.exec_command(command, timeout=timeout)
        stdout = stdout_ch.read().decode("utf-8", errors="replace")
        stderr = stderr_ch.read().decode("utf-8", errors="replace")
        returncode = stdout_ch.channel.recv_exit_status()

        return subprocess.CompletedProcess(
            args=command,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )
    finally:
        client.close()
