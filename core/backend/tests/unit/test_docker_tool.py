"""Unit tests for DockerTool."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from infra_toolkit.tools.docker import DockerTool


class TestDockerTool:
    """Test suite for DockerTool."""

    @patch('infra_toolkit.tools.docker.subprocess.run')
    def test_get_running_services_local(self, mock_run, mock_docker_containers):
        """Test getting running services locally."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = '\n'.join([
            '{"Name":"radarr","Image":"linuxserver/radarr:latest","Status":"Up 2 days","State":"running"}',
            '{"Name":"sonarr","Image":"linuxserver/sonarr:latest","Status":"Up 2 days","State":"running"}'
        ])
        mock_run.return_value = mock_result

        tool = DockerTool(server="localhost")
        containers = tool.get_running_services()

        assert len(containers) == 2
        assert containers[0]["name"] == "radarr"
        assert containers[1]["name"] == "sonarr"

    @patch('infra_toolkit.tools.docker.DockerTool._execute_ssh_command')
    def test_get_running_services_remote(self, mock_ssh, mock_docker_containers):
        """Test getting running services via SSH."""
        mock_ssh.return_value = '\n'.join([
            '{"Name":"radarr","Image":"linuxserver/radarr:latest","Status":"Up 2 days","State":"running"}',
            '{"Name":"sonarr","Image":"linuxserver/sonarr:latest","Status":"Up 2 days","State":"running"}'
        ])

        tool = DockerTool(server="boss-01")
        containers = tool.get_running_services()

        assert len(containers) == 2
        assert containers[0]["server"] == "boss-01"

    @patch('infra_toolkit.tools.docker.DockerTool._execute_ssh_command')
    def test_get_all_running_services(self, mock_ssh):
        """Test getting services from all servers."""
        mock_ssh.return_value = '{"Name":"test","Image":"test:latest","Status":"Up","State":"running"}'

        tool = DockerTool(all_servers=True)
        containers = tool.get_all_running_services()

        # Should query all 9 servers
        assert len(containers) >= 9

    @patch('infra_toolkit.tools.docker.subprocess.run')
    def test_get_container_logs(self, mock_run):
        """Test getting container logs."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Log line 1\nLog line 2\nLog line 3"
        mock_run.return_value = mock_result

        tool = DockerTool(server="localhost")
        logs = tool.get_container_logs("radarr", tail=100)

        assert "Log line 1" in logs
        assert "Log line 2" in logs
        mock_run.assert_called_once()

    @patch('infra_toolkit.tools.docker.Path.exists')
    @patch('infra_toolkit.tools.docker.Path.read_text')
    def test_validate_compose_file_valid(self, mock_read, mock_exists):
        """Test validating a valid docker-compose file."""
        mock_exists.return_value = True
        mock_read.return_value = """
version: '3.8'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
"""

        tool = DockerTool(server="localhost")
        is_valid, errors = tool.validate_compose_file(Path("/test/docker-compose.yml"))

        assert is_valid is True
        assert len(errors) == 0

    @patch('infra_toolkit.tools.docker.Path.exists')
    @patch('infra_toolkit.tools.docker.Path.read_text')
    def test_validate_compose_file_invalid(self, mock_read, mock_exists):
        """Test validating an invalid docker-compose file."""
        mock_exists.return_value = True
        mock_read.return_value = "invalid: yaml: content: ["

        tool = DockerTool(server="localhost")
        is_valid, errors = tool.validate_compose_file(Path("/test/docker-compose.yml"))

        assert is_valid is False
        assert len(errors) > 0

    @patch('infra_toolkit.tools.docker.subprocess.run')
    def test_health_check_healthy(self, mock_run):
        """Test health check for healthy Docker daemon."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Docker info output"
        mock_run.return_value = mock_result

        with patch.object(DockerTool, 'validate_compose_file', return_value=(True, [])):
            with patch.object(DockerTool, 'get_running_services', return_value=[{"name": "test"}]):
                tool = DockerTool(server="localhost")
                health = tool.health_check()

                assert health["status"] == "healthy"
                assert health["checks"]["docker_running"] is True

    @patch('infra_toolkit.tools.docker.subprocess.run')
    def test_health_check_unhealthy(self, mock_run):
        """Test health check for unhealthy Docker daemon."""
        mock_run.side_effect = Exception("Docker not running")

        tool = DockerTool(server="localhost")
        health = tool.health_check()

        assert health["status"] == "unhealthy"
        assert health["checks"]["docker_running"] is False

    @patch('infra_toolkit.tools.docker.DockerTool.get_running_services')
    def test_get_current_state(self, mock_get_services):
        """Test capturing current state."""
        mock_get_services.return_value = [
            {"name": "radarr", "state": "running"},
            {"name": "sonarr", "state": "running"}
        ]

        tool = DockerTool(server="localhost")
        state = tool.get_current_state()

        assert "services" in state
        assert len(state["services"]) == 2

    def test_resolve_server_address(self):
        """Test server address resolution."""
        tool = DockerTool(server="boss-01")
        ip = tool._resolve_server_address("boss-01")

        assert ip == "192.168.1.11"

    def test_resolve_server_address_ip(self):
        """Test server address resolution with IP."""
        tool = DockerTool(server="boss-01")
        ip = tool._resolve_server_address("192.168.1.11")

        assert ip == "192.168.1.11"
