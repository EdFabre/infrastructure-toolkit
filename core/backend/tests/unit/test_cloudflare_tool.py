"""Unit tests for CloudflareTool."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from infra_toolkit.tools.cloudflare import CloudflareTool


class TestCloudflareTool:
    """Test suite for CloudflareTool."""

    @pytest.fixture
    def mock_tunnel_config(self):
        """Mock tunnel configuration."""
        return {
            "config": {
                "ingress": [
                    {"hostname": "radarr.haymoed.com", "service": "http://192.168.1.11:7878"},
                    {"hostname": "sonarr.haymoed.com", "service": "http://192.168.1.11:8989"},
                    {"service": "http_status:404"}
                ]
            }
        }

    @patch('infra_toolkit.tools.cloudflare.requests.get')
    def test_get_tunnel_config(self, mock_get, mock_config, mock_tunnel_config):
        """Test getting tunnel configuration."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": mock_tunnel_config}
        mock_get.return_value = mock_response

        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            tool = CloudflareTool(domain="haymoed")
            config = tool.get_tunnel_config()

            assert "config" in config
            assert "ingress" in config["config"]
            assert len(config["config"]["ingress"]) == 3

    @patch('infra_toolkit.tools.cloudflare.requests.get')
    def test_get_tunnel_config_error(self, mock_get, mock_config):
        """Test error handling in get_tunnel_config."""
        mock_get.side_effect = Exception("API Error")

        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            tool = CloudflareTool(domain="haymoed")

            with pytest.raises(Exception):
                tool.get_tunnel_config()

    def test_validate_tunnel_config_valid(self, mock_config, mock_tunnel_config):
        """Test validating a valid tunnel configuration."""
        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            with patch.object(CloudflareTool, 'get_tunnel_config', return_value=mock_tunnel_config):
                tool = CloudflareTool(domain="haymoed")
                is_valid, errors = tool.validate_tunnel_config()

                assert is_valid is True
                assert len(errors) == 0

    def test_validate_tunnel_config_missing_catch_all(self, mock_config):
        """Test validation fails without catch-all rule."""
        invalid_config = {
            "config": {
                "ingress": [
                    {"hostname": "test.haymoed.com", "service": "http://localhost:8080"}
                ]
            }
        }

        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            with patch.object(CloudflareTool, 'get_tunnel_config', return_value=invalid_config):
                tool = CloudflareTool(domain="haymoed")
                is_valid, errors = tool.validate_tunnel_config()

                assert is_valid is False
                assert any("catch-all" in error.lower() for error in errors)

    def test_validate_tunnel_config_too_few_hostnames(self, mock_config):
        """Test validation fails with too few hostnames."""
        minimal_config = {
            "config": {
                "ingress": [
                    {"hostname": "test.haymoed.com", "service": "http://localhost:8080"},
                    {"service": "http_status:404"}
                ]
            }
        }

        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            with patch.object(CloudflareTool, 'get_tunnel_config', return_value=minimal_config):
                tool = CloudflareTool(domain="haymoed")
                is_valid, errors = tool.validate_tunnel_config()

                assert is_valid is False
                assert any("minimum" in error.lower() for error in errors)

    @patch('infra_toolkit.tools.cloudflare.requests.put')
    def test_add_hostname(self, mock_put, mock_config, mock_tunnel_config):
        """Test adding a new hostname."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_put.return_value = mock_response

        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            with patch.object(CloudflareTool, 'get_tunnel_config', return_value=mock_tunnel_config):
                with patch.object(CloudflareTool, 'validate_tunnel_config', return_value=(True, [])):
                    tool = CloudflareTool(domain="haymoed")
                    result = tool.add_hostname("prowlarr", "192.168.1.11", 9696)

                    assert result is True

    @patch('infra_toolkit.tools.cloudflare.requests.get')
    def test_health_check_success(self, mock_get, mock_config):
        """Test successful health check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {"id": "test-tunnel-id"}}
        mock_get.return_value = mock_response

        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            tool = CloudflareTool(domain="haymoed")
            health = tool.health_check()

            assert health["api_reachable"] is True
            assert health["tunnel_accessible"] is True

    @patch('infra_toolkit.tools.cloudflare.requests.get')
    def test_health_check_failure(self, mock_get, mock_config):
        """Test failed health check."""
        mock_get.side_effect = Exception("Connection failed")

        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            tool = CloudflareTool(domain="haymoed")
            health = tool.health_check()

            assert health["api_reachable"] is False

    def test_get_current_state(self, mock_config, mock_tunnel_config):
        """Test getting current state."""
        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            with patch.object(CloudflareTool, 'get_tunnel_config', return_value=mock_tunnel_config):
                tool = CloudflareTool(domain="haymoed")
                state = tool.get_current_state()

                assert "config" in state
                assert "timestamp" in state

    def test_hostname_exists(self, mock_config, mock_tunnel_config):
        """Test checking if hostname exists."""
        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            with patch.object(CloudflareTool, 'get_tunnel_config', return_value=mock_tunnel_config):
                tool = CloudflareTool(domain="haymoed")

                # Hostname exists
                assert tool._hostname_exists("radarr.haymoed.com") is True

                # Hostname doesn't exist
                assert tool._hostname_exists("nonexistent.haymoed.com") is False

    def test_construct_service_url(self, mock_config):
        """Test constructing service URLs."""
        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            tool = CloudflareTool(domain="haymoed")

            # HTTP (default)
            url = tool._construct_service_url("192.168.1.11", 8080)
            assert url == "http://192.168.1.11:8080"

            # HTTPS
            url = tool._construct_service_url("192.168.1.11", 8080, protocol="https")
            assert url == "https://192.168.1.11:8080"

    def test_domain_selection(self, mock_config):
        """Test domain selection."""
        with patch('infra_toolkit.tools.cloudflare.load_config', return_value=mock_config):
            # Haymoed domain
            tool_haymoed = CloudflareTool(domain="haymoed")
            assert tool_haymoed.domain == "haymoed"

            # Ramcyber domain
            tool_ramcyber = CloudflareTool(domain="ramcyber")
            assert tool_ramcyber.domain == "ramcyber"
