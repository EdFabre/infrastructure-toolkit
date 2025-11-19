"""Unit tests for NetworkTool."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from infra_toolkit.tools.network import NetworkTool


class TestNetworkTool:
    """Test suite for NetworkTool."""

    @patch('infra_toolkit.tools.network.requests.Session')
    def test_authenticate_success(self, mock_session_class, mock_config):
        """Test successful authentication."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'X-CSRF-Token': 'test-csrf-token'}
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        with patch('infra_toolkit.tools.network.load_config', return_value=mock_config):
            tool = NetworkTool()
            result = tool._authenticate()

            assert result is True
            assert tool.csrf_token == 'test-csrf-token'
            mock_session.post.assert_called_once()

    @patch('infra_toolkit.tools.network.requests.Session')
    def test_authenticate_failure(self, mock_session_class, mock_config):
        """Test authentication failure."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 401
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        with patch('infra_toolkit.tools.network.load_config', return_value=mock_config):
            tool = NetworkTool()
            result = tool._authenticate()

            assert result is False

    @patch('infra_toolkit.tools.network.NetworkTool._authenticate')
    @patch('infra_toolkit.tools.network.requests.Session.get')
    def test_get_system_health(self, mock_get, mock_auth, mock_network_health, mock_config):
        """Test getting system health."""
        mock_auth.return_value = True
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [mock_network_health]}
        mock_get.return_value = mock_response

        with patch('infra_toolkit.tools.network.load_config', return_value=mock_config):
            tool = NetworkTool()
            tool.session = Mock()
            tool.session.get = mock_get
            health = tool.get_system_health()

            assert health == mock_network_health

    @patch('infra_toolkit.tools.network.NetworkTool._authenticate')
    @patch('infra_toolkit.tools.network.requests.Session.get')
    def test_get_networks(self, mock_get, mock_auth, mock_config):
        """Test getting network configurations."""
        mock_auth.return_value = True
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "_id": "net1",
                    "name": "LAN",
                    "purpose": "corporate",
                    "vlan_enabled": False,
                    "domain_name": "home.lan"
                }
            ]
        }
        mock_get.return_value = mock_response

        with patch('infra_toolkit.tools.network.load_config', return_value=mock_config):
            tool = NetworkTool()
            tool.session = Mock()
            tool.session.get = mock_get
            networks = tool.get_networks()

            assert len(networks) == 1
            assert networks[0]["name"] == "LAN"

    @patch('infra_toolkit.tools.network.NetworkTool._authenticate')
    @patch('infra_toolkit.tools.network.requests.Session.get')
    def test_get_wifi_networks(self, mock_get, mock_auth, mock_config):
        """Test getting WiFi networks."""
        mock_auth.return_value = True
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "_id": "wlan1",
                    "name": "HomeWiFi",
                    "enabled": True,
                    "security": "wpapsk",
                    "minrate_ng_data_rate_kbps": 6000
                }
            ]
        }
        mock_get.return_value = mock_response

        with patch('infra_toolkit.tools.network.load_config', return_value=mock_config):
            tool = NetworkTool()
            tool.session = Mock()
            tool.session.get = mock_get
            wlans = tool.get_wifi_networks()

            assert len(wlans) == 1
            assert wlans[0]["name"] == "HomeWiFi"
            assert wlans[0]["enabled"] is True

    @patch('infra_toolkit.tools.network.NetworkTool._authenticate')
    @patch('infra_toolkit.tools.network.requests.Session.get')
    def test_get_devices(self, mock_get, mock_auth, mock_config):
        """Test getting network devices."""
        mock_auth.return_value = True
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "_id": "dev1",
                    "name": "U6-LR",
                    "type": "uap",
                    "model": "U6LR",
                    "ip": "192.168.1.10",
                    "mac": "00:11:22:33:44:55",
                    "state": 1,
                    "uptime": 86400
                }
            ]
        }
        mock_get.return_value = mock_response

        with patch('infra_toolkit.tools.network.load_config', return_value=mock_config):
            tool = NetworkTool()
            tool.session = Mock()
            tool.session.get = mock_get
            devices = tool.get_devices()

            assert len(devices) == 1
            assert devices[0]["name"] == "U6-LR"
            assert devices[0]["type"] == "uap"

    @patch('infra_toolkit.tools.network.NetworkTool._authenticate')
    @patch('infra_toolkit.tools.network.requests.Session.get')
    def test_get_clients(self, mock_get, mock_auth, mock_config):
        """Test getting network clients."""
        mock_auth.return_value = True
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "_id": "client1",
                    "hostname": "laptop",
                    "ip": "192.168.1.100",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "network": "LAN",
                    "is_wired": False,
                    "signal": -50,
                    "tx_bytes": 1000000,
                    "rx_bytes": 2000000
                }
            ]
        }
        mock_get.return_value = mock_response

        with patch('infra_toolkit.tools.network.load_config', return_value=mock_config):
            tool = NetworkTool()
            tool.session = Mock()
            tool.session.get = mock_get
            clients = tool.get_clients()

            assert len(clients) == 1
            assert clients[0]["hostname"] == "laptop"
            assert clients[0]["total_bytes"] == 3000000

    def test_health_check_authenticated(self, mock_config):
        """Test health check when authenticated."""
        with patch('infra_toolkit.tools.network.load_config', return_value=mock_config):
            with patch.object(NetworkTool, '_authenticate', return_value=True):
                tool = NetworkTool()
                health = tool.health_check()

                assert health["authenticated"] is True
                assert health["reachable"] is True

    def test_health_check_not_authenticated(self, mock_config):
        """Test health check when not authenticated."""
        with patch('infra_toolkit.tools.network.load_config', return_value=mock_config):
            with patch.object(NetworkTool, '_authenticate', return_value=False):
                tool = NetworkTool()
                health = tool.health_check()

                assert health["authenticated"] is False
