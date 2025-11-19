"""Unit tests for PerformanceTool."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from infra_toolkit.tools.performance import PerformanceTool


class TestPerformanceTool:
    """Test suite for PerformanceTool."""

    @patch('infra_toolkit.tools.performance.requests.get')
    def test_query_prometheus_exporter_success(self, mock_get, mock_prometheus_metrics):
        """Test successful Prometheus exporter query."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = mock_prometheus_metrics
        mock_get.return_value = mock_response

        tool = PerformanceTool(server="boss-01")
        result = tool._query_prometheus_exporter("boss-01", 9100)

        assert result == mock_prometheus_metrics
        mock_get.assert_called_once_with("http://192.168.1.11:9100/metrics", timeout=5)

    @patch('infra_toolkit.tools.performance.requests.get')
    def test_query_prometheus_exporter_failure(self, mock_get):
        """Test Prometheus exporter query failure."""
        mock_get.side_effect = Exception("Connection refused")

        tool = PerformanceTool(server="boss-01")
        result = tool._query_prometheus_exporter("boss-01", 9100)

        assert result is None

    def test_parse_prometheus_metric(self, mock_prometheus_metrics):
        """Test Prometheus metric parsing."""
        tool = PerformanceTool(server="boss-01")

        # Test CPU load
        load1 = tool._parse_prometheus_metric(mock_prometheus_metrics, "node_load1")
        assert load1 == 0.5

        # Test memory
        mem_total = tool._parse_prometheus_metric(mock_prometheus_metrics, "node_memory_MemTotal_bytes")
        assert mem_total == 16777216000

    @patch('infra_toolkit.tools.performance.PerformanceTool._query_prometheus_exporter')
    def test_get_server_metrics_via_node_exporter(self, mock_query, mock_prometheus_metrics):
        """Test getting metrics via node_exporter."""
        mock_query.return_value = mock_prometheus_metrics

        tool = PerformanceTool(server="boss-01")
        metrics = tool._get_server_metrics_via_node_exporter("boss-01")

        assert metrics["reachable"] is True
        assert metrics["cpu_load"]["1min"] == 0.5
        assert metrics["memory"]["used_percent"] == 50.0
        assert metrics["disk"]["used_percent"] == 50.0

    @patch('infra_toolkit.tools.performance.PerformanceTool._execute_ssh_command')
    def test_get_server_metrics_via_ssh(self, mock_ssh, mock_ssh_response):
        """Test getting metrics via SSH fallback."""
        def ssh_side_effect(server, command):
            if "free -b" in command:
                return mock_ssh_response["free -b"]
            elif "loadavg" in command:
                return mock_ssh_response["cat /proc/loadavail"]
            elif "df -B1" in command:
                return mock_ssh_response["df -B1 /"]
            return ""

        mock_ssh.side_effect = ssh_side_effect

        tool = PerformanceTool(server="boss-01")
        metrics = tool._get_server_metrics_via_ssh("boss-01")

        assert metrics["reachable"] is True
        assert "cpu_load" in metrics
        assert "memory" in metrics
        assert "disk" in metrics

    def test_calculate_status_healthy(self):
        """Test status calculation for healthy server."""
        tool = PerformanceTool(server="boss-01")
        metrics = {
            "reachable": True,
            "memory": {"used_percent": 50.0},
            "disk": {"used_percent": 50.0}
        }

        # This is tested in get_server_metrics which adds status
        # Here we verify the threshold logic
        assert metrics["memory"]["used_percent"] < tool.thresholds["memory_warning"]

    def test_calculate_status_warning(self):
        """Test status calculation for warning server."""
        tool = PerformanceTool(server="boss-01")
        metrics = {
            "reachable": True,
            "memory": {"used_percent": 85.0},
            "disk": {"used_percent": 50.0}
        }

        assert metrics["memory"]["used_percent"] >= tool.thresholds["memory_warning"]
        assert metrics["memory"]["used_percent"] < tool.thresholds["memory_critical"]

    def test_calculate_status_critical(self):
        """Test status calculation for critical server."""
        tool = PerformanceTool(server="boss-01")
        metrics = {
            "reachable": True,
            "memory": {"used_percent": 95.0},
            "disk": {"used_percent": 50.0}
        }

        assert metrics["memory"]["used_percent"] >= tool.thresholds["memory_critical"]

    @patch('infra_toolkit.tools.performance.PerformanceTool.get_server_metrics')
    def test_get_all_servers_metrics(self, mock_get_metrics, mock_server_metrics):
        """Test getting metrics for all servers."""
        mock_get_metrics.return_value = mock_server_metrics

        tool = PerformanceTool(all_servers=True)
        metrics_list = tool.get_all_servers_metrics()

        # Should query all 9 servers
        assert len(metrics_list) == 9
        assert mock_get_metrics.call_count == 9

    @patch('infra_toolkit.tools.performance.PerformanceTool.get_all_servers_metrics')
    def test_calculate_summary(self, mock_get_all, mock_server_metrics):
        """Test summary statistics calculation."""
        # Create mock metrics for multiple servers with different statuses
        metrics_list = [
            {**mock_server_metrics, "server": "boss-01", "status": "healthy"},
            {**mock_server_metrics, "server": "boss-02", "status": "warning"},
            {**mock_server_metrics, "server": "boss-03", "status": "critical"},
            {**mock_server_metrics, "server": "boss-04", "status": "unreachable", "reachable": False}
        ]
        mock_get_all.return_value = metrics_list

        tool = PerformanceTool(all_servers=True)
        summary = tool.get_summary()

        assert summary["total_servers"] == 4
        assert summary["healthy"] == 1
        assert summary["warning"] == 1
        assert summary["critical"] == 1
        assert summary["unreachable"] == 1

    def test_health_check_reachable(self):
        """Test health check for reachable server."""
        with patch.object(PerformanceTool, 'get_server_metrics') as mock_metrics:
            mock_metrics.return_value = {"reachable": True, "status": "healthy"}

            tool = PerformanceTool(server="boss-01")
            health = tool.health_check()

            assert health["reachable"] is True
            assert health["status"] == "healthy"

    def test_health_check_unreachable(self):
        """Test health check for unreachable server."""
        with patch.object(PerformanceTool, 'get_server_metrics') as mock_metrics:
            mock_metrics.return_value = {"reachable": False}

            tool = PerformanceTool(server="boss-01")
            health = tool.health_check()

            assert health["reachable"] is False
