"""API integration tests for performance endpoints."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from infra_toolkit.api.main import app


client = TestClient(app)


class TestPerformanceAPI:
    """Test suite for Performance API endpoints."""

    @patch('infra_toolkit.tools.performance.PerformanceTool.get_all_servers_metrics')
    def test_get_dashboard(self, mock_get_all, mock_server_metrics):
        """Test GET /api/perf/dashboard."""
        mock_get_all.return_value = [mock_server_metrics]

        response = client.get("/api/perf/dashboard")

        assert response.status_code == 200
        data = response.json()
        assert "servers" in data
        assert len(data["servers"]) == 1
        assert data["servers"][0]["server"] == "boss-01"

    @patch('infra_toolkit.tools.performance.PerformanceTool.get_server_metrics')
    def test_get_server_metrics(self, mock_get_metrics, mock_server_metrics):
        """Test GET /api/perf/servers/{server}/metrics."""
        mock_get_metrics.return_value = mock_server_metrics

        response = client.get("/api/perf/servers/boss-01/metrics")

        assert response.status_code == 200
        data = response.json()
        assert data["server"] == "boss-01"
        assert data["status"] == "healthy"
        assert "cpu_load" in data
        assert "memory" in data

    @patch('infra_toolkit.tools.performance.PerformanceTool.get_server_metrics')
    def test_get_server_metrics_unreachable(self, mock_get_metrics):
        """Test GET /api/perf/servers/{server}/metrics for unreachable server."""
        mock_get_metrics.return_value = {"reachable": False, "server": "boss-99"}

        response = client.get("/api/perf/servers/boss-99/metrics")

        assert response.status_code == 404
        assert "unreachable" in response.json()["detail"].lower()

    @patch('infra_toolkit.tools.performance.PerformanceTool.get_summary')
    def test_get_summary(self, mock_get_summary):
        """Test GET /api/perf/summary."""
        mock_get_summary.return_value = {
            "total_servers": 9,
            "healthy": 7,
            "warning": 1,
            "critical": 0,
            "unreachable": 1,
            "average_cpu_load": 0.5,
            "average_memory_percent": 60.0,
            "average_disk_percent": 50.0
        }

        response = client.get("/api/perf/summary")

        assert response.status_code == 200
        data = response.json()
        assert data["total_servers"] == 9
        assert data["healthy"] == 7
        assert data["warning"] == 1

    @patch('infra_toolkit.tools.performance.PerformanceTool.get_all_servers_metrics')
    def test_dashboard_error_handling(self, mock_get_all):
        """Test error handling in dashboard endpoint."""
        mock_get_all.side_effect = Exception("Connection error")

        response = client.get("/api/perf/dashboard")

        assert response.status_code == 500
        assert "error" in response.json()["detail"].lower()
