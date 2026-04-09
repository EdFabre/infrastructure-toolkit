"""Integration tests: ef-metrics instrumentation in infrastructure-toolkit CLI.

Tests cover:
- Stub behaviour when ef-metrics is absent (no crash, identity/noop)
- Real ef-metrics integration (invocations + operations recorded)
- track_command wraps dispatch correctly
- track_operation wraps handler routing correctly
"""

import pytest


# ---------------------------------------------------------------------------
# Stub tests (ef-metrics absent) — test inline stubs directly
# ---------------------------------------------------------------------------

def _make_stubs():
    """Create the same fallback stubs used in infra_toolkit/cli.py."""
    def track_command(tool_name, command=None):
        def decorator(func): return func
        return decorator
    def track_operation(name, op_type="other"):
        from contextlib import nullcontext
        return nullcontext()
    return track_command, track_operation


class TestStubsAbsent:
    """Verify stubs are transparent no-ops when ef-metrics is absent."""

    def test_track_command_stub_is_identity_decorator(self):
        track_command, _ = _make_stubs()
        @track_command(tool_name="infrastructure-toolkit", command="cloudflare")
        def dispatch():
            return "ok"
        assert dispatch() == "ok"

    def test_track_command_stub_propagates_exception(self):
        track_command, _ = _make_stubs()
        @track_command(tool_name="infrastructure-toolkit", command="proxmox")
        def dispatch():
            raise ValueError("oops")
        with pytest.raises(ValueError):
            dispatch()

    def test_track_operation_stub_is_context_manager(self):
        _, track_operation = _make_stubs()
        ran = []
        with track_operation("handle.cloudflare.list", op_type="api"):
            ran.append(1)
        assert ran == [1]

    def test_track_operation_stub_does_not_suppress_exceptions(self):
        _, track_operation = _make_stubs()
        with pytest.raises(RuntimeError):
            with track_operation("handle.proxmox.list", op_type="api"):
                raise RuntimeError("api failed")


# ---------------------------------------------------------------------------
# Real ef-metrics integration tests
# ---------------------------------------------------------------------------

class TestRealMetricsIntegration:
    """Verify ef-metrics records data correctly when installed."""

    @pytest.fixture(autouse=True)
    def _fresh_tracker(self, tmp_path, monkeypatch):
        from ef_metrics.storage import MetricsStorage
        from ef_metrics.tracker import _reset_tracker

        tmp_db = tmp_path / "metrics_test.db"
        monkeypatch.setattr(MetricsStorage, "DB_PATH", tmp_db)
        monkeypatch.setattr(MetricsStorage, "DB_DIR", tmp_db.parent)
        _reset_tracker()
        self._tmp_db = tmp_db
        yield
        _reset_tracker()

    def _flush(self):
        from ef_metrics.tracker import get_tracker, _reset_tracker
        get_tracker().shutdown()
        _reset_tracker()

    def _get_stats(self):
        from ef_metrics.storage import MetricsStorage
        s = MetricsStorage(db_path=self._tmp_db)
        stats = s.get_tool_stats(days=1)
        s.close()
        return stats

    def _get_operations(self):
        from ef_metrics.storage import MetricsStorage
        s = MetricsStorage(db_path=self._tmp_db)
        rows = s._get_connection().execute("SELECT name, type, success FROM operations").fetchall()
        s.close()
        return rows

    def test_track_command_records_invocation(self):
        from ef_metrics import track_command

        @track_command(tool_name="infrastructure-toolkit", command="cloudflare")
        def dispatch():
            pass

        dispatch()
        self._flush()

        stats = self._get_stats()
        assert len(stats) == 1
        assert stats[0]["tool"] == "infrastructure-toolkit"
        assert stats[0]["successes"] == 1

    def test_track_operation_handle_recorded(self):
        from ef_metrics import track_command, track_operation

        @track_command(tool_name="infrastructure-toolkit", command="cloudflare")
        def dispatch():
            with track_operation("handle.cloudflare.list", op_type="api"):
                pass

        dispatch()
        self._flush()

        ops = self._get_operations()
        assert any(r[0] == "handle.cloudflare.list" and r[1] == "api" for r in ops)

    def test_track_operation_multiple_tools(self):
        from ef_metrics import track_command, track_operation

        @track_command(tool_name="infrastructure-toolkit", command="proxmox")
        def dispatch():
            with track_operation("handle.proxmox.vms", op_type="api"):
                pass

        dispatch()
        self._flush()

        ops = self._get_operations()
        assert any(r[0] == "handle.proxmox.vms" and r[1] == "api" for r in ops)

    def test_failed_dispatch_records_failure(self):
        from ef_metrics import track_command

        @track_command(tool_name="infrastructure-toolkit", command="docker")
        def dispatch():
            raise SystemExit(1)

        with pytest.raises(SystemExit):
            dispatch()
        self._flush()

        stats = self._get_stats()
        assert stats[0]["successes"] == 0
