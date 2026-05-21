"""Smoke tests for PacketSentry TUI components.

Textual apps require an async event loop to run fully, but widget
classes and pure methods can be instantiated and called directly
without starting the app. These tests verify imports work, widget
classes are instantiable, and pure helper methods return expected types.
"""
from __future__ import annotations

import threading

import pytest


def test_dashboard_imports() -> None:
    """All TUI module symbols import without error."""
    from packetsentry.tui.dashboard import (
        AlertPanel,
        PacketSentryApp,
        StatsBar,
    )
    assert PacketSentryApp is not None
    assert StatsBar is not None
    assert AlertPanel is not None


def test_app_class_has_required_methods() -> None:
    """PacketSentryApp defines required lifecycle and action methods."""
    from packetsentry.tui.dashboard import PacketSentryApp

    assert hasattr(PacketSentryApp, "compose")
    assert hasattr(PacketSentryApp, "on_mount")
    assert hasattr(PacketSentryApp, "add_flow_row")
    assert hasattr(PacketSentryApp, "add_alert")
    assert hasattr(PacketSentryApp, "action_toggle_pause")
    assert hasattr(PacketSentryApp, "action_quit")


def test_app_bindings_defined() -> None:
    """PacketSentryApp exposes expected key bindings."""
    from packetsentry.tui.dashboard import PacketSentryApp

    keys = {b[0] for b in PacketSentryApp.BINDINGS}
    assert "q" in keys
    assert "p" in keys


def test_app_title_and_subtitle() -> None:
    """PacketSentryApp has TITLE and SUB_TITLE class attributes."""
    from packetsentry.tui.dashboard import PacketSentryApp

    assert isinstance(PacketSentryApp.TITLE, str)
    assert len(PacketSentryApp.TITLE) > 0
    assert isinstance(PacketSentryApp.SUB_TITLE, str)
    assert len(PacketSentryApp.SUB_TITLE) > 0


def test_app_instantiation_no_pipeline() -> None:
    """PacketSentryApp can be constructed without a pipeline or stop event."""
    from packetsentry.tui.dashboard import PacketSentryApp

    app = PacketSentryApp()
    assert app._pipeline is None
    assert isinstance(app._stop_event, threading.Event)
    assert app._paused is False


def test_app_instantiation_with_stop_event() -> None:
    """PacketSentryApp accepts a custom stop event."""
    from packetsentry.tui.dashboard import PacketSentryApp

    ev = threading.Event()
    app = PacketSentryApp(stop_event=ev)
    assert app._stop_event is ev


def test_stats_bar_instantiation() -> None:
    """StatsBar can be instantiated without a running app."""
    from packetsentry.tui.dashboard import StatsBar

    bar = StatsBar()
    assert bar is not None


def test_stats_bar_render_returns_string() -> None:
    """StatsBar.render() returns a non-empty string containing expected fields."""
    from packetsentry.tui.dashboard import StatsBar

    bar = StatsBar()
    result = bar.render()
    assert isinstance(result, str)
    assert "PKT" in result
    assert "FLW" in result
    assert "ALT" in result
    assert "pps" in result


def test_stats_bar_render_reflects_reactive_values() -> None:
    """StatsBar.render() incorporates current reactive attribute values."""
    from packetsentry.tui.dashboard import StatsBar

    bar = StatsBar()
    bar.packets = 1234
    bar.flows = 56
    bar.alerts = 7
    bar.pps = 99.5

    result = bar.render()
    assert "1,234" in result
    assert "56" in result
    assert "7" in result
    assert "100" in result or "99" in result  # formatted as pps:.0f


def test_alert_panel_instantiation() -> None:
    """AlertPanel can be instantiated without a running app."""
    from packetsentry.tui.dashboard import AlertPanel

    panel = AlertPanel()
    assert panel is not None
    assert panel._lines == []
    assert panel._max_lines == 200


def test_alert_panel_add_alert_populates_lines() -> None:
    """AlertPanel.add_alert() appends a formatted line to internal state."""
    from packetsentry.tui.dashboard import AlertPanel

    panel = AlertPanel()
    # update() requires a running Textual app; patch it out for unit testing
    panel.update = lambda *a, **kw: None  # type: ignore[method-assign]

    panel.add_alert("HIGH", 0.91, "192.168.1.10", "10.0.0.1", 443)
    assert len(panel._lines) == 1
    line = panel._lines[0]
    assert "HIGH" in line
    assert "192.168.1.10" in line
    assert "10.0.0.1" in line
    assert "443" in line
    assert "0.91" in line


def test_alert_panel_add_alert_all_severities() -> None:
    """AlertPanel.add_alert() handles all known severity levels."""
    from packetsentry.tui.dashboard import AlertPanel

    panel = AlertPanel()
    panel.update = lambda *a, **kw: None  # type: ignore[method-assign]

    for severity in ("CRITICAL", "HIGH", "MED", "LOW"):
        panel.add_alert(severity, 0.5, "1.2.3.4", "5.6.7.8", 80)

    assert len(panel._lines) == 4
    assert any("CRIT" in l for l in panel._lines)
    assert any("HIGH" in l for l in panel._lines)
    assert any("MED" in l for l in panel._lines)
    assert any("LOW" in l for l in panel._lines)


def test_alert_panel_unknown_severity() -> None:
    """AlertPanel.add_alert() handles unknown severity without raising."""
    from packetsentry.tui.dashboard import AlertPanel

    panel = AlertPanel()
    panel.update = lambda *a, **kw: None  # type: ignore[method-assign]

    panel.add_alert("UNKNOWN", 0.3, "1.1.1.1", "2.2.2.2", 22)
    assert len(panel._lines) == 1
    assert "???" in panel._lines[0]


def test_alert_panel_max_lines_enforced() -> None:
    """AlertPanel trims internal list to _max_lines when exceeded."""
    from packetsentry.tui.dashboard import AlertPanel

    panel = AlertPanel()
    panel.update = lambda *a, **kw: None  # type: ignore[method-assign]
    panel._max_lines = 10

    for i in range(15):
        panel.add_alert("LOW", 0.1, f"10.0.0.{i}", "8.8.8.8", 53)

    assert len(panel._lines) == 10
