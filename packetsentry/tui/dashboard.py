"""Textual TUI Dashboard — real-time PacketSentry monitor.

Renders a terminal UI with:
  - Header bar: packets/sec, bytes/sec, alert count
  - Flow log: scrolling table of recent flows
  - Alert panel: colour-coded alerts with SHAP explanations
  - Footer: keybinding hints

Runs in the main thread. Capture runs in a background Worker.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Static

_SPARK_CHARS = " ▁▂▃▄▅▆▇█"

if TYPE_CHECKING:
    from packetsentry.capture.pipeline import DetectionPipeline


class StatsBar(Static):
    """Header status bar showing live statistics."""

    packets = reactive(0)
    flows = reactive(0)
    alerts = reactive(0)
    pps = reactive(0.0)

    def render(self) -> str:
        return (
            f" [>] PKT: [bold #00FF41]{self.packets:,}[/] | "
            f"FLW: [bold #00FF41]{self.flows:,}[/] | "
            f"ALT: [bold red]{self.alerts:,}[/] | "
            f"[#00FF41]{self.pps:.0f} pps[/#00FF41]"
        )


class SparklineChart(Static):
    """Rolling sparkline chart for packets-per-second and alert rate.

    Maintains a 60-sample history (30 s at the default 0.5 s tick) and
    renders two ASCII spark lines — one for PPS, one for alert deltas.
    """

    _HISTORY = 64  # samples to keep

    DEFAULT_CSS = """
    SparklineChart {
        height: 4;
        padding: 0 2;
        background: #000000;
        border-bottom: heavy #00FF41;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._pps: list[float] = []
        self._alert_deltas: list[int] = []
        self._prev_alerts: int = 0

    def push(self, pps: float, total_alerts: int) -> None:
        """Record a new sample and refresh the widget."""
        self._pps.append(pps)
        if len(self._pps) > self._HISTORY:
            self._pps = self._pps[-self._HISTORY:]

        delta = max(0, total_alerts - self._prev_alerts)
        self._prev_alerts = total_alerts
        self._alert_deltas.append(delta)
        if len(self._alert_deltas) > self._HISTORY:
            self._alert_deltas = self._alert_deltas[-self._HISTORY:]

        self.refresh()

    @staticmethod
    def _spark(values: list[float], width: int) -> str:
        """Convert a list of floats into a fixed-width sparkline string."""
        if not values:
            return _SPARK_CHARS[0] * width
        # right-align: pad left with blanks if history shorter than width
        padded: list[float] = (
            [0.0] * (width - len(values)) + values[-width:]
            if len(values) < width
            else values[-width:]
        )
        peak = max(padded) or 1.0
        n = len(_SPARK_CHARS) - 1
        return "".join(_SPARK_CHARS[min(int(v / peak * n), n)] for v in padded)

    def render(self) -> str:
        width = 64
        pps_line = self._spark(self._pps, width)
        alt_line = self._spark([float(x) for x in self._alert_deltas], width)
        peak_pps = max(self._pps) if self._pps else 0.0
        total = self._prev_alerts
        return (
            f" [#555555]PPS [/#555555][#00FF41]{pps_line}[/#00FF41] "
            f"[#555555]peak {peak_pps:.0f}/s[/#555555]\n"
            f" [#555555]ALT [/#555555][#FF4500]{alt_line}[/#FF4500] "
            f"[#555555]total {total}[/#555555]"
        )


class AlertPanel(Static):
    """Scrolling panel of recent alerts."""

    DEFAULT_CSS = """
    AlertPanel {
        height: 100%;
        border: heavy #00FF41;
        background: #1a1a1a;
        padding: 0 1;
        overflow-y: auto;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._lines: list[str] = []
        self._max_lines = 200

    def add_alert(self, severity: str, confidence: float, src: str, dst: str, port: int) -> None:
        tags = {"CRITICAL": "[CRIT]", "HIGH": "[HIGH]", "MED": "[MED]", "LOW": "[LOW]"}
        colors = {"CRITICAL": "#FF0000", "HIGH": "#FF8C00", "MED": "#00FF41", "LOW": "white"}
        tag = tags.get(severity, "[???]")
        color = colors.get(severity, "white")
        ts = time.strftime("%H:%M:%S")

        line = f"[{color}]{tag} {ts} {severity:<8} {src} -> {dst}:{port}  conf={confidence:.2f}[/{color}]"
        self._lines.append(line)
        if len(self._lines) > self._max_lines:
            self._lines = self._lines[-self._max_lines:]
        self.update("\n".join(self._lines[-30:]))  # show last 30


class PacketSentryApp(App):
    """Main Textual application for PacketSentry.

    Args:
        pipeline: The DetectionPipeline instance to monitor.
        stop_event: Threading event to signal capture shutdown.
    """

    CSS = """
    Screen {
        layout: vertical;
        background: #1a1a1a;
    }
    #stats-bar {
        dock: top;
        height: 3;
        padding: 0 2;
        background: #000000;
        border-bottom: heavy #00FF41;
    }
    #main-container {
        height: 1fr;
    }
    #flow-table-container {
        width: 2fr;
        height: 100%;
        border: heavy white;
    }
    #alert-container {
        width: 1fr;
        height: 100%;
    }
    DataTable {
        height: 100%;
        background: #1a1a1a;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("p", "toggle_pause", "Pause/Resume"),
    ]

    TITLE = "PACKETSENTRY // NIDS"
    SUB_TITLE = "7-MODEL ENSEMBLE :: REAL-TIME DETECTION"

    def __init__(
        self,
        pipeline: "DetectionPipeline | None" = None,
        stop_event: threading.Event | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._pipeline = pipeline
        self._stop_event = stop_event or threading.Event()
        self._paused = False
        self._last_packet_count = 0
        self._last_check_time = time.monotonic()

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatsBar(id="stats-bar")
        yield SparklineChart(id="chart")
        with Horizontal(id="main-container"):
            with Vertical(id="flow-table-container"):
                yield DataTable(id="flow-table")
            with Vertical(id="alert-container"):
                yield AlertPanel(id="alert-panel")
        yield Footer()

    def on_mount(self) -> None:
        # Setup flow table columns
        table = self.query_one("#flow-table", DataTable)
        table.add_columns("Time", "Source", "Destination", "Proto", "Bytes", "Score")
        table.cursor_type = "row"

        # Start periodic stats update
        self.set_interval(0.5, self._update_stats)

    def _update_stats(self) -> None:
        """Periodically refresh the stats bar from the pipeline."""
        if self._pipeline is None:
            return

        stats = self._pipeline.stats()
        bar = self.query_one("#stats-bar", StatsBar)
        bar.packets = stats["packets"]
        bar.flows = stats["completed_flows"]
        bar.alerts = stats["alerts"]

        # Calculate packets per second
        now = time.monotonic()
        dt = now - self._last_check_time
        if dt > 0:
            bar.pps = (stats["packets"] - self._last_packet_count) / dt
        self._last_packet_count = stats["packets"]
        self._last_check_time = now

        # Push sample to sparkline chart
        chart = self.query_one("#chart", SparklineChart)
        chart.push(bar.pps, stats["alerts"])

    def add_flow_row(
        self, ts: str, src: str, dst: str, proto: str, nbytes: str, score: str
    ) -> None:
        """Add a row to the flow table (called from pipeline callback)."""
        table = self.query_one("#flow-table", DataTable)
        table.add_row(ts, src, dst, proto, nbytes, score)
        # Keep only last 200 rows
        while table.row_count > 200:
            table.remove_row(table.rows[0].key)

    def add_alert(
        self, severity: str, confidence: float, src: str, dst: str, port: int
    ) -> None:
        """Add an alert to the alert panel."""
        panel = self.query_one("#alert-panel", AlertPanel)
        panel.add_alert(severity, confidence, src, dst, port)

    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self.sub_title = ">> PAUSED <<" if self._paused else "7-MODEL ENSEMBLE :: REAL-TIME DETECTION"

    def action_quit(self) -> None:
        self._stop_event.set()
        self.exit()
