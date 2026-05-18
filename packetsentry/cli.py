"""Typer CLI entrypoint.

Commands:
  packetsentry live     — Start live capture with TUI dashboard
  packetsentry replay   — Replay a PCAP through the pipeline
  packetsentry alerts   — View alert history from DuckDB
  packetsentry stats    — Show pipeline statistics
"""

import json
import threading

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="packetsentry",
    help="Network Intrusion Detection System — live capture, ML ensemble, real-time TUI.",
    no_args_is_help=True,
)

console = Console()


@app.command()
def live(
    interface: str = typer.Option("Wi-Fi", help="Network interface to capture on."),
):
    """Start live packet capture with the real-time TUI dashboard."""
    from packetsentry.capture.pipeline import DetectionPipeline
    from packetsentry.capture.live import start_live_capture
    from packetsentry.tui.dashboard import PacketSentryApp

    pipeline = DetectionPipeline()
    stop_event = threading.Event()

    # Start capture in background thread
    capture_thread = threading.Thread(
        target=start_live_capture,
        args=(interface, pipeline),
        kwargs={"stop_event": stop_event},
        daemon=True,
    )
    capture_thread.start()

    # Run TUI in main thread
    tui = PacketSentryApp(pipeline=pipeline, stop_event=stop_event)
    tui.run()

    # When TUI exits, stop capture
    stop_event.set()
    capture_thread.join(timeout=3.0)
    console.print("[green]PacketSentry stopped.[/green]")


@app.command()
def replay(
    pcap: str = typer.Argument(..., help="Path to PCAP file."),
    speed: float = typer.Option(0.0, help="Replay speed multiplier (0 = max speed)."),
):
    """Replay a PCAP file through the detection pipeline."""
    from packetsentry.capture.pipeline import DetectionPipeline
    from packetsentry.capture.replay import replay_pcap

    pipeline = DetectionPipeline()
    alert_count = 0

    def on_alert(result):
        nonlocal alert_count
        alert_count += 1
        # Infer severity from confidence
        if result.confidence >= 0.90:
            sev, color = "CRITICAL", "red"
        elif result.confidence >= 0.75:
            sev, color = "HIGH", "yellow"
        elif result.confidence >= 0.60:
            sev, color = "MED", "cyan"
        else:
            sev, color = "LOW", "white"

        console.print(
            f"  [{color}]🚨 {sev}[/{color}] conf={result.confidence:.2f} "
            f"aho={result.scores.get('aho_corasick', 0):.2f} "
            f"xgb={result.scores.get('xgboost', 0):.2f} "
            f"gnn={result.scores.get('gnn_detector', 0):.2f}"
        )

    console.print(f"[bold]Replaying:[/bold] {pcap} at speed={speed}x")
    summary = replay_pcap(pcap, pipeline, speed=speed, alert_callback=on_alert)

    table = Table(title="Replay Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Packets", str(summary["packets"]))
    table.add_row("Flows", str(summary["flows"]))
    table.add_row("Alerts", str(summary["alerts"]))
    table.add_row("Duration", f"{summary['duration_sec']}s")
    console.print(table)


@app.command()
def alerts(
    last: int = typer.Option(50, help="Number of recent alerts to show."),
):
    """View alert history from DuckDB."""
    from packetsentry.alerts.store import DuckDBAlertStore

    store = DuckDBAlertStore()
    rows = store.get_recent_alerts(limit=last)

    if not rows:
        console.print("[yellow]No alerts found.[/yellow]")
        return

    table = Table(title=f"Recent Alerts (last {last})")
    table.add_column("Time", style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Source IP")
    table.add_column("Dest", style="cyan")
    table.add_column("Conf", style="green")

    severity_colors = {"CRITICAL": "red", "HIGH": "yellow", "MED": "cyan", "LOW": "white"}
    for row in rows:
        sev = row.get("severity", "?")
        color = severity_colors.get(sev, "white")
        table.add_row(
            str(row.get("timestamp", ""))[:19],
            f"[{color}]{sev}[/{color}]",
            str(row.get("src_ip", "")),
            f"{row.get('dst_ip', '')}:{row.get('dst_port', '')}",
            f"{row.get('confidence', 0):.2f}",
        )

    console.print(table)


@app.command()
def bench(
    patterns: int = typer.Option(1000, help="Number of patterns to benchmark."),
    text_size: str = typer.Option("10MB", help="Synthetic text size."),
):
    """Benchmark Aho-Corasick vs naive regex."""
    import time
    import re
    from packetsentry.detection.aho_corasick import AhoCorasick

    # Generate patterns
    import random
    import string
    pats = ["".join(random.choices(string.ascii_lowercase, k=8)) for _ in range(patterns)]

    # Parse text size
    multiplier = {"KB": 1024, "MB": 1024**2, "GB": 1024**3}
    unit = text_size[-2:]
    size = int(text_size[:-2]) * multiplier.get(unit, 1)
    text = "".join(random.choices(string.ascii_lowercase + " ", k=size))

    # Aho-Corasick
    ac = AhoCorasick()
    for p in pats:
        ac.add_pattern(p)
    ac.build()

    start = time.perf_counter()
    ac_matches = ac.search(text)
    ac_time = time.perf_counter() - start

    # Naive regex
    combined = "|".join(re.escape(p) for p in pats)
    start = time.perf_counter()
    re_matches = list(re.finditer(combined, text))
    re_time = time.perf_counter() - start

    table = Table(title=f"Benchmark: {patterns} patterns × {text_size} text")
    table.add_column("Engine", style="cyan")
    table.add_column("Time", style="green")
    table.add_column("Matches")
    table.add_column("Speedup", style="yellow")
    table.add_row("Aho-Corasick", f"{ac_time:.3f}s", str(len(ac_matches)), "—")
    table.add_row("Regex", f"{re_time:.3f}s", str(len(re_matches)), f"{re_time/max(ac_time,1e-9):.1f}×")
    console.print(table)
