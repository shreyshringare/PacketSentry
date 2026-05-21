"""Typer CLI entrypoint.

Commands:
  packetsentry live      — Start live capture with TUI dashboard (--no-tui for headless JSON)
  packetsentry replay    — Replay a PCAP through the pipeline (--output json for machine-readable)
  packetsentry alerts    — View alert history from DuckDB (--severity, --output)
  packetsentry bench     — Benchmark Aho-Corasick vs regex
  packetsentry serve     — Start the FastAPI web backend
  packetsentry status    — Show pipeline statistics
  packetsentry explain   — Show SHAP feature attribution for an alert
  packetsentry similar   — Find similar past alerts via ChromaDB
  packetsentry clusters  — Show attack family clusters from ChromaDB
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
    no_tui: bool = typer.Option(False, "--no-tui", help="Run headless, log alerts as JSON to stdout."),
):
    """Start live packet capture. Use --no-tui for headless JSON output."""
    from packetsentry.capture.pipeline import DetectionPipeline
    from packetsentry.capture.live import start_live_capture

    pipeline = DetectionPipeline()
    stop_event = threading.Event()

    if no_tui:
        def _on_alert(result, features, src_ip, dst_ip, dst_port):
            import time
            from packetsentry.alerts.severity import confidence_to_severity
            print(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "severity": confidence_to_severity(result.confidence),
                "confidence": round(result.confidence, 4),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "scores": {k: round(v, 4) for k, v in result.scores.items()},
            }), flush=True)

        pipeline._alert_callback = _on_alert  # type: ignore[attr-defined]
        console.print(f"[dim]Headless capture on {interface}. Ctrl+C to stop.[/dim]")
        try:
            start_live_capture(interface, pipeline, stop_event=stop_event)
        except KeyboardInterrupt:
            stop_event.set()
        return

    from packetsentry.tui.dashboard import PacketSentryApp

    capture_thread = threading.Thread(
        target=start_live_capture,
        args=(interface, pipeline),
        kwargs={"stop_event": stop_event},
        daemon=True,
    )
    capture_thread.start()
    tui = PacketSentryApp(pipeline=pipeline, stop_event=stop_event)
    tui.run()
    stop_event.set()
    capture_thread.join(timeout=3.0)
    console.print("[green]PacketSentry stopped.[/green]")


@app.command()
def replay(
    pcap: str = typer.Argument(..., help="Path to PCAP file."),
    speed: float = typer.Option(0.0, help="Replay speed multiplier (0 = max speed)."),
    output: str = typer.Option("table", help="Output format: table or json."),
    bpf: str = typer.Option("", "--bpf", help="BPF filter string (e.g. 'tcp port 80')."),
):
    """Replay a PCAP file through the detection pipeline."""
    import time as _time
    from packetsentry.capture.pipeline import DetectionPipeline
    from packetsentry.capture.replay import replay_pcap
    from packetsentry.alerts.severity import confidence_to_severity

    _severity_colors = {"CRITICAL": "red", "HIGH": "yellow", "MED": "cyan", "LOW": "white"}
    json_alerts: list[dict] = []

    def on_alert(result, features, src_ip, dst_ip, dst_port):
        sev = confidence_to_severity(result.confidence)
        if output == "json":
            record = {
                "ts": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                "severity": sev,
                "confidence": round(result.confidence, 4),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "scores": {k: round(v, 4) for k, v in result.scores.items()},
            }
            print(json.dumps(record), flush=True)
            json_alerts.append(record)
        else:
            color = _severity_colors.get(sev, "white")
            console.print(
                f"  [{color}]🚨 {sev}[/{color}] conf={result.confidence:.2f} "
                f"aho={result.scores.get('aho_corasick', 0):.2f} "
                f"xgb={result.scores.get('xgboost', 0):.2f} "
                f"gnn={result.scores.get('gnn_detector', 0):.2f}"
            )

    pipeline = DetectionPipeline(alert_callback=on_alert)

    if output != "json":
        bpf_note = f"  bpf={bpf!r}" if bpf else ""
        console.print(f"[bold]Replaying:[/bold] {pcap} at speed={speed}x{bpf_note}")

    summary = replay_pcap(pcap, pipeline, speed=speed, bpf_filter=bpf or None)

    if output == "json":
        print(json.dumps({
            "summary": {
                "packets": summary["packets"],
                "flows": summary["flows"],
                "alerts": summary["alerts"],
                "duration_sec": summary["duration_sec"],
            },
            "alerts": json_alerts,
        }, indent=2))
        return

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
    severity: str = typer.Option("", help="Filter by severity: CRITICAL, HIGH, MED, LOW."),
    output: str = typer.Option("table", help="Output format: table or json."),
):
    """View alert history from DuckDB."""
    from packetsentry.alerts.store import DuckDBAlertStore

    store = DuckDBAlertStore()
    rows = store.get_recent_alerts(limit=last)

    if severity:
        rows = [r for r in rows if r.get("severity", "").upper() == severity.upper()]

    if not rows:
        if output == "json":
            print("[]")
        else:
            console.print("[yellow]No alerts found.[/yellow]")
        return

    if output == "json":
        print(json.dumps(rows, indent=2, default=str))
        return

    table = Table(title=f"Recent Alerts (last {last})" + (f" [{severity}]" if severity else ""))
    table.add_column("Time", style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Source IP")
    table.add_column("Dest", style="cyan")
    table.add_column("Conf", style="green")
    table.add_column("Rule")

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
            str(row.get("rule", "")),
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


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Bind host."),
    port: int = typer.Option(8000, help="Bind port."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code change."),
):
    """Start the PacketSentry web API backend (FastAPI + WebSocket)."""
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn not installed. Run: pip install uvicorn[standard][/red]")
        raise typer.Exit(1)

    import os, sys
    backend_dir = os.path.join(os.path.dirname(__file__), "..", "packetsentry-web", "backend")
    sys.path.insert(0, backend_dir)
    os.chdir(backend_dir)

    console.print(f"[bold]Starting PacketSentry API[/bold] on {host}:{port}")
    uvicorn.run("main:app", host=host, port=port, reload=reload)


@app.command()
def status(
    output: str = typer.Option("table", help="Output format: table or json."),
):
    """Show current pipeline statistics."""
    from packetsentry.alerts.store import DuckDBAlertStore

    store = DuckDBAlertStore()

    stats = {
        "alerts_in_db": len(store.get_recent_alerts(limit=10000)),
        "db_path": "data/alerts.duckdb",
        "status": "ready",
    }

    if output == "json":
        print(json.dumps(stats, indent=2))
        return

    table = Table(title="PacketSentry Status")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")
    for k, v in stats.items():
        table.add_row(k, str(v))
    console.print(table)


@app.command()
def explain(
    alert_id: str = typer.Argument(..., help="Alert ID to explain."),
):
    """Show SHAP feature attribution for an alert."""
    from packetsentry.alerts.store import DuckDBAlertStore

    store = DuckDBAlertStore()
    rows = store.get_recent_alerts(limit=10000)
    match = next((r for r in rows if r.get("alert_id") == alert_id), None)

    if not match:
        console.print(f"[red]Alert {alert_id!r} not found.[/red]")
        raise typer.Exit(1)

    shap_raw = match.get("shap_explanation", "{}")
    try:
        shap: dict = json.loads(shap_raw) if isinstance(shap_raw, str) else shap_raw
    except Exception:
        shap = {}

    table = Table(title=f"SHAP Explanation — {alert_id}")
    table.add_column("Feature", style="cyan")
    table.add_column("SHAP Value", style="green")
    table.add_column("Direction")

    for feat, val in sorted(shap.items(), key=lambda x: abs(float(x[1])), reverse=True)[:10]:
        v = float(val)
        direction = "[red]↑ attack[/red]" if v > 0 else "[green]↓ normal[/green]"
        table.add_row(feat, f"{v:+.4f}", direction)

    console.print(table)
    console.print(f"\nSeverity: [bold]{match.get('severity')}[/bold]  Confidence: {match.get('confidence', 0):.2f}")


@app.command()
def similar(
    alert_id: str = typer.Argument(..., help="Alert ID to find similar alerts for."),
    top: int = typer.Option(5, help="Number of similar alerts to return."),
):
    """Find similar past alerts using ChromaDB vector similarity."""
    from packetsentry.alerts.store import DuckDBAlertStore
    from packetsentry.storage.vector_store import ChromaStore

    store = DuckDBAlertStore()
    vector_store = ChromaStore()

    rows = store.get_recent_alerts(limit=10000)
    match = next((r for r in rows if r.get("alert_id") == alert_id), None)
    if not match:
        console.print(f"[red]Alert {alert_id!r} not found.[/red]")
        raise typer.Exit(1)

    embedding_blob = match.get("embedding")
    if not embedding_blob:
        console.print("[yellow]No embedding stored for this alert.[/yellow]")
        return

    import numpy as np
    embedding = np.frombuffer(embedding_blob, dtype=np.float32)
    results = vector_store.find_similar(embedding, n=top)

    table = Table(title=f"Top {top} Similar Alerts")
    table.add_column("ID", style="dim")
    table.add_column("Similarity", style="green")
    table.add_column("Severity", style="bold")
    table.add_column("Src IP")
    table.add_column("Time")

    for r in results:
        meta = r.get("metadata", {})
        dist = r.get("distance", 1.0)
        similarity = f"{(1 - dist) * 100:.1f}%"
        table.add_row(
            r.get("id", "")[:12],
            similarity,
            meta.get("severity", "?"),
            meta.get("src_ip", "?"),
            meta.get("timestamp", "?"),
        )
    console.print(table)


@app.command()
def clusters():
    """Show attack family clusters from ChromaDB vector store."""
    from packetsentry.storage.vector_store import ChromaStore

    vector_store = ChromaStore()
    summary = vector_store.cluster_summary()

    if not summary:
        console.print("[yellow]No clusters found. Run live capture to populate the vector store.[/yellow]")
        return

    table = Table(title="Attack Family Clusters (ChromaDB)")
    table.add_column("Attack Type", style="cyan")
    table.add_column("Count", style="green")

    for attack_type, count in sorted(summary.items(), key=lambda x: x[1], reverse=True):
        table.add_row(attack_type, str(count))
    console.print(table)
