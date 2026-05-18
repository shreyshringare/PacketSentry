"""PCAP file replay with configurable speed.

Reads packets from a ``.pcap`` file and feeds them through the
``DetectionPipeline`` at a controlled speed.

Usage::

    from packetsentry.capture.pipeline import DetectionPipeline
    from packetsentry.capture.replay import replay_pcap

    pipeline = DetectionPipeline()
    summary = replay_pcap("attack.pcap", pipeline, speed=0.0)
    print(summary)  # {'packets': 1234, 'alerts': 42, ...}
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable, Optional

from scapy.all import PcapReader  # type: ignore

from packetsentry.capture.live import scapy_to_parsed
from packetsentry.capture.pipeline import DetectionPipeline
from packetsentry.detection.ensemble import DecisionResult

logger = logging.getLogger(__name__)


def replay_pcap(
    pcap_path: str,
    pipeline: DetectionPipeline,
    speed: float = 1.0,
    alert_callback: Callable[[DecisionResult], None] | None = None,
) -> dict:
    """Replay a PCAP file through the detection pipeline.

    Args:
        pcap_path: Path to the ``.pcap`` file.
        pipeline: The detection pipeline to feed packets into.
        speed: Replay speed multiplier.
               ``1.0`` = real-time (respects inter-packet timing).
               ``0.0`` = as fast as possible (no sleeps).
               ``10.0`` = 10× faster than real-time.
        alert_callback: Called with each DecisionResult that is an alert.

    Returns:
        Summary dictionary with keys: ``packets``, ``alerts``,
        ``flows``, ``duration_sec``.

    Raises:
        FileNotFoundError: If ``pcap_path`` does not exist.
    """
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    logger.info("Replaying PCAP: %s at speed=%.1fx", pcap_path, speed)
    start = time.monotonic()
    last_ts: float | None = None

    try:
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                parsed = scapy_to_parsed(pkt)
                if parsed is None:
                    continue

                # Inter-packet delay (respects original timing)
                if speed > 0.0 and last_ts is not None:
                    delta = parsed.timestamp - last_ts
                    if delta > 0:
                        time.sleep(delta / speed)
                last_ts = parsed.timestamp

                result = pipeline.ingest(parsed)
                if result and result.is_alert and alert_callback:
                    alert_callback(result)

    except Exception as e:
        logger.error("Error replaying PCAP: %s", e)
        raise

    # Flush remaining flows
    pipeline.flush()

    elapsed = time.monotonic() - start
    stats = pipeline.stats()
    summary = {
        "packets": stats["packets"],
        "alerts": stats["alerts"],
        "flows": stats["completed_flows"],
        "duration_sec": round(elapsed, 2),
    }

    logger.info("Replay complete: %s", summary)
    return summary
