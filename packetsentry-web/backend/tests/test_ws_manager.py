"""Tests for WebSocketManager."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from starlette.websockets import WebSocketState


def _make_ws():
    ws = AsyncMock()
    ws.client_state = WebSocketState.CONNECTED
    return ws


@pytest.mark.asyncio
async def test_connect_registers_client():
    import sys
    sys.path.insert(0, "packetsentry-web/backend")
    from ws_manager import WebSocketManager

    manager = WebSocketManager()
    ws = _make_ws()
    await manager.connect(ws)
    assert ws in manager._clients
    ws.accept.assert_called_once()


@pytest.mark.asyncio
async def test_disconnect_removes_client():
    import sys
    sys.path.insert(0, "packetsentry-web/backend")
    from ws_manager import WebSocketManager

    manager = WebSocketManager()
    ws = _make_ws()
    await manager.connect(ws)
    manager.disconnect(ws)
    assert ws not in manager._clients


@pytest.mark.asyncio
async def test_broadcast_sends_to_all_clients():
    import sys
    sys.path.insert(0, "packetsentry-web/backend")
    from ws_manager import WebSocketManager

    manager = WebSocketManager()
    ws1, ws2 = _make_ws(), _make_ws()
    await manager.connect(ws1)
    await manager.connect(ws2)
    await manager.broadcast({"type": "stats_update", "pps": 100})
    ws1.send_text.assert_called_once()
    ws2.send_text.assert_called_once()
