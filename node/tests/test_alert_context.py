import pytest

from poaw_node.service import Node


class _Store:
    def __init__(self):
        self.marked = []

    async def pending_alerts(self):
        return [{"alert_id": "a1", "workspace_id": "w1", "receipt": {"body": {"receipt_id": "r1"}}}]

    async def mark_alert(self, alert_id, ok, error=""):
        self.marked.append((alert_id, ok))


class _Sink:
    def __init__(self):
        self.calls = []

    async def send(self, receipt, *, alert_id=None, workspace_id=None):
        self.calls.append((receipt["body"]["receipt_id"], alert_id, workspace_id))


@pytest.mark.asyncio
async def test_flush_alerts_tells_the_sink_which_alert_and_workspace():
    n = Node.__new__(Node)  # only the alert path is exercised
    n.store, n.alerts = _Store(), _Sink()
    assert await n.flush_alerts() == 1
    assert n.alerts.calls == [("r1", "a1", "w1")] and n.store.marked == [("a1", True)]
