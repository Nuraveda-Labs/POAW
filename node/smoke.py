"""Self-host smoke test: send one claim to a running node and check its receipt with the spec's reference checker.

  python node/smoke.py http://127.0.0.1:8080 <api key>        (from the repository root)
Exit 0 only if the claim is decided `verified` and the receipt checks out against the node's published keys.
"""
import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

base, key = sys.argv[1].rstrip("/"), sys.argv[2]


def get(path: str) -> dict:
    with urllib.request.urlopen(base + path, timeout=20) as r:
        return json.load(r)


body = json.dumps({"client_claim_id": f"smoke-{int(time.time())}", "agent_id": "smoke", "action": "http.url.status",
                   "target": "https://example.com/", "claimed_at": "2026-01-01T00:00:00Z"}).encode()
req = urllib.request.Request(base + "/v1/claims", data=body, method="POST",
                             headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=30) as r:
    claim = json.load(r)
print("claim:", {k: claim.get(k) for k in ("state", "verdict", "receipt_id")})
if claim.get("verdict") != "verified" or not claim.get("receipt_id"):
    sys.exit("the claim wasn't verified")
with tempfile.TemporaryDirectory() as d:
    Path(d, "receipt.json").write_text(json.dumps(get(f"/v1/receipts/{claim['receipt_id']}")))
    Path(d, "keys.json").write_text(json.dumps(get("/.well-known/poaw-keys.json")))
    checker = Path(__file__).resolve().parents[1] / "spec" / "tools" / "check.py"
    out = subprocess.run(["uv", "run", "-q", str(checker), str(Path(d, "receipt.json")), str(Path(d, "keys.json"))],
                         capture_output=True, text=True)
    print(out.stdout[-400:])
    result = json.loads(out.stdout[out.stdout.index("{"):])
    if not result.get("valid"):
        sys.exit("the receipt did not verify")
print("smoke: PASS")
