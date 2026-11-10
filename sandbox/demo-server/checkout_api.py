"""Toy service for the Sudo by Contract demo.

On the first start after a "deployment" it is degraded: /health returns 503
and ~18% of /checkout calls fail, as if a worker pool wedged after deploy
#1842. Restarting the process clears it. That restart is exactly the one
action the Deploy Agent is allowed to perform.
"""
import json
import os
import random
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = sys.argv[1] if len(sys.argv) > 1 else "checkout-api"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
STATE = f"/var/lib/checkout/{NAME}.degraded"
STARTED = time.time()

# A degraded flag that survives exactly one start: the restart heals it.
degraded = os.path.exists(STATE)
if degraded:
    with open(STATE) as f:
        starts = int(f.read().strip() or "0")
    if starts >= 1:
        os.remove(STATE)
        degraded = False
    else:
        with open(STATE, "w") as f:
            f.write(str(starts + 1))


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/health"):
            if degraded:
                self._send(503, {
                    "service": NAME, "status": "unhealthy", "deployment": "#1842",
                    "error_rate": 0.18, "baseline_error_rate": 0.012,
                    "failing_endpoint": "POST /checkout", "uptime_s": int(time.time() - STARTED),
                })
            else:
                self._send(200, {"service": NAME, "status": "healthy", "deployment": "#1842",
                                 "error_rate": 0.011, "uptime_s": int(time.time() - STARTED)})
        elif self.path.startswith("/checkout"):
            if degraded and random.random() < 0.18:
                self._send(500, {"error": "worker pool exhausted"})
            else:
                self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        sys.stdout.write("%s %s\n" % (NAME, fmt % args))
        sys.stdout.flush()


print(f"{NAME} listening on :{PORT} ({'DEGRADED' if degraded else 'healthy'})", flush=True)
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
