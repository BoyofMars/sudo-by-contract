"""Mock NEAR JSON-RPC for the sshd integration test (test fixture only).

Answers exactly what sbc-gate needs: `view_access_key` and `send_tx` for
`consume` / `report_denial`, behaving like the policy contract for one
capability (#12) that grants `service.restart:checkout-api` once.
Every decision is appended to the log file so the test can assert on it.
"""
import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])
LOG = sys.argv[2]
REVOKED = set()
STATE = {"uses": 0}


def read_borsh_tx(b):
    p = 0

    def take(n):
        nonlocal p
        s = b[p:p + n]
        p += n
        return s

    def u32():
        return int.from_bytes(take(4), "little")

    def string():
        return take(u32())

    string()          # signer
    take(1 + 32)      # key type + public key
    take(8)           # nonce
    string()          # receiver
    take(32)          # block hash
    assert u32() == 1
    assert take(1) == b"\x02"
    method = string().decode()
    args = json.loads(string())
    return method, args


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if body["method"] == "query":
            result = {"nonce": 1, "block_hash": "11111111111111111111111111111111", "permission": "FullAccess"}
        else:
            method, args = read_borsh_tx(base64.b64decode(body["params"]["signed_tx_base64"]))
            ret = None
            if method == "consume":
                base = {"uses": STATE["uses"], "max_uses": 1, "valid_before": 0, "action": "service.restart:checkout-api"}
                if args["request_id"] in REVOKED:
                    ret = {**base, "allowed": False, "code": "revoked", "message": "authorization was revoked"}
                elif args["action"] != "service.restart:checkout-api":
                    ret = {**base, "allowed": False, "code": "out_of_scope", "message": "capability permits only service.restart:checkout-api"}
                elif STATE["uses"] >= 1:
                    ret = {**base, "allowed": False, "code": "exhausted", "message": "all permitted uses are consumed"}
                else:
                    STATE["uses"] += 1
                    ret = {**base, "uses": 1, "allowed": True, "code": "allowed", "message": "permitted"}
            with open(LOG, "a") as f:
                f.write(json.dumps({"method": method, "args": args, "ret": ret}) + "\n")
            sv = base64.b64encode(json.dumps(ret).encode()).decode() if ret is not None else ""
            result = {"status": {"SuccessValue": sv}, "transaction": {"hash": "mock"}}
        out = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
