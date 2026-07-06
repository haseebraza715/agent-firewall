from __future__ import annotations

import ipaddress
import json
import secrets
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

from .approvals import ApprovalConflict, ApprovalNotFound, SQLiteApprovalQueue
from .policy import Policy
from .state import SQLiteStateStore


class Dashboard:
    def __init__(
        self,
        policy_path: Path,
        audit_path: Path,
        state_path: Path,
        host: str = "127.0.0.1",
        port: int = 8787,
        token: Optional[str] = None,
    ) -> None:
        if not _is_loopback(host):
            raise ValueError("dashboard host must be a loopback address")
        self.policy = Policy.load(policy_path)
        self.audit_path = audit_path
        self.state = SQLiteStateStore(state_path)
        self.approvals = SQLiteApprovalQueue(state_path)
        self.token = token or secrets.token_urlsafe(32)
        handler = _handler(self)
        self.server = ThreadingHTTPServer((host, port), handler)

    @property
    def address(self) -> str:
        host, port = self.server.server_address[:2]
        return "http://{}:{}".format(host, port)

    def serve_forever(self) -> None:
        print("Agent Firewall dashboard: {}".format(self.address), flush=True)
        self.server.serve_forever()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def summary(self) -> Dict[str, Any]:
        events = read_events(self.audit_path)
        counts = Counter(event.get("event") for event in events)
        usage = self.state.usage()
        return {
            "allowed": counts["allowed"] + counts["approval_granted"],
            "blocked": counts["blocked"] + counts["approval_denied"],
            "failed": counts["failed"],
            "near_misses": counts["approval_requested"],
            "pending_approvals": len(self.approvals.pending()),
            "tool_calls": usage.tool_calls,
            "max_calls": self.policy.budget.max_calls,
            "estimated_cost_usd": str(usage.estimated_cost_usd),
            "max_cost_usd": (
                str(self.policy.budget.max_cost_usd)
                if self.policy.budget.max_cost_usd is not None
                else None
            ),
        }


def read_events(path: Path, limit: int = 200) -> List[Dict[str, Any]]:
    events: deque = deque(maxlen=limit)
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict):
                    events.append(event)
    except FileNotFoundError:
        pass
    return list(events)


def _handler(dashboard: Dashboard):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentFirewall/0.1"

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/":
                nonce = secrets.token_urlsafe(16)
                page = (
                    _HTML.replace("__TOKEN__", dashboard.token)
                    .replace("__NONCE__", nonce)
                    .encode("utf-8")
                )
                self._send(
                    200,
                    page,
                    "text/html; charset=utf-8",
                    nonce=nonce,
                )
            elif path == "/api/summary":
                self._json(200, dashboard.summary())
            elif path == "/api/events":
                self._json(200, {"events": read_events(dashboard.audit_path)})
            elif path == "/api/approvals":
                self._json(
                    200,
                    {
                        "approvals": [
                            record.as_dict()
                            for record in dashboard.approvals.pending()
                        ]
                    },
                )
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            prefix = "/api/approvals/"
            if not path.startswith(prefix):
                self._json(404, {"error": "not found"})
                return
            if not secrets.compare_digest(
                self.headers.get("X-Agent-Firewall-Token", ""),
                dashboard.token,
            ):
                self._json(403, {"error": "invalid dashboard token"})
                return
            if not self.headers.get("Content-Type", "").startswith(
                "application/json"
            ):
                self._json(415, {"error": "content type must be application/json"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length < 1 or length > 1024:
                self._json(400, {"error": "invalid request size"})
                return
            try:
                body = json.loads(self.rfile.read(length))
                status = body["decision"]
                record = dashboard.approvals.decide(
                    unquote(path[len(prefix) :]),
                    status,
                )
            except (json.JSONDecodeError, KeyError, ValueError):
                self._json(400, {"error": "decision must be approved or denied"})
                return
            except ApprovalNotFound:
                self._json(404, {"error": "approval not found"})
                return
            except ApprovalConflict as exc:
                self._json(409, {"error": str(exc)})
                return
            self._json(200, record.as_dict())

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _json(self, status: int, value: Any) -> None:
            self._send(
                status,
                json.dumps(value, separators=(",", ":"), default=str).encode(
                    "utf-8"
                ),
                "application/json",
            )

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            nonce: Optional[str] = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            policy = "default-src 'none'; connect-src 'self'"
            if nonce:
                policy += "; style-src 'nonce-{}'; script-src 'nonce-{}'".format(
                    nonce, nonce
                )
            self.send_header("Content-Security-Policy", policy)
            self.end_headers()
            self.wfile.write(body)

    return Handler


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Firewall</title>
<style nonce="__NONCE__">
:root{color-scheme:dark;font:15px system-ui;background:#0b1020;color:#e8ecf4}
body{max-width:1100px;margin:0 auto;padding:32px 20px}
h1{font-size:24px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card,section{background:#151c30;border:1px solid #29334d;border-radius:10px;padding:16px}
.value{font-size:28px;font-weight:700}section{margin-top:16px;overflow:auto}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #29334d}
button{border:0;border-radius:6px;padding:7px 10px;margin-right:6px;cursor:pointer}
.approve{background:#45d483}.deny{background:#ff6b6b}.muted{color:#9ba8c7}
</style>
</head>
<body>
<h1>Agent Firewall</h1>
<div class="grid" id="summary"></div>
<section><h2>Pending approvals</h2><table><tbody id="approvals"></tbody></table></section>
<section><h2>Recent events</h2><table><thead><tr><th>Time</th><th>Event</th><th>Tool</th><th>Reason</th></tr></thead><tbody id="events"></tbody></table></section>
<p class="muted" id="status"></p>
<script nonce="__NONCE__">
const token="__TOKEN__";
const text=(tag,value)=>{const node=document.createElement(tag);node.textContent=value??"—";return node};
async function decide(id,decision){await fetch("/api/approvals/"+encodeURIComponent(id),{method:"POST",headers:{"Content-Type":"application/json","X-Agent-Firewall-Token":token},body:JSON.stringify({decision})});await load()}
async function load(){try{
 const [s,a,e]=await Promise.all(["summary","approvals","events"].map(x=>fetch("/api/"+x).then(r=>r.json())));
 const cards=[["Allowed",s.allowed],["Blocked",s.blocked],["Near misses",s.near_misses],["Pending",s.pending_approvals],["Calls",s.tool_calls+(s.max_calls?"/"+s.max_calls:"")],["Cost","$"+s.estimated_cost_usd+(s.max_cost_usd?"/$"+s.max_cost_usd:"")]];
 const summary=document.querySelector("#summary");summary.replaceChildren(...cards.map(([k,v])=>{const c=text("div","");c.className="card";const n=text("div",v);n.className="value";c.append(n,text("div",k));return c}));
 const approvals=document.querySelector("#approvals");approvals.replaceChildren(...a.approvals.map(x=>{const r=document.createElement("tr");r.append(text("td",x.tool),text("td",x.reason));const actions=document.createElement("td");for(const d of ["approved","denied"]){const b=text("button",d==="approved"?"Approve":"Deny");b.className=d==="approved"?"approve":"deny";b.onclick=()=>decide(x.call_id,d);actions.append(b)}r.append(actions);return r}));
 const events=document.querySelector("#events");events.replaceChildren(...e.events.slice().reverse().map(x=>{const r=document.createElement("tr");r.append(text("td",x.timestamp),text("td",x.event),text("td",x.tool),text("td",x.reason));return r}));
 document.querySelector("#status").textContent="Updated "+new Date().toLocaleTimeString();
}catch(error){document.querySelector("#status").textContent=String(error)}}
load();setInterval(load,1500);
</script>
</body>
</html>
"""
