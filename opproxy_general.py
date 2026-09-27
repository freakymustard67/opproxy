"""opproxy_general — general-purpose OpenAI-compatible proxy for Zen free models.

For plain clients (e.g. a study summarizer) that send no tools and/or
stream:false. Same fingerprint as opproxy.py (no API key):

  Authorization: Bearer public | User-Agent: opencode/latest/2.0.18/cli
  x-opencode-session: ses_… (fresh valid ID per request)
  stream:true forced upstream | tools always include read+shell dummies

Differences vs opproxy.py (harness proxy):
  * streaming responses are sanitized, not passed through: drops
    reasoning_content/name fields, dummy read/shell/bash tool_calls,
    and the trailing {"choices":[],"cost":"0"} line Zen appends.
  * non-streaming aggregation likewise returns content-only messages.
  * chat-only (/v1/chat/completions + /v1/models + /health). Responses/
    messages families intentionally omitted for a summarizer.

Stdlib only.
"""
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("OPENCODE_ZEN_URL", "https://opencode.ai/zen/v1")
ZEN_KEY = os.environ.get("ZEN_KEY") or os.environ.get("OPENCODE_API_KEY") or "public"
PROXY_TOKEN = os.environ.get("PROXY_TOKEN") or os.environ.get("API_KEY") or ""
PORT = int(os.environ.get("PORT", "8788"))
UA = os.environ.get("OPENCODE_UA", "opencode/latest/2.0.18/cli")

CHAT_MODELS = [
    "big-pickle", "space-bunny-free", "longcat-2.5-preview-free",
    "mimo-v2.6-flash-free", "mimo-v2.5-free", "mimo-v2-pro-free",
    "ling-3.0-flash-fin-free", "nemotron-3-ultra-free",
    "nemotron-3.5-lightning-free", "deepseek-v4-flash-free",
    "kimi-k2.5-free", "glm-5-free",
]

DUMMY_NAMES = {"read", "shell", "bash"}
CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def make_ses() -> str:
    ts = int(time.time() * 1000)
    cur = (~((ts * 0x1000 + 1))) & ((1 << 48) - 1)
    t = "".join(f"{(cur >> (40 - 8 * i)) & 0xff:02x}" for i in range(6))
    return "ses_" + t + "".join(CHARS[secrets.randbelow(62)] for _ in range(14))


def ensure_tools(tools):
    tools = list(tools or [])
    names = set()
    for t in tools:
        try:
            names.add(t["function"]["name"])
        except (KeyError, TypeError):
            pass
    if "read" not in names:
        tools.append({"type": "function", "function": {
            "name": "read", "description": "Read a file",
            "parameters": {"type": "object", "properties": {}}}})
    if "shell" not in names and "bash" not in names:
        tools.append({"type": "function", "function": {
            "name": "shell", "description": "Run a shell command",
            "parameters": {"type": "object", "properties": {}}}})
    return tools


def clean_delta(delta):
    """Return a sanitized OpenAI delta, or None if nothing client-visible."""
    out = {}
    if delta.get("role"):
        out["role"] = delta["role"]
    if isinstance(delta.get("content"), str) and delta["content"]:
        out["content"] = delta["content"]
    tcs = delta.get("tool_calls") or []
    kept = [tc for tc in tcs
            if isinstance(tc, dict)
            and ((tc.get("function") or {}).get("name")) not in DUMMY_NAMES]
    if kept:
        out["tool_calls"] = kept
    return out or None


class H(BaseHTTPRequestHandler):
    server_version = "opproxy-general/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _auth_ok(self):
        if not PROXY_TOKEN:
            return True
        got = self.headers.get("Authorization", "")
        if got.startswith("Bearer "):
            got = got[7:]
        return secrets.compare_digest(got, PROXY_TOKEN)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        if self.path in ("/v1/models", "/v1/models/"):
            return self._send(200, {"object": "list", "data": [
                {"id": m, "object": "model", "owned_by": "opencode-zen"}
                for m in CHAT_MODELS]})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            return self._send(404, {"error": "chat-only proxy (POST /v1/chat/completions)"})
        if not self._auth_ok():
            return self._send(401, {"error": "bad proxy key"})
        try:
            ln = int(self.headers.get("Content-Length", 0))
        except ValueError:
            ln = 0
        try:
            body = json.loads(self.rfile.read(ln).decode() if ln else "{}")
        except (ValueError, UnicodeDecodeError):
            return self._send(400, {"error": "invalid json"})
        model = str(body.get("model", "")).split("/")[-1].split(":")[0]
        if model not in CHAT_MODELS:
            return self._send(422, {"error": f"free chat models only: {CHAT_MODELS}"})
        client_stream = bool(body.get("stream", False))
        client_tools = body.get("tools") or []
        base_up = dict(body, model=model, stream=True,
                       stream_options={"include_usage": True},
                       tools=ensure_tools(client_tools))
        if not client_tools and "tool_choice" not in body:
            # Summarizer clients send no tools: keep the gate dummies but
            # forbid calls so the model returns text instead of dummy calls.
            base_up["tool_choice"] = "none"
        if client_tools:
            return self._passthrough(base_up, model, client_stream)
        # No-tool clients: aggregate (with retries on dummy-only calls),
        # then answer JSON or re-emit clean SSE. This avoids leaking
        # reasoning/name/dummy-call deltas to plain OpenAI clients.
        text, usage, finish = "", None, None
        for _ in range(3):
            status, resp, err = self._upstream(base_up)
            if err is not None:
                try:
                    return self._send(status, json.loads(err.decode()))
                except ValueError:
                    return self._send(status, {"error": "upstream error"})
            text, usage, finish = self._aggregate(resp)
            resp.close()
            if text.strip():
                break
            base_up = dict(base_up)  # fresh ses below; new upstream sample
        if finish == "tool_calls":
            finish = "stop"
        if not client_stream:
            return self._send(200, {
                "id": f"chatcmpl-{secrets.token_hex(8)}", "object": "chat.completion",
                "created": int(time.time()), "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                             "finish_reason": finish or "stop"}],
                "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}})
        return self._emit_text_stream(model, text, usage, finish or "stop")

    def _upstream(self, up):
        req = urllib.request.Request(
            UPSTREAM + "/chat/completions", data=json.dumps(up).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {ZEN_KEY}")
        req.add_header("User-Agent", UA)
        req.add_header("x-opencode-client", "cli")
        req.add_header("x-opencode-project", "global")
        req.add_header("x-opencode-session", make_ses())
        try:
            resp = urllib.request.urlopen(req, timeout=120)
            return 200, resp, None
        except urllib.error.HTTPError as e:
            return e.code, None, e.read()

    def _emit_text_stream(self, model, text, usage, finish):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        cid, created = f"chatcmpl-{secrets.token_hex(8)}", int(time.time())
        try:
            self.wfile.write(f"data: {json.dumps({'id': cid, 'object': 'chat.completion.chunk', 'created': created, 'model': model, 'choices': [{'index': 0, 'delta': {'role': 'assistant'}, 'finish_reason': None}]})}\n\n".encode())
            for i in range(0, len(text), 2000):
                self.wfile.write(f"data: {json.dumps({'id': cid, 'object': 'chat.completion.chunk', 'created': created, 'model': model, 'choices': [{'index': 0, 'delta': {'content': text[i:i + 2000]}, 'finish_reason': None}]})}\n\n".encode())
            self.wfile.write(f"data: {json.dumps({'id': cid, 'object': 'chat.completion.chunk', 'created': created, 'model': model, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': finish}]})}\n\n".encode())
            if usage:
                self.wfile.write(f"data: {json.dumps({'usage': usage})}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _passthrough(self, up, model, client_stream):
        status, resp, err = self._upstream(up)
        if err is not None:
            try:
                return self._send(status, json.loads(err.decode()))
            except ValueError:
                return self._send(status, {"error": "upstream error"})
        if client_stream:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            try:
                self._relay_stream(resp)
            finally:
                resp.close()
            return
        text, usage, finish = self._aggregate(resp)
        resp.close()
        if finish == "tool_calls":
            finish = "stop"
        return self._send(200, {
            "id": f"chatcmpl-{secrets.token_hex(8)}", "object": "chat.completion",
            "created": int(time.time()), "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": finish or "stop"}],
            "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}})

    def _events(self, resp):
        buf = b""
        while True:
            chunk = resp.read(32768)
            if not chunk:
                break
            buf += chunk
        for line in buf.decode(errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data in ("[DONE]", ""):
                continue
            try:
                ev = json.loads(data)
            except ValueError:
                continue
            if not ev.get("choices") and not ev.get("usage"):
                continue  # drops {"choices":[],"cost":"0"} trailer
            yield ev

    def _relay_stream(self, resp):
        saw_real_call = False
        for ev in self._events(resp):
            for ch in ev.get("choices", []):
                finish = ch.get("finish_reason")
                delta = clean_delta(ch.get("delta", {}))
                if delta is None:
                    if not finish:
                        continue
                    delta = {}
                if delta.get("tool_calls"):
                    saw_real_call = True
                elif finish == "tool_calls" and not saw_real_call:
                    # Dummy-only calls were stripped; report clean stop.
                    finish = "stop"
                out = {"id": ev.get("id", f"chatcmpl-{secrets.token_hex(8)}"),
                       "object": "chat.completion.chunk",
                       "created": ev.get("created", int(time.time())),
                       "model": ev.get("model", ""),
                       "choices": [{"index": ch.get("index", 0), "delta": delta,
                                    "finish_reason": finish}]}
                try:
                    self.wfile.write(f"data: {json.dumps(out)}\n\n".encode())
                except (BrokenPipeError, ConnectionResetError):
                    return
            if ev.get("usage"):
                try:
                    self.wfile.write(
                        f"data: {json.dumps({'usage': ev['usage']})}\n\n".encode())
                except (BrokenPipeError, ConnectionResetError):
                    return
        try:
            self.wfile.write(b"data: [DONE]\n\n")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _aggregate(self, resp):
        text, usage, finish = "", None, None
        pending = {}
        for ev in self._events(resp):
            for ch in ev.get("choices", []):
                d = ch.get("delta", {})
                if isinstance(d.get("content"), str):
                    text += d["content"]
                for tc in d.get("tool_calls", []) or []:
                    idx = tc.get("index", 0)
                    m = pending.setdefault(idx, {"name": "", "args": ""})
                    f = tc.get("function", {})
                    if f.get("name"):
                        m["name"] = f["name"]
                    if f.get("arguments"):
                        m["args"] += f["arguments"]
                if ch.get("finish_reason"):
                    finish = ch["finish_reason"]
            if ev.get("usage"):
                usage = ev["usage"]
        # Any non-dummy tool call would need real execution; for a summarizer
        # surface it explicitly instead of silently dropping it.
        real = [(i, m) for i, m in pending.items() if m["name"] not in DUMMY_NAMES and m["name"]]
        if real:
            text += "\n\n[tool_call filtered: " + ", ".join(
                f"{m['name']}" for _, m in real) + " — resend via a harness proxy]"
        return text, usage, finish


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    print(f"opproxy-general on :{PORT} upstream={UPSTREAM}", flush=True)
    srv.serve_forever()
