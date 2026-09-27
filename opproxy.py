"""opproxy — combined Zen free-model proxy (stdlib only, no deps).

Combines, from /tmp/opencode/proxies/*:
- PandaDecSt/opencodeProxy: OpenAI + Anthropic dual API idea, tool-call awareness
- bigdata2211it-web/opencode-free-proxy: Bun UA spoof, per-user sticky ses (30m),
  Anthropic<->OpenAI translation approach, 429 mapping
- akashdeep000/opencode-zen-proxy: verified limits, /status metrics, UPSTREAM_PROXY
  egress rotation support, paid-model 422 gate
- usa-w/opencode-free-proxy: Bearer public-or-BYOK, force stream:true upstream +
  SSE->JSON aggregation for stream:false clients, x-model-fallback header
- denysvitali/opencode-proxy: protocol translation patterns, model routing
- 6Kmfi6HP/opencode2api: 3-protocol gateway + fingerprint research
  (ses_ format ^ses_[0-9a-f]{12}[0-9A-Za-z]{14}$, UA opencode/<ch>/<semver>/<client>)
- RaisNafis/weimeng8888/lumishoang: minimal passthrough, model aliasing
- keelzhang/jason9075: session injection, logging

Verified fingerprint (no API key, see zen_free.py):
  Authorization: Bearer public | User-Agent: opencode/latest/2.0.18/cli
  x-opencode-session (valid ses_ ID) | stream:true | tools include read+shell
"""
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from zen_models import MODELS, chat_model_ids, responses_model_ids, short_name


UPSTREAM = os.environ.get("OPENCODE_ZEN_URL", "https://opencode.ai/zen/v1")
ZEN_KEY = os.environ.get("ZEN_KEY") or os.environ.get("OPENCODE_API_KEY") or "public"
PROXY_TOKEN = os.environ.get("PROXY_TOKEN") or os.environ.get("API_KEY") or ""
PORT = int(os.environ.get("PORT", "8787"))
UA = os.environ.get("OPENCODE_UA", "opencode/latest/2.0.18/cli")
UPSTREAM_PROXY = os.environ.get("UPSTREAM_PROXY")  # e.g. http://user:pass@host:3128 (v6pool-style rotation)
FALLBACK_MODEL = os.environ.get("FALLBACK_MODEL", "big-pickle")

ses_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Free models live in zen_models.py (single source of truth, probed against
# upstream). Upstream protocol families: chat -> /chat/completions,
# responses -> /responses. /v1/messages is a native Anthropic passthrough and
# serves whichever catalog model accepts that wire format, so it is not a
# model family of its own.


DUMMY_CHAT_TOOLS = [
    {"type": "function", "function": {"name": "read", "description": "Read a file", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "shell", "description": "Run a shell command", "parameters": {"type": "object", "properties": {}}}},
]
DUMMY_RESP_TOOLS = [
    {"type": "function", "name": "read", "description": "Read a file", "parameters": {"type": "object", "properties": {}}},
    {"type": "function", "name": "shell", "description": "Run a shell command", "parameters": {"type": "object", "properties": {}}},
]
DUMMY_ANT_TOOLS = [
    {"name": "read", "description": "Read a file", "input_schema": {"type": "object", "properties": {}}},
    {"name": "shell", "description": "Run a shell command", "input_schema": {"type": "object", "properties": {}}},
]
DUMMY_NAMES = {"read", "shell", "bash"}

MAX_BODY = 50 * 1024 * 1024
TOO_LARGE = object()   # sentinel: body over MAX_BODY (distinct from bad JSON)

SES_RE = re.compile(r"^ses_[0-9a-f]{12}[0-9A-Za-z]{14}$")


def _deep_stats():
    """Snapshot counters with the nested dicts *copied*, not shared: /status
    serializes outside the lock, and a stat() landing mid-dumps would raise
    "dictionary changed size during iteration"."""
    return {"requests_total": _stats["requests_total"],
            "by_model": dict(_stats["by_model"]),
            "by_status": dict(_stats["by_status"]),
            "rate_limited": _stats["rate_limited"],
            "fallback_used": _stats["fallback_used"],
            "started": _stats["started"]}


_stats_lock = threading.Lock()
_stats = {"requests_total": 0, "by_model": {}, "by_status": {}, "rate_limited": 0,
          "fallback_used": 0, "started": time.time()}


def stat(model, status):
    with _stats_lock:
        _stats["requests_total"] += 1
        _stats["by_model"][model] = _stats["by_model"].get(model, 0) + 1
        _stats["by_status"][str(status)] = _stats["by_status"].get(str(status), 0) + 1
        if str(status) == "429":
            _stats["rate_limited"] += 1


def make_ses() -> str:
    ts = int(time.time() * 1000)
    cur = (~((ts * 0x1000 + 1))) & ((1 << 48) - 1)
    t = "".join(f"{(cur >> (40 - 8 * i)) & 0xff:02x}" for i in range(6))
    return "ses_" + t + "".join(ses_CHARS[secrets.randbelow(62)] for _ in range(14))


_sessions, _sessions_lock = {}, threading.Lock()  # per-client-IP sticky ses, 30m (bigdata)


def session_for(client_ip, provided):
    if provided and SES_RE.match(provided):
        return provided
    now = time.time()
    with _sessions_lock:
        ent = _sessions.get(client_ip)
        if ent and now - ent[1] < 1800:
            return ent[0]
        ses = make_ses()
        _sessions[client_ip] = (ses, now)
        if len(_sessions) > 10000:  # LRU-ish clear (akashdeep)
            _sessions.clear()
        return ses


def ensure_chat_tools(tools):
    tools = list(tools or [])
    names = set()
    for t in tools:
        try:
            names.add(t["function"]["name"])
        except (KeyError, TypeError):
            pass
    if "read" not in names:
        tools.append(DUMMY_CHAT_TOOLS[0])
    if "shell" not in names and "bash" not in names:
        tools.append(DUMMY_CHAT_TOOLS[1])
    return tools


def ensure_resp_tools(tools):
    tools = list(tools or [])
    names = {t.get("name") for t in tools if isinstance(t, dict)}
    if "read" not in names:
        tools.append(DUMMY_RESP_TOOLS[0])
    if "shell" not in names and "bash" not in names:
        tools.append(DUMMY_RESP_TOOLS[1])
    return tools


def ensure_ant_tools(tools):
    tools = list(tools or [])
    names = {t.get("name") for t in tools if isinstance(t, dict)}
    if "read" not in names:
        tools.append(DUMMY_ANT_TOOLS[0])
    if "shell" not in names and "bash" not in names:
        tools.append(DUMMY_ANT_TOOLS[1])
    return tools


def upstream_post(path, payload, ses, stream_want, extra_headers=None):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(UPSTREAM + path, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {ZEN_KEY}")
    req.add_header("User-Agent", UA)
    req.add_header("x-opencode-client", "cli")
    req.add_header("x-opencode-project", "global")
    req.add_header("x-opencode-session", ses)
    req.add_header("Accept", "text/event-stream" if stream_want else "application/json")
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    kw = {}
    if UPSTREAM_PROXY:  # v6pool-style rotation (akashdeep)
        kw["proxies"] = {"https": UPSTREAM_PROXY, "http": UPSTREAM_PROXY}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(kw.get("proxies", {}))) \
        if UPSTREAM_PROXY else None
    try:
        resp = (opener.open(req, timeout=120) if opener
                else urllib.request.urlopen(req, timeout=120))
        return resp.status, resp, None
    except urllib.error.HTTPError as e:
        return e.code, None, e.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        # Connection refused / DNS / TLS / read timeout. Unhandled, the
        # exception killed the request with no response at all (client saw a
        # socket reset); report it as an upstream failure instead.
        return 502, None, json.dumps({"error": {"type": "upstream_unavailable",
                                               "message": str(e)[:200]}}).encode()


class H(BaseHTTPRequestHandler):
    server_version = "opproxy/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, obj, extra=None):
        body = json.dumps(obj).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _auth_ok(self):
        if not PROXY_TOKEN:
            return True
        # Anthropic clients (and hermes in anthropic_messages mode) send
        # x-api-key; OpenAI clients send Authorization: Bearer.
        got = self.headers.get("Authorization") or self.headers.get("x-api-key") or ""
        if got.startswith("Bearer "):
            got = got[7:]
        return secrets.compare_digest(got, PROXY_TOKEN)

    def _drain(self, n):
        """Consume an oversized body before replying. Answering 413 and closing
        mid-upload makes the client fail on a broken pipe instead of reading
        the status, so the bytes are swallowed (bounded) first."""
        left = min(n, 128 * 1024 * 1024)
        while left > 0:
            chunk = self.rfile.read(min(left, 1 << 20))
            if not chunk:
                break
            left -= len(chunk)
        self.close_connection = True

    def _body(self):
        try:
            ln = int(self.headers.get("Content-Length", 0))
        except ValueError:
            ln = 0
        if ln > MAX_BODY:
            self._drain(ln)
            return TOO_LARGE
        raw = self.rfile.read(ln) if ln else b"{}"
        try:
            return json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            return None


    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        if self.path == "/status":
            with _stats_lock:
                s = _deep_stats()
            s["uptime"] = int(time.time() - s.pop("started"))
            return self._send(200, s)
        if self.path in ("/v1/models", "/v1/models/"):
            data = [{"id": m, "object": "model", "owned_by": "opencode-zen",
                     "context_window": v["context"]} for m, v in MODELS.items()]
            return self._send(200, {"object": "list", "data": data})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth_ok():
            return self._send(401, {"error": "bad proxy key"})
        body = self._body()
        if body is TOO_LARGE:
            return self._send(413, {"error": "request body too large"})
        if body is None:
            return self._send(400, {"error": "invalid json"})
        if self.path == "/v1/chat/completions":
            return self.handle_chat(body)
        if self.path == "/v1/responses":
            return self.handle_responses(body)
        if self.path == "/v1/messages":
            return self.handle_messages(body)
        return self._send(404, {"error": "unknown endpoint (use /v1/chat/completions, /v1/responses, /v1/messages)"})

    # ---- /v1/chat/completions (OpenAI-compatible) ----
    def handle_chat(self, body):
        model = body.get("model", "")
        short = short_name(model)
        if short not in MODELS:
            # paid-model gate (akashdeep 422) + fallback (usa-w x-model-fallback)
            if FALLBACK_MODEL in MODELS:
                with _stats_lock:
                    _stats["fallback_used"] += 1
                body = dict(body, model=FALLBACK_MODEL)
                short = FALLBACK_MODEL
                fallback_hdr = {"x-model-fallback": f"{model} -> {short}"}
            else:
                stat(model, 422)
                return self._send(422, {"error": f"unknown/free model only: {chat_model_ids()}"})
        else:
            fallback_hdr = {}
        if MODELS[short]["protocol"] == "responses":
            stat(short, 400)
            return self._send(400, {"error": f"{short} is a /v1/responses model; call /v1/responses"})
        client_stream = body.get("stream", False)
        # fingerprint: force stream upstream, inject read+shell (usa-w prepareZenBody)
        up = dict(body, model=short, stream=True,
                  stream_options={"include_usage": True},
                  tools=ensure_chat_tools(body.get("tools")))
        ses = session_for(self.client_address[0], self.headers.get("x-opencode-session"))
        status, resp, err = upstream_post("/chat/completions", up, ses, True)
        if err is not None:
            stat(short, status)
            try:
                return self._send(status, json.loads(err.decode()),
                                  {**fallback_hdr, "Retry-After": "60"} if status == 429 else fallback_hdr)
            except ValueError:
                return self._send(status, {"error": "upstream error"}, fallback_hdr)
        if client_stream:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("X-Accel-Buffering", "no")
            for k, v in fallback_hdr.items():
                self.send_header(k, v)
            self.end_headers()
            try:
                while True:
                    chunk = resp.read(32768)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        break
            finally:
                resp.close()
            stat(short, 200)
            return
        # aggregate SSE -> JSON (usa-w aggregateSseToJson)
        text, tool_calls, usage = "", [], None
        buf = b""
        while True:
            chunk = resp.read(32768)
            if not chunk:
                break
            buf += chunk
        resp.close()
        for line in buf.decode(errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                continue
            try:
                ev = json.loads(data)
            except ValueError:
                continue
            for ch in ev.get("choices", []):
                d = ch.get("delta", {})
                if isinstance(d.get("content"), str):
                    text += d["content"]
                for tc in d.get("tool_calls", []) or []:
                    tool_calls.append(tc)
            if ev.get("usage"):
                usage = ev["usage"]
        msg = {"role": "assistant", "content": text or None}
        if tool_calls:
            # merge streaming tool-call deltas by index, drop dummies
            merged = {}
            for tc in tool_calls:
                idx = tc.get("index", 0)
                m = merged.setdefault(idx, {"id": tc.get("id", ""), "type": "function",
                                            "function": {"name": "", "arguments": ""}})
                f = tc.get("function", {})
                if f.get("name"):
                    m["function"]["name"] = f["name"]
                if f.get("arguments"):
                    m["function"]["arguments"] += f["arguments"]
                if tc.get("id"):
                    m["id"] = tc["id"]
            msg["tool_calls"] = [m for m in merged.values()
                                 if m["function"]["name"] not in DUMMY_NAMES]
            if not msg["tool_calls"]:
                msg.pop("tool_calls")
        out = {"id": f"chatcmpl-{secrets.token_hex(8)}", "object": "chat.completion",
               "created": int(time.time()), "model": short,
               "choices": [{"index": 0, "message": msg, "finish_reason": "stop"}],
               "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
        stat(short, 200)
        return self._send(200, out, fallback_hdr)

    # ---- /v1/responses (OpenAI Responses) ----
    def handle_responses(self, body):
        model = body.get("model", "")
        short = short_name(model)
        if short not in MODELS or MODELS[short]["protocol"] != "responses":
            stat(model, 422)
            return self._send(422, {"error": f"responses model required, free: "
                                             f"{responses_model_ids()}"})
        client_stream = body.get("stream", False)
        up = dict(body, model=short, store=False, stream=True,
                  tools=ensure_resp_tools(body.get("tools")))
        ses = session_for(self.client_address[0], self.headers.get("x-opencode-session"))
        status, resp, err = upstream_post("/responses", up, ses, True)
        if err is not None:
            stat(short, status)
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
                while True:
                    chunk = resp.read(32768)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        break
            finally:
                resp.close()
            stat(short, 200)
            return
        # best-effort aggregate: prefer response.completed event, else concat output_text
        raw = b""
        while True:
            chunk = resp.read(32768)
            if not chunk:
                break
            raw += chunk
        resp.close()
        completed = None
        texts = []
        for line in raw.decode(errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            try:
                ev = json.loads(data)
            except ValueError:
                continue
            if ev.get("type") == "response.completed" and isinstance(ev.get("response"), dict):
                completed = ev["response"]
            if ev.get("type") == "response.output_text.delta" and isinstance(ev.get("delta"), str):
                texts.append(ev["delta"])
        if completed is not None:
            # strip dummy function_call items
            out = [i for i in completed.get("output", [])
                   if not (isinstance(i, dict) and i.get("type") == "function_call"
                           and i.get("name") in DUMMY_NAMES)]
            completed = dict(completed, output=out)
            stat(short, 200)
            return self._send(200, completed)
        stat(short, 200)
        return self._send(200, {"id": f"resp_{secrets.token_hex(8)}", "object": "response",
                                "status": "completed", "model": short,
                                "output": [{"type": "message", "role": "assistant",
                                            "content": [{"type": "output_text", "text": "".join(texts)}]}]})

    # ---- /v1/messages (Anthropic native passthrough, beta) ----
    def handle_messages(self, body):
        model = body.get("model", "")
        short = short_name(model)
        if short not in MODELS:
            stat(model, 422)
            return self._send(422, {"error": f"free models only: {chat_model_ids()}"})
        client_stream = bool(body.get("stream", False))
        up = dict(body, model=short, stream=client_stream,
                  tools=ensure_ant_tools(body.get("tools")))
        up.setdefault("max_tokens", 1024)
        ses = session_for(self.client_address[0], self.headers.get("x-opencode-session"))
        status, resp, err = upstream_post("/messages", up, ses, client_stream, {
            "anthropic-version": self.headers.get("anthropic-version", "2023-06-01"),
        })
        if err is not None:
            stat(short, status)
            try:
                return self._send(status, json.loads(err.decode()))
            except ValueError:
                return self._send(status, {"error": "upstream error"})
        try:
            if client_stream:
                self._stream_messages(resp, short)
            else:
                self._json_messages(resp, short)
        finally:
            resp.close()

    def _json_messages(self, resp, short):
        """Non-streaming: strip the gate dummy tool_use blocks Zen echoes back."""
        try:
            msg = json.loads(resp.read().decode(errors="replace"))
        except ValueError:
            stat(short, 502)
            return self._send(502, {"error": "upstream sent a non-JSON body"})
        if isinstance(msg, dict) and isinstance(msg.get("content"), list):
            kept = [b for b in msg["content"]
                    if not (isinstance(b, dict) and b.get("type") == "tool_use"
                            and b.get("name") in DUMMY_NAMES)]
            if len(kept) != len(msg["content"]):
                msg["content"] = kept
                if msg.get("stop_reason") == "tool_use" and not any(
                        b.get("type") == "tool_use" for b in kept):
                    msg["stop_reason"] = "end_turn"
        stat(short, 200)
        return self._send(200, msg)

    def _stream_messages(self, resp, short):
        """Streaming: relay the Anthropic event stream, dropping whole dummy
        tool_use blocks (start + deltas + stop) so a gate dummy never reaches
        the client as a real tool invocation."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        dummy_idx, real_tool_use, broken = set(), False, False
        for raw_line in resp:
            if broken:
                break
            line = raw_line.decode(errors="replace").rstrip("\r\n")
            if not line.startswith("data:"):
                out = line + "\n"          # event:/ping/keep-alive pass through
            else:
                try:
                    data = json.loads(line[5:].strip() or "{}")
                except ValueError:
                    out = line + "\n"
                    data = None
                if data is not None:
                    kind = data.get("type")
                    if kind == "content_block_start":
                        block = data.get("content_block") or {}
                        if block.get("type") == "tool_use":
                            if block.get("name") in DUMMY_NAMES:
                                dummy_idx.add(data.get("index"))
                                continue
                            real_tool_use = True
                    elif kind in ("content_block_delta", "content_block_stop"):
                        if data.get("index") in dummy_idx:
                            continue
                    elif kind == "message_delta":
                        delta = data.get("delta") or {}
                        if delta.get("stop_reason") == "tool_use" and not real_tool_use:
                            data = dict(data, delta=dict(delta, stop_reason="end_turn"))
                    out = f"data: {json.dumps(data)}\n\n"
            try:
                self.wfile.write(out.encode())
            except (BrokenPipeError, ConnectionResetError):
                broken = True
        stat(short, 200)


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    print(f"opproxy on :{PORT} upstream={UPSTREAM} "
          f"auth={'BYOK' if ZEN_KEY != 'public' else 'public-anon'} "
          f"proxy={'rotating-egress' if UPSTREAM_PROXY else 'direct'}", flush=True)
    srv.serve_forever()
