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
import hashlib
import json
import os
import re
import secrets
import socket
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
UA = os.environ.get("OPENCODE_UA", "opencode/latest/2.0.14/cli")
UPSTREAM_PROXY = os.environ.get("UPSTREAM_PROXY")  # e.g. http://user:pass@host:3128 (v6pool-style rotation)
FALLBACK_MODEL = os.environ.get("FALLBACK_MODEL", "big-pickle")

ses_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# Fingerprint values below are ported from ~/omp-zen-proxy/main.ts, which is
# the implementation verified working against the live gate. Where opproxy
# previously guessed, it now matches that reference:
#   * UA 2.0.14 (was 2.0.18, a version nothing here ever verified)
#   * x-opencode-project is a real 32-hex id (was the literal "global")
#   * x-opencode-session + x-session-affinity + X-Session-Id, all set
#   * session id is sha256-derived (was a timestamp bit-pattern)
#   * gate tools are read + bash (was read + shell)
OPENCODE_CLIENT = os.environ.get("OPENCODE_SPOOF_CLIENT", "cli")
RESERVED_TOOLS = {"web_search": "hermes_web_search", "search_files": "hermes_search_files"}

# Free models live in zen_models.py (single source of truth, probed against
# upstream). Upstream protocol families: chat -> /chat/completions,
# responses -> /responses. /v1/messages is a native Anthropic passthrough and
# serves whichever catalog model accepts that wire format, so it is not a
# model family of its own.


DUMMY_CHAT_TOOLS = [
    {"type": "function", "function": {"name": "read", "description": "Compatibility alias (OpenCode free-tier gate check). Prefer the native equivalent.", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "bash", "description": "Compatibility alias (OpenCode free-tier gate check). Prefer the native equivalent.", "parameters": {"type": "object", "properties": {}}}},
]
DUMMY_RESP_TOOLS = [
    {"type": "function", "name": "read", "description": "Compatibility alias (OpenCode free-tier gate check). Prefer the native equivalent.", "parameters": {"type": "object", "properties": {}}},
    {"type": "function", "name": "bash", "description": "Compatibility alias (OpenCode free-tier gate check). Prefer the native equivalent.", "parameters": {"type": "object", "properties": {}}},
]
DUMMY_ANT_TOOLS = [
    {"name": "read", "description": "Compatibility alias (OpenCode free-tier gate check). Prefer the native equivalent.", "input_schema": {"type": "object", "properties": {}}},
    {"name": "bash", "description": "Compatibility alias (OpenCode free-tier gate check). Prefer the native equivalent.", "input_schema": {"type": "object", "properties": {}}},
]
DUMMY_NAMES = {"read", "shell", "bash"}

MAX_BODY = 50 * 1024 * 1024
TOO_LARGE = object()   # sentinel: body over MAX_BODY (distinct from bad JSON)

SES_RE = re.compile(r"^ses_[0-9a-f]{12}[0-9A-Za-z]{14}$")
PROJECT_RE = re.compile(r"^[0-9a-f]{32}$")


def _install_id():
    try:
        with open(os.path.join(os.path.expanduser("~"), ".omp", "install-id")) as fh:
            return fh.read()
    except OSError:
        return None


def project_id():
    """32-hex project id from OPENCODE_SPOOF_PROJECT_ID or ~/.omp/install-id.
    Omitted when unavailable: the reference proxy omits it too, and a bogus
    value (opproxy sent the literal "global") is worse than none."""
    for raw in (os.environ.get("OPENCODE_SPOOF_PROJECT_ID"), _install_id()):
        if not raw:
            continue
        cleaned = raw.strip().replace("-", "").lower()
        if PROJECT_RE.match(cleaned):
            return cleaned
    return None


def to_ses(seed):
    """ses_<12 hex><14 base62> — the shape opencode sends. sha256-derived from
    the client's own session id so stickiness survives, matching
    omp-zen-proxy's toOpencodeSessionId."""
    digest = hashlib.sha256(str(seed).encode()).digest()
    hexpart = "".join(f"{b:02x}" for b in digest[:6])
    tail = "".join(ses_CHARS[digest[6 + (i % 26)] % 62] for i in range(14))
    return "ses_" + hexpart + tail


def wire_tool_name(tool):
    if not isinstance(tool, dict):
        return None
    fn = tool.get("function")
    if isinstance(fn, dict) and isinstance(fn.get("name"), str):
        return fn["name"]
    return tool.get("name") if isinstance(tool.get("name"), str) else None


def alias_reserved_tools(body, is_python_client):
    """Zen reserves web_search/search_files server-side and 400s client
    functions using those names, and rejects the `strict` key. Gated on the
    OpenAI Python SDK fingerprint so omp (no de-alias mapping) is untouched,
    exactly as omp-zen-proxy does it."""
    if not is_python_client:
        return False
    changed = False
    for t in body.get("tools") or []:
        if not isinstance(t, dict):
            continue
        if "strict" in t:
            t.pop("strict")
            changed = True
        name = wire_tool_name(t)
        if name in RESERVED_TOOLS:
            if isinstance(t.get("function"), dict):
                t["function"]["name"] = RESERVED_TOOLS[name]
            else:
                t["name"] = RESERVED_TOOLS[name]
            changed = True
    tc = body.get("tool_choice")
    if isinstance(tc, dict) and wire_tool_name(tc) in RESERVED_TOOLS:
        name = wire_tool_name(tc)
        if isinstance(tc.get("function"), dict):
            tc["function"]["name"] = RESERVED_TOOLS[name]
        else:
            tc["name"] = RESERVED_TOOLS[name]
        changed = True
    return changed


def incoming_session(headers):
    """Any session header a client may use, as omp-zen-proxy reads them."""
    for name in ("x-opencode-session", "x-session-affinity", "x-session-id"):
        value = (headers.get(name) or "").strip()
        if value:
            return value
    return None

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
    """Random seed for a session id. The id itself is sha256-derived in
    to_ses(), matching what opencode actually emits."""
    return f"{time.time_ns()}-{secrets.token_hex(8)}"




_sessions, _sessions_lock = {}, threading.Lock()  # per-client-IP sticky ses, 30m (bigdata)


def session_for(client_ip, provided):
    """Reuse the client's own session when it sends one (any of the three
    headers), otherwise keep one sticky per client IP for 30 minutes."""
    if provided and SES_RE.match(provided):
        return provided
    now = time.time()
    with _sessions_lock:
        ent = _sessions.get(client_ip)
        if ent and now - ent[1] < 1800:
            return ent[0]
        ses = to_ses(provided or make_ses())
        _sessions[client_ip] = (ses, now)
        if len(_sessions) > 10000:  # LRU-ish clear (akashdeep)
            _sessions.clear()
        return ses



def ensure_chat_tools(tools):
    tools = list(tools or [])
    names = {n for n in (wire_tool_name(t) for t in tools) if n}
    if "read" not in names:
        tools.append(DUMMY_CHAT_TOOLS[0])
    if "bash" not in names and "shell" not in names:
        tools.append(DUMMY_CHAT_TOOLS[1])
    return tools



def ensure_resp_tools(tools):
    tools = list(tools or [])
    names = {n for n in (wire_tool_name(t) for t in tools) if n}
    if "read" not in names:
        tools.append(DUMMY_RESP_TOOLS[0])
    if "bash" not in names and "shell" not in names:
        tools.append(DUMMY_RESP_TOOLS[1])
    return tools


def ensure_ant_tools(tools):
    tools = list(tools or [])
    names = {n for n in (wire_tool_name(t) for t in tools) if n}
    if "read" not in names:
        tools.append(DUMMY_ANT_TOOLS[0])
    if "bash" not in names and "shell" not in names:
        tools.append(DUMMY_ANT_TOOLS[1])
    return tools


def upstream_post(path, payload, ses, stream_want, extra_headers=None):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(UPSTREAM + path, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {ZEN_KEY}")
    req.add_header("User-Agent", UA)
    req.add_header("x-opencode-client", OPENCODE_CLIENT)
    req.add_header("x-opencode-session", ses)
    req.add_header("x-session-affinity", ses)
    req.add_header("X-Session-Id", ses)
    project = project_id()
    if project:
        req.add_header("x-opencode-project", project)
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
        try:
            if self.path == "/v1/chat/completions":
                return self.handle_chat(body)
            if self.path == "/v1/responses":
                return self.handle_responses(body)
            if self.path == "/v1/messages":
                return self.handle_messages(body)
            return self._send(404, {"error": "unknown endpoint (use /v1/chat/completions, /v1/responses, /v1/messages)"})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:  # noqa: BLE001 - a handler bug must not look like a dead proxy
            # An unhandled exception here used to close the socket with no
            # response at all, which clients report as "retrying" forever.
            stat("proxy", 500)
            return self._send(500, {"error": {"type": "proxy_error",
                                              "message": f"{type(e).__name__}: {e}"[:200]}})

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
        # fingerprint: force stream upstream, inject the read+bash gate pair
        alias_reserved_tools(body, self.headers.get("x-stainless-lang") == "python")
        up = dict(body, model=short, stream=True,
                  stream_options={"include_usage": True},
                  tools=ensure_chat_tools(body.get("tools")))
        ses = session_for(self.client_address[0], incoming_session(self.headers))
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
                self._relay_chat_sse(resp)
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
        if not (msg.get("content") or "").strip() and "tool_calls" not in msg:
            # Upstream produced neither text nor a real tool call (typically a
            # dummy-only call that was stripped). A 200 with an empty message
            # is indistinguishable from a legitimately blank answer, so the
            # client just stores nothing and retries.
            stat(short, 502)
            return self._send(502, {"error": {
                "type": "empty_upstream_response",
                "message": "upstream returned no content and no non-dummy tool call"}},
                fallback_hdr)
        out = {"id": f"chatcmpl-{secrets.token_hex(8)}", "object": "chat.completion",
               "created": int(time.time()), "model": short,
               "choices": [{"index": 0, "message": msg,
                            "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}],
               "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
        stat(short, 200)
        return self._send(200, out, fallback_hdr)

    def _relay_chat_sse(self, resp):
        """Relay chat SSE with the gate dummy tool calls removed.

        The raw byte relay forwarded `read`/`shell` calls as real invocations,
        so a tool-using client (hermes, omp) tried to execute them. Tool-call
        deltas are fragmented — the first fragment carries the name, later
        ones only arguments — so each index is remembered once identified.
        Zen's trailing {"choices":[],"cost":"0"} event is dropped as a side
        effect: it carries neither choices nor usage.
        """
        dummy_idx, real_call = set(), False
        for raw_line in resp:
            line = raw_line.decode(errors="replace").rstrip("\r\n")
            if not line.startswith("data:"):
                out = line + "\n"
            else:
                payload = line[5:].strip()
                try:
                    ev = json.loads(payload) if payload and payload != "[DONE]" else None
                except ValueError:
                    ev = None
                if ev is None:
                    out = line + "\n"
                else:
                    choices = ev.get("choices") or []
                    for ch in choices:
                        delta = ch.get("delta") or {}
                        kept = []
                        for tc in delta.get("tool_calls") or []:
                            idx = tc.get("index", 0)
                            name = (tc.get("function") or {}).get("name")
                            if name in DUMMY_NAMES:
                                dummy_idx.add(idx)
                            elif name:
                                real_call = True
                            if idx not in dummy_idx:
                                kept.append(tc)
                        if delta.get("tool_calls"):
                            if kept:
                                delta["tool_calls"] = kept
                            else:
                                delta.pop("tool_calls")
                        if ch.get("finish_reason") == "tool_calls" and not real_call:
                            ch["finish_reason"] = "stop"
                    if not ev.get("usage") and not any(
                            (ch.get("delta") or ch.get("finish_reason")) for ch in choices):
                        continue
                    out = f"data: {json.dumps(ev)}\n\n"
            try:
                self.wfile.write(out.encode())
            except (BrokenPipeError, ConnectionResetError):
                return


    # ---- /v1/responses (OpenAI Responses) ----
    def handle_responses(self, body):
        model = body.get("model", "")
        short = short_name(model)
        if short not in MODELS or MODELS[short]["protocol"] != "responses":
            stat(model, 422)
            return self._send(422, {"error": f"responses model required, free: "
                                             f"{responses_model_ids()}"})
        client_stream = body.get("stream", False)
        alias_reserved_tools(body, self.headers.get("x-stainless-lang") == "python")
        up = dict(body, model=short, store=False, stream=True,
                  tools=ensure_resp_tools(body.get("tools")))
        ses = session_for(self.client_address[0], incoming_session(self.headers))
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
                self._relay_resp_sse(resp)
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

    def _relay_resp_sse(self, resp):
        """Relay Responses SSE with dummy function_call items removed, keyed by
        item_id: an item is announced in response.output_item.added and carries
        its arguments in later function_call_arguments events."""
        dummy_items = set()
        for raw_line in resp:
            line = raw_line.decode(errors="replace").rstrip("\r\n")
            if not line.startswith("data:"):
                out = line + "\n"
            else:
                payload = line[5:].strip()
                try:
                    ev = json.loads(payload) if payload and payload != "[DONE]" else None
                except ValueError:
                    ev = None
                if ev is None:
                    out = line + "\n"
                else:
                    item = ev.get("item") or {}
                    if (ev.get("type") == "response.output_item.added"
                            and item.get("type") == "function_call"
                            and item.get("name") in DUMMY_NAMES):
                        dummy_items.add(item.get("id"))
                        continue
                    if ev.get("item_id") in dummy_items or ev.get("id") in dummy_items:
                        continue
                    if ev.get("type") == "response.completed":
                        obj = ev.get("response")
                        if isinstance(obj, dict) and isinstance(obj.get("output"), list):
                            ev = dict(ev, response=dict(obj, output=[
                                i for i in obj["output"]
                                if not (isinstance(i, dict) and i.get("type") == "function_call"
                                        and i.get("name") in DUMMY_NAMES)]))
                    out = f"data: {json.dumps(ev)}\n\n"
            try:
                self.wfile.write(out.encode())
            except (BrokenPipeError, ConnectionResetError):
                return

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
        ses = session_for(self.client_address[0], incoming_session(self.headers))
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


class Server(ThreadingHTTPServer):
    """Dual-stack, so `localhost` works whichever family the client resolves
    first. A client configured with http://localhost:PORT got connection
    refused on ::1 when the proxy only listened on IPv4."""
    daemon_threads = True
    address_family = socket.AF_INET6
    allow_reuse_address = True

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        return super().server_bind()


def build_server(port):
    try:
        return Server(("::", port), H)
    except OSError:      # host without IPv6
        return ThreadingHTTPServer(("0.0.0.0", port), H)


if __name__ == "__main__":
    srv = build_server(PORT)
    print(f"opproxy on :{PORT} (localhost + 127.0.0.1) upstream={UPSTREAM} "
          f"auth={'BYOK' if ZEN_KEY != 'public' else 'public-anon'} "
          f"project={project_id() or 'unset'} "
          f"proxy={'rotating-egress' if UPSTREAM_PROXY else 'direct'}", flush=True)
    srv.serve_forever()
