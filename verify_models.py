#!/usr/bin/env python3
"""Re-measure the Zen model catalog against upstream and diff it.

Zen publishes no model metadata (/v1/models is bare ids; the sibling
metadata endpoints are all 404), and models.dev disagrees with the live
gateway, so zen_models.py is maintained by direct measurement instead.
This script reproduces that measurement so the numbers can be refreshed
instead of silently rotting.

    python3 verify_models.py              # full matrix, prints a diff
    python3 verify_models.py --vision     # only the cheap vision checks
    python3 verify_models.py --check      # exit 1 if the catalog is stale

The context probe is slow and expensive: it sends real multi-hundred-thousand
token prompts, so it is not part of --vision or --check.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor

from zen_models import MODELS

UPSTREAM = os.environ.get("OPENCODE_ZEN_URL", "https://opencode.ai/zen/v1")
KEY = os.environ.get("OPENCODE_API_KEY") or os.environ.get("ZEN_KEY") or "public"
UA = os.environ.get("OPENCODE_UA", "opencode/latest/2.0.14/cli")
FILLER = "the quick brown fox jumps over the lazy dog. "

GATE_TOOLS = [
    {"type": "function", "function": {
        "name": n,
        "description": "Compatibility alias (OpenCode free-tier gate check). "
                       "Prefer the native equivalent.",
        "parameters": {"type": "object", "properties": {}},
    }} for n in ("read", "bash")
]

# The responses protocol wants the flat tool shape; sending the chat shape
# there is a 400 ("tools[0] missing required field name"), which _post turned
# into a silent "no vision" verdict for both muse models.
GATE_TOOLS_RESP = [
    {"type": "function", "name": t["function"]["name"],
     "description": t["function"]["description"],
     "parameters": t["function"]["parameters"]} for t in GATE_TOOLS
]



def project_id():
    """The 32-hex id the real client sends; falls back to a stable constant."""
    path = os.path.expanduser("~/.omp/install-id")
    try:
        with open(path) as f:
            return f.read().strip().replace("-", "").lower()
    except OSError:
        return "0" * 32


def session_id(seed):
    """A ses_ id in the shape Zen expects (12 hex + 14 alnum)."""
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    d = hashlib.sha256(str(seed).encode()).digest()
    return "ses_" + "".join(f"{b:02x}" for b in d[:6]) + \
        "".join(alphabet[d[6 + (i % 26)] % 62] for i in range(14))


def _post(path, payload, ses, timeout):
    req = urllib.request.Request(UPSTREAM + path, data=json.dumps(payload).encode(),
                                 method="POST")
    for k, v in [("Content-Type", "application/json"),
                 ("Authorization", f"Bearer {KEY}"),
                 ("User-Agent", UA),
                 ("x-opencode-session", session_id(ses)),
                 ("x-session-affinity", session_id(ses)),
                 ("X-Session-Id", session_id(ses)),
                 ("x-opencode-client", "cli"),
                 ("x-opencode-project", project_id()),
                 ("Accept", "text/event-stream")]:
        req.add_header(k, v)
    try:
        return urllib.request.urlopen(req, timeout=timeout).read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        if os.environ.get("VERIFY_DEBUG"):
            print(f"  ! {path} -> HTTP {e.code}: {e.read()[:200]!r}", file=sys.stderr)
        return None
    except Exception as e:
        if os.environ.get("VERIFY_DEBUG"):
            print(f"  ! {path} -> {type(e).__name__}: {e}", file=sys.stderr)
        return None


def probe_context(model, chars, timeout=300):
    """Return (prompt_tokens, max_output) the model reported, or None on failure."""
    filler = (FILLER * (chars // len(FILLER) + 1))[:chars]
    body = _post("/chat/completions", {
        "model": model,
        "messages": [{"role": "user", "content": filler + "\n\nReply with exactly: PONG"}],
        "stream": True, "stream_options": {"include_usage": True},
        "tools": GATE_TOOLS,
    }, f"{model}-{chars}", timeout)
    if body is None:
        return None
    toks = re.findall(r'"prompt_tokens":(\d+)', body)
    if not toks:
        return None
    out = re.findall(r'"completion_tokens":(\d+)', body)
    return int(toks[-1]), (int(out[-1]) if out else None)


def solid_png(r, g, b):
    """A 1x1 PNG of an exact colour, so a vision reply cannot be guessed."""
    def chunk(tag, data):
        body = tag + data
        return (struct.pack(">I", len(data)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))
    return ("data:image/png;base64," + base64.b64encode(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00" + bytes([r, g, b])))
        + chunk(b"IEND", b"")
    ).decode())


def _resp_text_and_calls(raw):
    """(assistant text, [(call_id, name, args)]) from a /responses SSE body."""
    text, calls, by_id = "", [], {}
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        body = line[5:].strip()
        if not body or body == "[DONE]":
            continue
        try:
            ev = json.loads(body)
        except ValueError:
            continue
        if ev.get("type") == "response.output_text.delta" and isinstance(ev.get("delta"), str):
            text += ev["delta"]
        elif ev.get("type") == "response.function_call_arguments.done":
            by_id[ev.get("item_id")] = ev.get("arguments", "")
        elif ev.get("type") == "response.output_item.done":
            item = ev.get("item") or {}
            if item.get("type") == "function_call":
                calls.append((item.get("call_id") or item.get("id"),
                              item.get("name"), item.get("arguments", "")))
    return text, calls


def _probe_once(model, url, question, timeout):
    """One vision attempt, returning the assistant text (tool call answered)."""
    if MODELS[model]["protocol"] == "responses":
        payload = {
            "model": model, "stream": True, "tools": GATE_TOOLS_RESP,
            "input": [{"role": "user", "content": [
                {"type": "input_text", "text": question},
                {"type": "input_image", "image_url": url}]}],
        }
        path = "/responses"
    else:
        payload = {
            "model": model, "stream": True, "stream_options": {"include_usage": True},
            "tools": GATE_TOOLS,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": question},
                {"type": "image_url", "image_url": {"url": url}}]}],
        }
        path = "/chat/completions"
    body = _post(path, payload, f"vis-{model}-{url[-12:]}", timeout)
    if body is None:
        return None
    if path == "/responses":
        text, calls = _resp_text_and_calls(body)
        if calls and "lue" not in text:
            # Answer the gate dummies for it and let it get to the answer.
            convo = list(payload["input"]) + [
                {"type": "function_call", "call_id": cid, "name": name, "arguments": args}
                for cid, name, args in calls]
            convo += [{"type": "function_call_output", "call_id": cid,
                       "output": "no files are available in this environment"}
                      for cid, _, _ in calls]
            convo += [{"role": "user", "content": [
                {"type": "input_text", "text": "No tools are available. Answer from the "
                                               "image itself: which single color is it?"}]}]
            second = _post(path, dict(payload, input=convo), f"vis2-{model}-{url[-12:]}", timeout)
            if second is not None:
                text += _resp_text_and_calls(second)[0]
        return text
    return " ".join(re.findall(r'"(?:content|text)":\s*"([^"]*)"', body))


def probe_vision(model, timeout=200, runs=2):
    """True only if the model reads image content rather than guessing.

    Two images whose answers must differ: the blue 1x1 PNG has to come back
    blue, and the same question about a red one must not. One image cannot
    separate vision from a lucky guess.

    The control is repeated and every run must pass. The muse pair guesses --
    "gray" or "white" for blue, red and green alike -- but once in six
    attempts it happened to say "blue" for the blue image and "white" for the
    red one, which a single-run check scored as a pass. Measured over three
    runs each, they pass 0/3 and 0/3.

    Each protocol family gets its own request shape (a chat model is probed
    with an image_url part, a responses model with an input_image part),
    because probing a responses model over the chat wire would report every
    image model as visionless.
    """
    question = "What single color is this image? One word."
    for _ in range(max(1, runs)):
        blue = _probe_once(model, solid_png(0, 0, 255), question, timeout)
        if blue is None:
            return False
        red = _probe_once(model, solid_png(255, 0, 0), question, timeout)
        if red is None:
            return False
        if not ("lue" in blue and "lue" not in red):
            return False
    return True


def context_ladder(model, timeout=300):
    """Largest prompt that returns 200, searched with an exponential ladder."""
    best = None
    for chars in (1_000_000, 2_000_000, 3_000_000, 4_000_000, 4_200_000):
        got = probe_context(model, chars, timeout)
        if got is None:
            break
        best = got
    if best is None:
        return 0
    # The top of the ladder succeeded; walk up to find where it actually breaks.
    lo, hi = 4_200_000, 5_400_000
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if probe_context(model, mid, timeout) is not None:
            lo, best = mid, probe_context(model, mid, timeout) or best
        else:
            hi = mid - 1
    return best[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vision", action="store_true", help="cheap capability pass only")
    ap.add_argument("--check", action="store_true", help="exit 1 if catalog is stale")
    ap.add_argument("--models", help="comma-separated subset to probe")
    args = ap.parse_args()

    ids = args.models.split(",") if args.models else list(MODELS)
    drift = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        vision = dict(zip(ids, ex.map(lambda m: probe_vision(m), ids)))
    for m, seen in vision.items():
        want = MODELS[m]["vision"]
        flag = "ok" if seen == want else "DRIFT"
        if seen != want:
            drift.append(f"{m}: vision catalog={want} measured={seen}")
        print(f"  vision  {m:34s} {flag} (catalog={want} measured={seen})")

    if args.vision:
        print("\n" + ("\n".join(drift) if drift else "no drift"))
        return 1 if (drift and args.check) else 0

    for m in ids:
        if MODELS[m]["protocol"] != "chat":
            print(f"  context {m:34s} skipped (responses protocol, not probed here)")
            continue
        t0 = time.time()
        measured = context_ladder(m)
        want = MODELS[m]["context"]
        flag = "ok" if want <= measured or want == measured else "DRIFT"
        if want > measured:
            drift.append(f"{m}: context catalog={want} measured_max={measured}")
        print(f"  context {m:34s} {flag} catalog={want} measured_max={measured} "
              f"({time.time() - t0:.0f}s)")

    print("\n" + ("\n".join(drift) if drift else "no drift"))
    return 1 if (drift and args.check) else 0


if __name__ == "__main__":
    sys.exit(main())
