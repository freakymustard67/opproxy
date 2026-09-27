"""Standalone Zen free-model client, replicating opencode V2 (no API key).
Requires: Authorization Bearer public + opencode UA + valid ses_ ID + stream:true + tools[read,shell].
"""
import json, secrets, time, urllib.request, urllib.error

ZEN = "https://opencode.ai/zen/v1"
UA = "opencode/latest/2.0.18/cli"
CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def make_ses() -> str:
    ts = int(time.time() * 1000)
    cur = (~((ts * 0x1000 + 1))) & ((1 << 48) - 1)
    t = "".join(f"{(cur >> (40 - 8 * i)) & 0xff:02x}" for i in range(6))
    return "ses_" + t + "".join(CHARS[secrets.randbelow(62)] for _ in range(14))

def base_headers(ses: str) -> dict:
    return {
        "Content-Type": "application/json",
        "Authorization": "Bearer public",
        "User-Agent": UA,
        "x-opencode-session": ses,
    }

def post_stream(path: str, payload: dict):
    ses = make_ses()
    req = urllib.request.Request(ZEN + path, data=json.dumps(payload).encode(), method="POST")
    for k, v in base_headers(ses).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            buf = b""
            while True:
                chunk = r.read(4096)
                if not chunk:
                    break
                buf += chunk
                print(chunk.decode(errors="replace"), end="", flush=True)
            print()
            return buf
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read()[:500]}")
        raise

# Tools: names matter (read+shell required), schemas can be minimal.
CHAT_TOOLS = [
    {"type": "function", "function": {"name": "read", "description": "x", "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "shell", "description": "x", "parameters": {"type": "object", "properties": {}}}},
]
RESP_TOOLS = [
    {"type": "function", "name": "read", "description": "x", "parameters": {"type": "object", "properties": {}}},
    {"type": "function", "name": "shell", "description": "x", "parameters": {"type": "object", "properties": {}}},
]

def chat(model: str, text: str):
    """openai-compatible free: big-pickle, space-bunny-free, mimo-*, etc."""
    return post_stream("/chat/completions", {
        "model": model,
        "messages": [{"role": "user", "content": text}],
        "stream": True,
        "stream_options": {"include_usage": True},
        "tools": CHAT_TOOLS,
    })

def responses(model: str, text: str):
    """openai free: muse-spark-1.3-contributor-free, etc."""
    return post_stream("/responses", {
        "model": model,
        "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}],
        "store": False,
        "stream": True,
        "tools": RESP_TOOLS,
    })

if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "chat"
    model = sys.argv[2] if len(sys.argv) > 2 else "big-pickle"
    text = sys.argv[3] if len(sys.argv) > 3 else "say ok"
    (chat if mode == "chat" else responses)(model, text)
