"""Zen free-model catalog, shared by opproxy.py and opproxy_general.py.

Both proxies used to carry their own hardcoded list, which silently drifted
out of sync with upstream: ids that Zen had already dropped kept being
advertised on /v1/models and answered 401/400 at request time.

Every id below was probed on its own protocol against the anonymous upstream
and answered 200. Upstream protocol families are chat (/chat/completions) and
responses (/responses); Zen's /messages endpoint is not a separate model
family -- it serves whichever models accept the Anthropic wire format (today
only space-bunny-free), so `protocol` never claims it.

Context windows are inherited from the original models.dev-derived table and
are NOT verified: a 250k-token prompt was accepted by every chat model here
and rejected by big-pickle at ~1M tokens, but that 400 is ambiguous (upstream
also rejects oversized bodies), so the legacy numbers are kept as-is rather
than invented. Treat them as hints.
"""
MODELS = {
    "big-pickle": {"protocol": "chat", "context": 1048576},
    "space-bunny-free": {"protocol": "chat", "context": 1048576},
    "longcat-2.5-preview-free": {"protocol": "chat", "context": 200000},
    "mimo-v2.6-flash-free": {"protocol": "chat", "context": 200000},
    "mimo-v2.5-free": {"protocol": "chat", "context": 200000},
    "ling-3.0-flash-fin-free": {"protocol": "chat", "context": 200000},
    "nemotron-3-ultra-free": {"protocol": "chat", "context": 200000},
    "nemotron-3.5-lightning-free": {"protocol": "chat", "context": 200000},
    "muse-spark-1.3-contributor-free": {"protocol": "responses", "context": 1048576},
    "muse-spark-1.2-contributor-free": {"protocol": "responses", "context": 1048576},
}

# Free ids that upstream no longer serves, kept out of MODELS on purpose so a
# future contributor does not "restore" them from an old README:
#   kimi-k2.5-free, glm-5-free, mimo-v2-pro-free, qwen3.6-plus-free,
#   minimax-m2.5-free, minimax-m3-free  -> 401 ModelError, absent from /v1/models
#   jev-1.13-free                        -> 500 on every protocol
#   deepseek-v4-flash-free                -> 400 "Model is unavailable" (provider down)
RETIRED = {
    "kimi-k2.5-free": "401 ModelError, not in upstream catalog",
    "glm-5-free": "401 ModelError, not in upstream catalog",
    "mimo-v2-pro-free": "401 ModelError, not in upstream catalog",
    "qwen3.6-plus-free": "401 ModelError, not in upstream catalog",
    "minimax-m2.5-free": "401 ModelError, not in upstream catalog",
    "minimax-m3-free": "401 ModelError, not in upstream catalog",
    "jev-1.13-free": "500 on chat/responses/messages",
    "deepseek-v4-flash-free": "400 Model is unavailable (provider down)",
}


def chat_model_ids():
    """Ids served on /v1/chat/completions, in catalog order."""
    return [m for m, v in MODELS.items() if v["protocol"] == "chat"]


def responses_model_ids():
    """Ids served on /v1/responses, in catalog order."""
    return [m for m, v in MODELS.items() if v["protocol"] == "responses"]


def short_name(model):
    """Strip the `provider/model` and `model:tag` decorations clients add."""
    return str(model or "").split("/")[-1].split(":")[0]
