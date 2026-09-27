"""Zen free-model catalog, shared by opproxy.py and opproxy_general.py.

Both proxies used to carry their own hardcoded list, which silently drifted
out of sync with upstream: ids that Zen had already dropped kept being
advertised on /v1/models and answered 401/400 at request time.

Every id below was probed on its own protocol against the anonymous upstream
and answered 200. Upstream protocol families are chat (/chat/completions) and
responses (/responses); Zen's /messages endpoint is not a separate model
family -- it serves whichever models accept the Anthropic wire format (today
only space-bunny-free), so `protocol` never claims it.

CONTEXT AND CAPABILITY NUMBERS ARE MEASURED, NOT COPIED
------------------------------------------------------
Zen's public API publishes no model metadata: /v1/models returns bare ids
(verified -- no `context`, `capabilities` or `modalities` keys), and
/v1/models/<id>, /models.json, /config.json, /provider/models, /catalog and
/capabilities are all 404. Third-party sources are not trustworthy here
either: models.dev lists big-pickle at 200000 (it accepted 933768 real prompt
tokens) and marks mimo-v2.5-free deprecated while Zen still serves it.

So the numbers come from Zen itself, by two routes:

 1. Upstream states the limit when you exceed it. Asking for
    max_tokens=3_000_000 returns, verbatim:
      "This endpoint's maximum context length is 1048576 tokens"      (mimo)
      "This endpoint's maximum context length is 262144 tokens"       (ling)
      "This endpoint's maximum context length is 1000000 tokens"      (nemotron)
      "/max_tokens: 3000000 is not less or equal to 262144"           (longcat)
    Those are quoted straight from the error, so they beat any inference.
    big-pickle and space-bunny-free reject an oversized max_tokens with a
    bare "invalid request" and never state a number, so theirs stay
    unconfirmed; the ladder measured 984553 prompt tokens for big-pickle,
    which is consistent with a 1048576 window that a body-size ceiling
    reaches first.
 2. Where upstream will not say, verify_models.py measures it: a prompt of
    N filler characters, and the `prompt_tokens` the model itself reported.

CAPABILITIES COME FROM THE VENDORS, NOT FROM A PIXEL PROBE
---------------------------------------------------------
`vision`, `reasoning` and `tools` are transcribed from the model vendors'
own documentation, because they are facts about the model, not about this
gateway, and a local probe can only ever estimate them:

  * Muse Spark 1.2 / 1.3 (Meta) -- "Muse Spark is a natively multimodal
    reasoning model"; "perceives video, images and documents"; all three
    versions "share the same modalities and context window, 1,048,576 tokens".
    (ai.developer.meta.com/docs/models, dev.meta.ai/docs/models,
    dev.meta.ai/models/muse-spark). So: vision True, context 1048576.
  * Nemotron 3 Ultra and 3.5 Lightning (NVIDIA) -- "Context length: up to 1M
    tokens" (docs.nvidia.com, build.nvidia.com model card), which matches the
    1000000 that upstream states when you exceed it. Nemotron 3.5 Lightning is
    a text-only reasoning model, so vision False.
  * The rest: vision confirmed by the two-image control in verify_models.py
    (a blue 1x1 PNG must come back blue AND a red one must not -- one image
    cannot tell vision from a lucky guess).

That control is advisory, not authoritative, and it is *not* what the catalog
is built from. On a flat 1x1 pixel it is unreliable in both directions: the
muse models answer "gray"/"white" for blue, red and green alike (6 attempts,
0/3 control passes) while being documented multimodal, because naming the
exact colour of a single flat pixel is a different question from whether an
image is understood. A probe that cannot agree with the vendor's own model
card is measuring the probe.

`max_output` is the weakest field. Upstream states a max_tokens ceiling only
for longcat (262144); the vendors publish output caps for some models (NVIDIA
publishes Nemotron 3 Ultra at ~64K output) and nothing at all for others, so
the rest are unverified hints.

See `verify_models.py` to re-run the matrix and refresh the numbers.
"""

# context: upstream-stated where it exists (see above), otherwise measured.
# vision:  two-image control.  max_output: unverified hint.
MODELS = {
    "big-pickle": {
        "protocol": "chat", "context": 1048576, "vision": True,
        "reasoning": True, "tools": True, "max_output": 32000,
    },
    # context unconfirmed upstream (same bare "invalid request" as big-pickle)
    "space-bunny-free": {
        "protocol": "chat", "context": 1048576, "vision": True,
        "reasoning": True, "tools": True, "max_output": 524288,
    },
    # upstream: "/max_tokens: 3000000 is not less or equal to 262144"
    "longcat-2.5-preview-free": {
        "protocol": "chat", "context": 262144, "vision": False,
        "reasoning": True, "tools": True, "max_output": 262144,
    },
    # upstream: "maximum context length is 1048576 tokens"
    "mimo-v2.6-flash-free": {
        "protocol": "chat", "context": 1048576, "vision": True,
        "reasoning": True, "tools": True, "max_output": 32000,
    },
    # upstream: "maximum context length is 1048576 tokens"
    "mimo-v2.5-free": {
        "protocol": "chat", "context": 1048576, "vision": True,
        "reasoning": True, "tools": True, "max_output": 32000,
    },
    # upstream: "maximum context length is 262144 tokens"
    "ling-3.0-flash-fin-free": {
        "protocol": "chat", "context": 262144, "vision": False,
        "reasoning": True, "tools": True, "max_output": 32768,
    },
    # upstream: "maximum context length is 1000000 tokens" (not 1048576)
    "nemotron-3-ultra-free": {
        "protocol": "chat", "context": 1000000, "vision": False,
        "reasoning": True, "tools": True, "max_output": 128000,
    },
    # upstream: "maximum context length is 1000000 tokens" (not 1048576)
    "nemotron-3.5-lightning-free": {
        "protocol": "chat", "context": 1000000, "vision": False,
        "reasoning": True, "tools": True, "max_output": 262144,
    },
    # Meta: "natively multimodal reasoning model", "perceives video, images
    # and documents", all versions share a 1,048,576-token window.
    "muse-spark-1.3-contributor-free": {
        "protocol": "responses", "context": 1048576, "vision": True,
        "reasoning": True, "tools": True, "max_output": 131072,
    },
    # same family, same modalities and context window
    "muse-spark-1.2-contributor-free": {
        "protocol": "responses", "context": 1048576, "vision": True,
        "reasoning": True, "tools": True, "max_output": 131072,
    },
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


def model_info(model_id):
    """Full advertised record for one id, as served on /v1/models.

    Kept in one place so the catalog and the endpoint cannot disagree.

    Zen's own /models is bare (id/object/created/owned_by and nothing else), so
    the fields are emitted in the three shapes clients already parse rather
    than one invented shape nobody reads:

      * OpenAI      — id, object, created, owned_by (the baseline)
      * models.dev  — `limit`, `modalities`, `reasoning`, `tool_call`, `cost`.
                      read by opencode and by hermes' agent/models_dev.py
                      (_parse_model_info), which is where context_window and
                      vision support come from for those clients.
      * OpenRouter  — `supported_parameters`, `context_length`,
                      `architecture.input_modalities`, `top_provider`. read by
                      hermes' parse_openrouter_reasoning_capabilities, which
                      decides "supports reasoning" from the presence of
                      "reasoning" in supported_parameters and nothing else.

    Reasoning effort levels are deliberately absent: they are not published
    upstream and were not measured, so a client that needs them still has to
    probe. A missing `reasoning` object reads as "supports reasoning, efforts
    unknown", which is the truth.
    """
    m = MODELS[model_id]
    context, output = m["context"], m["max_output"]
    vision, reasoning, tools = m["vision"], m["reasoning"], m["tools"]
    input_modalities = ["text"] + (["image"] if vision else [])
    params = ["max_tokens", "temperature", "top_p", "stop", "stream"]
    if tools:
        params += ["tools", "tool_choice", "parallel_tool_calls"]
    if reasoning:
        params.append("reasoning")
    return {
        "id": model_id,
        "object": "model",
        "created": 0,          # not published upstream; keeps strict parsers happy
        "owned_by": "opencode-zen",
        "name": model_id,
        # what this proxy has always served, plus a dict-of-bools `capabilities`
        # matching hermes' provider-level capabilities shape
        "context_window": context,
        "capabilities": {"vision": vision, "reasoning": reasoning, "tools": tools},
        "limits": {"context": context, "output": output},
        # models.dev
        "limit": {"context": context, "output": output},
        "modalities": {"input": input_modalities, "output": ["text"]},
        "reasoning": reasoning,
        "tool_call": tools,
        "attachment": vision,
        "cost": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0},
        # OpenRouter
        "supported_parameters": params,
        "context_length": context,
        "architecture": {"input_modalities": input_modalities,
                         "output_modalities": ["text"],
                         "modality": f"text+{'image->' if vision else ''}text"},
        "top_provider": {"context_length": context,
                         "max_completion_tokens": output,
                         "is_moderated": False},
    }
