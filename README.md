# opproxy

Local proxy exposing OpenCode Zen free models as OpenAI-compatible APIs.
No API key required. Stdlib only, zero dependencies.

## How it works

Zen's anonymous free tier only answers requests that look like they come
from inside the OpenCode client. `opproxy` applies that fingerprint to every
upstream request:

* `Authorization: Bearer public` (or `ZEN_KEY`/`OPENCODE_API_KEY` if set)
* `User-Agent: opencode/latest/2.0.14/cli` (override with `OPENCODE_UA`)
* `x-opencode-session` + `x-session-affinity` + `X-Session-Id`, all set to the
  same sha256-derived `ses_<12hex><14base62>` id. A session the client already
  sends (under any of those three headers) is reused, so its stickiness
  survives; otherwise one is kept per client IP for 30 minutes.
* `x-opencode-client: cli` and `x-opencode-project: <32-hex>`, the latter from
  `OPENCODE_SPOOF_PROJECT_ID` or `~/.omp/install-id`, omitted when unavailable
* `stream: true` forced upstream (`store: false` on `/v1/responses`,
  `stream_options: {"include_usage": true}` on chat)
* `tools` always include `read` + `bash` dummies (per-protocol format).
  Without them Zen returns
  `403 FreeTierError: ... only ... within OpenCode`.
* For OpenAI Python SDK clients, `web_search`/`search_files` are aliased to
  `hermes_web_search`/`hermes_search_files` and a `strict` key is dropped —
  Zen reserves those names server-side. Other clients (omp) pass through
  untouched.
* Dummy calls are stripped from responses on all three protocols, streaming
  included, so a tool-using client never tries to execute them.

Fingerprint values are ported from `~/omp-zen-proxy/main.ts`, the
implementation verified working against the live gate.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/chat/completions` | OpenAI chat. Paid/unknown models → `422` (or fallback, see below). `/v1/responses` models → `400` with hint. Non-streaming clients get SSE aggregated to a `chat.completion` object. |
| `POST` | `/v1/responses` | OpenAI Responses. Non-streaming aggregates the SSE `response.completed` event (dummy `function_call` items removed). |
| `POST` | `/v1/messages` | Anthropic passthrough (beta). Dummy `read`/`shell` tools injected, `max_tokens` defaults to 1024. Streams properly, and dummy `tool_use` blocks are removed from both the JSON and the SSE event stream. |
| `GET` | `/v1/models` | Free-model list with context windows. |
| `GET` | `/health` | `{status: ok}`. |
| `GET` | `/status` | Metrics: `requests_total`, `by_model`, `by_status`, `rate_limited`, `fallback_used`, `uptime`. |

## Free models

Single source of truth: `zen_models.py`. Every id there was probed on its own
protocol and answered 200; ids Zen has since dropped are listed in that
module's `RETIRED` map with the upstream error, so they are not re-added here.

Chat (`/v1/chat/completions`): `big-pickle`, `space-bunny-free`,
`longcat-2.5-preview-free`, `mimo-v2.6-flash-free`, `mimo-v2.5-free`,
`ling-3.0-flash-fin-free`, `nemotron-3-ultra-free`,
`nemotron-3.5-lightning-free`.

Responses (`/v1/responses`): `muse-spark-1.3-contributor-free`,
`muse-spark-1.2-contributor-free`.

`/v1/messages` is **not** a separate model family: upstream gates it per
model, and today only `space-bunny-free` answers there (a chat model). The
endpoint accepts any catalog model and lets upstream decide — a model that
cannot speak the Anthropic wire format returns its own `401 ModelError`.

Unknown/paid chat models fall back to `big-pickle` with an
`x-model-fallback` response header (disable with `FALLBACK_MODEL=`).

## Run

```bash
./start.sh                           # :8787, backgrounded + verified
python3 opproxy.py                  # :8787, anonymous, foreground
PORT=8080 PROXY_TOKEN=secret python3 opproxy.py
ZEN_KEY=sk-... python3 opproxy.py   # BYOK instead of public
UPSTREAM_PROXY=http://user:pass@host:3128 python3 opproxy.py  # rotating egress
OPENCODE_ZEN_URL=https://opencode.ai/zen/v1 python3 opproxy.py
```

| Env | Default | Purpose |
|---|---|---|
| `PORT` | `8787` | Listen port |
| `ZEN_KEY` / `OPENCODE_API_KEY` | `public` | Upstream credential |
| `PROXY_TOKEN` / `API_KEY` | _(open)_ | Require `Authorization: Bearer` on inbound requests |
| `OPENCODE_ZEN_URL` | `https://opencode.ai/zen/v1` | Upstream base |
| `OPENCODE_UA` | `opencode/latest/2.0.18/cli` | Upstream User-Agent |
| `UPSTREAM_PROXY` | _(direct)_ | `http(s)://` proxy for upstream egress |
| `FALLBACK_MODEL` | `big-pickle` | Fallback for unknown chat models (empty disables) |
| `OPENCODE_SPOOF_PROJECT_ID` | `~/.omp/install-id` | 32-hex `x-opencode-project` value |

## Use with harnesses

Any OpenAI-compatible client pointing at `http://127.0.0.1:8787/v1`:

```bash
# curl
curl http://127.0.0.1:8787/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"big-pickle","messages":[{"role":"user","content":"hi"}],"stream":false}'

# omp (oh-my-pi) — ~/.omp/agent/models.yml
providers:
  opproxy:
    baseUrl: http://127.0.0.1:8787/v1
    api: openai-completions
    apiKey: OPPROXY_KEY
    models:
      - {id: big-pickle, name: Big Pickle, contextWindow: 200000, maxTokens: 32000}
export OPPROXY_KEY=dummy
omp -p --model opproxy/big-pickle "say ok"

# hermes — ~/.hermes/config.yaml: a `providers:` entry, then point model.* at it
providers:
  opproxy:
    base_url: http://127.0.0.1:8787/v1
    auth: none            # proxy needs no key; use key_env if PROXY_TOKEN is set
    api_mode: chat_completions
    default_model: big-pickle
    discover_models: false   # the list below is the allowlist; see note
    context_length: 200000
    models:                  # chat models only — the /v1/responses ones
      - big-pickle           # cannot be called on /v1/chat/completions
      - space-bunny-free
      - longcat-2.5-preview-free
      - mimo-v2.6-flash-free
      - mimo-v2.5-free
      - ling-3.0-flash-fin-free
      - nemotron-3-ultra-free
      - nemotron-3.5-lightning-free
model:
  provider: opproxy
  default: big-pickle
  base_url: http://127.0.0.1:8787/v1
  api_mode: chat_completions

hermes config set model.provider opproxy
hermes config set model.default big-pickle
hermes config set model.base_url http://127.0.0.1:8787/v1
hermes config set model.api_mode chat_completions
hermes -z "say ok"


# opencode (v2 config)
# { "providers": { "local": { "package": "@opencode-ai/ai/providers/openai-compatible",
#   "settings": {"baseURL": "http://127.0.0.1:8787/v1"}, ... } } }
```

Verified with `omp` (plain reply + file-write task) and `hermes` against
`big-pickle`: a one-shot reply, and a tool-using turn that ran the agent loop
to completion (6 API calls, `failed: false`, `finish_reason=stop`). Because
hermes sends tools on every turn, the streamed dummy `read`/`shell` calls must
be filtered for it to work at all — see the streaming notes above.

`discover_models: true` makes hermes enumerate `/v1/models`, which also lists
the two `/v1/responses` models; it tries them on `/v1/chat/completions`, gets
the `400` cross-protocol hint, and moves on.

`zen_free.py` is the minimal standalone client proving the gate
(`chat` and `responses` modes, no proxy needed).

## Limits

* Streaming upstream is mandatory; non-streaming is emulated by aggregation,
  so a `stream:false` response arrives after the whole generation.
* `/v1/messages` is a native passthrough, not a full Anthropic↔OpenAI
  translation; some Anthropic clients may need `max_tokens` set (it defaults
  to 1024).
* Request bodies over 50 MB get `413`; an upstream that cannot be reached
  (refused, DNS, TLS, timeout) gets `502`, not a dropped connection.
* Free models are rate-limited per IP and may reuse prompts for training
  depending on the model (see Zen pricing/privacy docs). The fingerprint is
  undocumented and can break if Zen tightens the gate.
* The free-model list rots: Zen retires ids without notice. Re-probe with
  `python3 zen_free.py chat <model> "hi"` and update `zen_models.py`.
