# opproxy

Local proxy exposing OpenCode Zen free models as OpenAI-compatible APIs.
No API key required. Stdlib only, zero dependencies.

## How it works

Zen's anonymous free tier only answers requests that look like they come
from inside the OpenCode client. `opproxy` applies that fingerprint to every
upstream request:

* `Authorization: Bearer public` (or `ZEN_KEY`/`OPENCODE_API_KEY` if set)
* `User-Agent: opencode/latest/2.0.18/cli` (override with `OPENCODE_UA`)
* Fresh valid `x-opencode-session: ses_…` per client (sticky 30 min per
  client IP, reused if the client already sends one)
* `x-opencode-client: cli`, `x-opencode-project: global`
* `stream: true` forced upstream (`store: false` on `/v1/responses`,
  `stream_options: {"include_usage": true}` on chat)
* `tools` always include `read` + `shell` dummies (per-protocol format).
  Without them Zen returns
  `403 FreeTierError: ... only ... within OpenCode`.
  Dummy calls are stripped from non-streaming responses.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/chat/completions` | OpenAI chat. Paid/unknown models → `422` (or fallback, see below). `/v1/responses` models → `400` with hint. Non-streaming clients get SSE aggregated to a `chat.completion` object. |
| `POST` | `/v1/responses` | OpenAI Responses. Non-streaming aggregates the SSE `response.completed` event (dummy `function_call` items removed). |
| `POST` | `/v1/messages` | Anthropic passthrough (beta). Dummy `read`/`shell` tools injected, `max_tokens` defaults to 1024. |
| `GET` | `/v1/models` | Free-model list with context windows. |
| `GET` | `/health` | `{status: ok}`. |
| `GET` | `/status` | Metrics: `requests_total`, `by_model`, `by_status`, `rate_limited`, `fallback_used`, `uptime`. |

## Free models

Chat (`/v1/chat/completions`): `big-pickle`, `space-bunny-free`,
`longcat-2.5-preview-free`, `mimo-v2.6-flash-free`, `mimo-v2.5-free`,
`mimo-v2-pro-free`, `ling-3.0-flash-fin-free`, `nemotron-3-ultra-free`,
`nemotron-3.5-lightning-free`, `deepseek-v4-flash-free`, `kimi-k2.5-free`,
`glm-5-free`.

Responses (`/v1/responses`): `muse-spark-1.3-contributor-free`,
`muse-spark-1.2-contributor-free`.

Messages (`/v1/messages`, beta): `qwen3.6-plus-free`, `minimax-m2.5-free`,
`minimax-m3-free`.

Unknown/paid chat models fall back to `big-pickle` with an
`x-model-fallback` response header (disable with `FALLBACK_MODEL=`).

## Run

```bash
python3 opproxy.py                  # :8787, anonymous
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

# hermes
hermes config set model.provider custom
hermes config set model.base_url http://127.0.0.1:8787/v1
hermes config set model.default big-pickle
hermes chat -q "say ok" --oneshot

# opencode (v2 config)
# { "providers": { "local": { "package": "@opencode-ai/ai/providers/openai-compatible",
#   "settings": {"baseURL": "http://127.0.0.1:8787/v1"}, ... } } }
```

Verified with `omp` (plain reply + file-write task) and `hermes`
(plain reply + file-write task) against `big-pickle`.

`zen_free.py` is the minimal standalone client proving the gate
(`chat` and `responses` modes, no proxy needed).

## General-purpose proxy (`opproxy_general.py`)

Same fingerprint, but for plain clients like a study summarizer that send
no tools and/or `stream:false`:

```bash
python3 opproxy_general.py  # :8788
```

* `POST /v1/chat/completions`, `GET /v1/models`, `GET /health`.
* No-tool requests get gate dummies + `tool_choice:none` upstream, are
  aggregated with retries (the model nondeterministically calls the dummy
  tools ~1/3 of the time), and dummy-only results are reported as
  `finish_reason:stop`.
* Streaming responses are re-emitted clean: no `reasoning_content`/`name`
  fields, no dummy `tool_calls`, no `cost` trailer.
* Requests that already carry tools pass through (streaming sanitized).

## Limits

* Streaming upstream is mandatory; non-streaming is emulated by aggregation.
* Streamed dummy `read`/`shell` deltas are passed through; clients should
  ignore tool calls to them (non-streaming responses are already filtered).
* `/v1/messages` is a native passthrough, not a full Anthropic↔OpenAI
  translation; some Anthropic clients may need `max_tokens` set.
* Free models are rate-limited per IP and may reuse prompts for training
  depending on the model (see Zen pricing/privacy docs). The fingerprint is
  undocumented and can break if Zen tightens the gate.
