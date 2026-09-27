# opproxy

Combined Zen free-model proxy (stdlib only). Cloned 11 upstream repos into
`/tmp/opencode/proxies/` and merged the best parts into `opproxy.py`.

## What was merged

| Source | Taken |
|---|---|
| `PandaDecSt/opencodeProxy` | OpenAI + Anthropic dual API, tool awareness |
| `bigdata2211it-web/opencode-free-proxy` | Bun UA spoof, sticky `ses_` (30m), Anthropic streaming translator idea, 429 mapping |
| `akashdeep000/opencode-zen-proxy` | Verified limits, `/status` metrics, `UPSTREAM_PROXY` rotation env, 422 paid gate |
| `usa-w/opencode-free-proxy` | `Bearer public`-or-BYOK, force `stream:true` + SSE→JSON aggregation, `x-model-fallback` |
| `denysvitali/opencode-proxy` | Protocol translation patterns, model routing |
| `6Kmfi6HP/opencode2api` | 3-protocol gateway + fingerprint research |
| `RaisNafis/weimeng8888/lumishoang` | Minimal passthrough, aliasing |
| `keelzhang/jason9075` | Session injection, logging |

## Verified fingerprint (no API key)

`Authorization: Bearer public` + `User-Agent: opencode/latest/2.0.18/cli` +
valid `x-opencode-session: ses_…` + `stream:true` + tools include `read`+`shell`.
See `zen_free.py`.

## Run

```bash
python3 opproxy.py                  # :8787
PORT=8080 PROXY_TOKEN=secret python3 opproxy.py
ZEN_KEY=sk-... python3 opproxy.py   # BYOK instead of public
UPSTREAM_PROXY=http://user:pass@host:3128 python3 opproxy.py  # rotating egress
```

Endpoints: `POST /v1/chat/completions`, `POST /v1/responses`,
`POST /v1/messages` (beta), `GET /v1/models`, `GET /health`, `GET /status`.
