# Egress masking — airtight, no host core change

`hermes-llm-privacy` masks at **ingress** (per input hook). That leaves gaps for any path that
reaches model context without firing those hooks (inline-dispatched tools, sub-agent output,
user-typed input). The airtight fix is to mask at **egress** — one chokepoint just before the
request goes to the provider, so nothing can bypass by construction.

## How (enabled with `LLM_PRIVACY_EGRESS=1`)

The plugin **monkeypatches the single provider-call chokepoint** at load —
`agent.chat_completion_helpers.interruptible_api_call`, the function every provider request funnels
through. The agent's method re-imports that name at call time, so replacing the module attribute
takes effect immediately. The wrapper masks the text of every outgoing message
(`messages` / `input`), preserving `tool_use`/`tool_result` structure and ids, then forwards to the
original. Restore stays on `transform_llm_output`.

**No Hermes core edit, no upstream PR, no proxy.** `pip install` + the env var is enough — which is
why it works for public installs, not just a box you control.

```bash
LLM_PRIVACY_EGRESS=1   # in the gateway environment
```

## Guarantees & caveats

- **Composes with ingress** — already-minted tokens don't re-match, so this is a safety net on top
  of the input hooks, not double-masking.
- **Covers the bypass paths** the review flagged: bypassed tools, sub-agents, and (now) user-typed
  input all pass through this one chokepoint.
- **Best-effort, version-pinned.** It targets a Hermes internal (`interruptible_api_call`). If a
  future Hermes moves it, egress **silently no-ops** (logs a warning) and the ingress hooks keep
  working — it never breaks the request path (all masking is wrapped in try/except).
- **Cost:** it re-scans the full outgoing message list on every call. Fine for normal contexts;
  for very long histories consider masking only new messages (future optimisation).
- ⚠️ It rewrites every outgoing provider request. Validate on a non-critical agent first
  (round-trip correctness + request integrity) before a customer-facing bot.

The cleanest *long-term* form is still an upstream mutable pre-send hook (so no monkeypatch), but
this delivers the guarantee today without touching the host.
