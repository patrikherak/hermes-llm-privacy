# Egress masking — airtight, no host core change

`hermes-llm-privacy` masks at **ingress** (per input hook). That leaves gaps for any path that
reaches model context without firing those hooks (inline-dispatched tools, sub-agent output,
user-typed input). The airtight fix is to mask at **egress** — one chokepoint just before the
request goes to the provider, so nothing can bypass by construction.

## How (enabled with `LLM_PRIVACY_EGRESS=1`)

The plugin **monkeypatches the single provider-call chokepoint** at load —
`agent.chat_completion_helpers.interruptible_api_call`, the function every provider request funnels
through. The agent's method re-imports that name at call time, so replacing the module attribute
takes effect immediately. The wrapper re-masks **tool-result content** in the outgoing messages (both Anthropic
`tool_result` blocks and OpenAI `role: tool` messages), preserving structure/ids, then forwards to
the original. It intentionally leaves the human's own input raw — masking user-typed values would
break the model's ability to use them in a tool call (value-passing). Restore stays on `transform_llm_output`.

**No Hermes core edit, no upstream PR, no proxy.** `pip install` + the env var is enough — which is
why it works for public installs, not just a box you control.

```bash
LLM_PRIVACY_EGRESS=1   # in the gateway environment
```

## Guarantees & caveats

- **Composes with ingress** — already-minted tokens don't re-match, so this is a safety net on top
  of the input hooks, not double-masking.
- **Covers the bypass paths** the review flagged: tool output from inline-dispatched tools and
  sub-agents passes through this one chokepoint. (User-typed input is intentionally not masked —
  see above — to preserve value-passing.)
- **Best-effort, version-pinned — but never *silently* off.** It targets a Hermes internal
  (`interruptible_api_call`). On successful install it logs `egress masking ACTIVE` at WARNING; if
  the internal moved and it can't patch, it logs an **ERROR** (`EGRESS REQUESTED BUT NOT
  INSTALLED …`). Because a silent egress no-op would mean PII silently reaching the provider, the
  outcome is always logged loudly — check your gateway log after enabling. The ingress hooks keep
  working regardless, and the request path never breaks (all masking is wrapped in try/except).
- **Cost:** it re-scans the full outgoing message list on every call. Fine for normal contexts;
  for very long histories consider masking only new messages (future optimisation).
- ⚠️ It rewrites every outgoing provider request. Validate on a non-critical agent first
  (round-trip correctness + request integrity) before a customer-facing bot.

The cleanest *long-term* form is still an upstream mutable pre-send hook (so no monkeypatch), but
this delivers the guarantee today without touching the host.
