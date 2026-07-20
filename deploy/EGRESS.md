# Egress masking — the mutable `pre_api_request` requirement

`hermes-llm-privacy` masks at **ingress** (per input hook). That leaves gaps for any path that
reaches model context without firing those hooks (inline-dispatched tools, sub-agent output,
user-typed input). The airtight fix is to mask at **egress** — one chokepoint just before the
request goes to the provider, so nothing can bypass by construction.

Hermes exposes `pre_api_request`, but it is **observe-only**: it receives a *copy* of the messages
for tracing (langfuse) and its return value is ignored. To enable egress masking, the host must let
a `pre_api_request` hook **replace** the outgoing messages.

## Minimal core change (Hermes)

In `agent/conversation_loop.py`, where `pre_api_request` is invoked, capture the return and apply a
returned list back to the outgoing request (backward-compatible: hooks that return `None`, like
langfuse, change nothing):

```python
# was:  _invoke_hook("pre_api_request", ... request=_request_payload)
_pre_results = _invoke_hook("pre_api_request", ..., request=_request_payload)
for _pr in (_pre_results or []):
    if isinstance(_pr, list) and _pr:
        if isinstance(api_kwargs.get("messages"), list):
            api_kwargs["messages"] = _pr
        elif isinstance(api_kwargs.get("input"), list):
            api_kwargs["input"] = _pr
        break
```

Then run the plugin with `LLM_PRIVACY_EGRESS=1`; it registers `_mask_egress` on `pre_api_request`,
which masks text content of every message and returns the new list.

## Status

- Plugin side: implemented and shipped (env-gated `LLM_PRIVACY_EGRESS`, default off).
- Host side: the above is a **proposed upstream change** to Hermes. Until it (or an equivalent
  mutable pre-send hook) lands, egress masking is inert. Alternative without touching Hermes: a
  pre-send **LLM proxy** (LiteLLM-style) that masks at the network edge.

⚠️ This rewrites every outgoing provider request. Validate on a non-critical agent first
(round-trip correctness + request integrity) before enabling on a production/customer-facing bot.
