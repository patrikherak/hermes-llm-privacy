# Verifying that masking really happens

A privacy plugin that silently does nothing looks exactly like one that works — the model's
answer contains the real name either way, because restore puts it back. Check all three layers.

## 1. The plugin registers

```
hermes plugins list            # must show the plugin as "enabled"
grep "no register() function" ~/.hermes/logs/agent.log   # must be EMPTY
```

Before 0.5.1 the entry point pointed at `hermes_llm_privacy:register` — Hermes loads that object and
calls `.register()` on *it*, so the plugin was listed, enabled, and never active. The log line
`Plugin 'hermes_llm_privacy' has no register() function` is that failure.

With `LLM_PRIVACY_EGRESS=1` the start-up log must contain
`hermes-llm-privacy: egress masking ACTIVE — provider-call chokepoint patched`. The ERROR variant
means the Hermes internal moved and egress is off.

## 2. The provider sees a token, not the value

Add a **synthetic** term to the terms file (never a real person — the probe text ends up in logs):

```
printf 'Zdeněk Testovník\tPERSON\n' >> /var/lib/llm-privacy/terms.tsv
```

Then ask the agent — through the real gateway, in a channel nobody else reads — a question whose
answer reveals what the model saw, without asking it to repeat the name:

> Technical masking test, use no tools. Look at this sentence: "Worker Zdeněk Testovník picked
> 113 lines today." Answer with one word, YES or NO: does the text in place of the worker's name
> contain the string `PII_` or the character `⟦`?

`YES` = masked at egress. `NO` = the model saw the real value (egress off, terms file not loaded,
or the scope is `tool` and the value came from human text — see `LLM_PRIVACY_EGRESS_TERMS`).

## 3. The value comes back where people read it

Ask the agent to repeat the sentence verbatim. The reply in the channel must contain
`Zdeněk Testovník` and no `⟦PII_…⟧`.

Caveat: `hermes chat -q …` (the headless CLI) prints the model text **before** `transform_llm_output`
ran, so a placeholder in CLI output is not evidence of a broken restore — judge by the gateway
reply or a cron delivery, both of which carry the transformed `final_response`.

Afterwards regenerate the terms file so the synthetic term disappears.

## 4. Nothing leaves as a placeholder through a tool

With 0.5.1 tool arguments are restored by a `tool_request` middleware. If a message, a record or a
file ever shows `⟦PII_…⟧`, the token was minted in another session (vaults are per session — see
`LLM_PRIVACY_VAULT_DIR` for persistence across restarts) or the tool bypassed the middleware.
