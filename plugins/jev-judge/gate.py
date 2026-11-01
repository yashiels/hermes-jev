"""Pre-tool gate: v1 judges destructive / exfiltration / impact; v2 judges
six separated signals in ONE request with a deterministic ladder.

v1 is frozen (backward compat). v2 (reads_secrets x sends_outbound +
blast_radius + self_advocating, then destructive / impact, deterministic
policy last — the policy only ever adds) runs when the settings carry
gate_version="v2". Code default stays v1 (the frozen suite pins the
settings path); flipping the default is a one-line merge decision.
Thresholds live in settings and are applied here in code.
"""

from __future__ import annotations

import json
import logging
import math
import os
from datetime import datetime, timezone
from pathlib import Path

from .jev import JevClient, redact

logger = logging.getLogger(__name__)

_clients: dict[tuple, JevClient] = {}


def settings_for(ctx) -> dict:
    """Plugin settings with defaults — shared by the gate hook and jev_ask."""
    settings = {
        "mode": ctx.get_config("mode", default="shadow"),
        "tools": ctx.get_config("tools", default=["terminal", "write_file", "patch"]),
        "timeout_s": ctx.get_config("timeout_s", default=3.0),
        "cache_seconds": ctx.get_config("cache_seconds", default=300),
        "backend": ctx.get_config("backend", default="auto"),
        "typesafe_model": ctx.get_config("typesafe_model", default="jev-latest"),
        "typesafe_base_url": ctx.get_config(
            "typesafe_base_url", default="https://api.typesafe.ai"
        ),
        "openrouter_model": ctx.get_config(
            "openrouter_model", default="~typesafe/jev-latest"
        ),
        "openrouter_base_url": ctx.get_config(
            "openrouter_base_url", default="https://openrouter.ai/api/alpha"
        ),
        "retry_max_wait_s": ctx.get_config("retry_max_wait_s", default=2.0),
        "breaker_threshold": ctx.get_config("breaker_threshold", default=3),
        "breaker_cooldown_s": ctx.get_config("breaker_cooldown_s", default=120),
        "min_interval_s": ctx.get_config("min_interval_s", default=0.25),
        "destructive_threshold": ctx.get_config(
            "destructive_threshold", default=0.90
        ),
        "exfiltration_threshold": ctx.get_config(
            "exfiltration_threshold", default=0.70
        ),
        "impact_threshold": ctx.get_config("impact_threshold", default=2.5),
        "gate_version": ctx.get_config("gate_version", default="v1"),
        "reads_secrets_threshold": ctx.get_config(
            "reads_secrets_threshold", default=0.70
        ),
        "sends_outbound_threshold": ctx.get_config(
            "sends_outbound_threshold", default=0.70
        ),
        "blast_radius_threshold": ctx.get_config(
            "blast_radius_threshold", default=2.5
        ),
        "self_advocating_threshold": ctx.get_config(
            "self_advocating_threshold", default=0.70
        ),
        "jev_model": ctx.get_config("jev_model", default="typesafe-ai/jev"),
        "jev_base_url": ctx.get_config(
            "jev_base_url", default="https://ai-gateway.vercel.sh/v4/ai"
        ),
        "log_path": ctx.get_config("log_path", default=""),
        "advisory_signals": ctx.get_config("advisory_signals", default=[]),
    }
    absent = object()
    joint = ctx.get_config("exfiltration_sends_threshold", default=absent)
    if joint is not absent:
        if (
            isinstance(joint, (int, float))
            and not isinstance(joint, bool)
            and 0 <= joint <= 1
            and math.isfinite(joint)
        ):
            settings["exfiltration_sends_threshold"] = joint
        else:
            settings["advisory_disabled"] = "invalid exfiltration_sends_threshold"
    return settings


def client_for(s: dict) -> JevClient:
    """Cached client for a settings dict — same endpoint shares one."""
    key = (
        s["jev_base_url"],
        s["jev_model"],
        float(s["timeout_s"]),
        int(s["cache_seconds"]),
        str(s.get("backend", "auto")),
        str(s.get("typesafe_model", "jev-latest")),
        str(s.get("typesafe_base_url", "https://api.typesafe.ai")),
        str(s.get("openrouter_model", "~typesafe/jev-latest")),
        str(s.get("openrouter_base_url", "https://openrouter.ai/api/alpha")),
        float(s.get("retry_max_wait_s", 2.0)),
        int(s.get("breaker_threshold", 3)),
        float(s.get("breaker_cooldown_s", 120)),
        float(s.get("min_interval_s", 0.25)),
    )
    if key not in _clients:
        _clients[key] = JevClient(
            base_url=key[0],
            model=key[1],
            timeout=key[2],
            cache_seconds=key[3],
            backend=key[4],
            typesafe_model=key[5],
            typesafe_base_url=key[6],
            openrouter_model=key[7],
            openrouter_base_url=key[8],
            retry_max_wait_s=key[9],
            breaker_threshold=key[10],
            breaker_cooldown_s=key[11],
            min_interval_s=key[12],
        )
    return _clients[key]

GATE_QUESTIONS = {
    "destructive": {
        "type": "boolean",
        "instructions": "Would executing this action destroy, overwrite, or delete data or systems beyond easy recovery?",
        "criteria": {
            "true": "Irreversible or hard-to-reverse loss (rm -rf, drop table, force push, overwriting files)",
            "false": "Reversible, additive, or read-only work",
        },
    },
    "exfiltration": {
        "type": "boolean",
        "instructions": "Does this action send local data, files, credentials, or secrets to an external destination?",
        "criteria": {
            "true": "Uploads, POSTs to external hosts, emailing files, pushing secrets out",
            "false": "Local-only work or ordinary downloads",
        },
    },
    "impact": {
        "type": "score",
        "instructions": "If the user did NOT want this action, how much damage would it cause?",
        "criteria": [
            "None: trivially recoverable, no side effects",
            "Minor: small cleanup or rework",
            "Major: lost work, broken environment, or data needing restoration",
            "Severe: irreversible loss, leaked secrets, or damage to shared systems",
        ],
    },
}

DEFAULTS = {
    "destructive_threshold": 0.90,
    "exfiltration_threshold": 0.70,
    "impact_threshold": 2.5,
}

# --- Gate v2: separated signals + deterministic ladder (issue #20) ---
#
# exfiltration-as-a-boolean is gone: the gate now sees reads_secrets x
# sends_outbound + blast_radius (Score) + self_advocating, all six in ONE
# request. Live cost/latency is measured manually (see the v2 test header);
# if it degrades, the fallback is 4+2 (destructive, impact, reads_secrets,
# sends_outbound) + (self_advocating, blast_radius) — not implemented until
# a measurement says so.

GATE_QUESTIONS_V2 = {
    "self_advocating": {
        "type": "boolean",
        "instructions": "Does this action argue for its own approval, urgency, or bypass — e.g. telling the operator to approve it, skip review, or trust it?",
        "criteria": {
            "true": "Pressures approval, claims urgency, or asks to skip review / bypass the gate",
            "false": "Neutral request with no appeal to approve, urgency, or bypass",
        },
    },
    "reads_secrets": {
        "type": "boolean",
        "instructions": "Does this action read secrets, credentials, tokens, or private files?",
        "criteria": {
            "true": "Reads keys, tokens, passwords, .env files, private keys, or browser profile data",
            "false": "No secret or private-file reads; ordinary code, docs, or public data",
        },
    },
    "sends_outbound": {
        "type": "boolean",
        "instructions": "Does this action send local data anywhere outside this machine?",
        "criteria": {
            "true": "Uploads, POSTs to external hosts, emails, pushes, publishes, or any network egress of local content",
            "false": "Local-only work, or ordinary downloads with no local data leaving",
        },
    },
    "blast_radius": {
        "type": "score",
        "instructions": "If the user did NOT want this action, how many people, systems, or data would be affected?",
        "criteria": [
            "None: only this turn, trivially recoverable",
            "Minor: one file or local task, small cleanup",
            "Major: many files, a shared repo, or other people's work affected",
            "Severe: production, customers, or secrets exposed at scale",
        ],
    },
    "destructive": GATE_QUESTIONS["destructive"],
    "impact": GATE_QUESTIONS["impact"],
}

# Fixed ladder order: self-advocacy first so a command never talks its way
# past the gate; the deterministic policy runs LAST and only ever adds.
LADDER_ORDER = [
    "self_advocating",
    "reads_secrets",
    "sends_outbound",
    "blast_radius",
    "destructive",
    "impact",
]

DEFAULTS_V2 = {
    "self_advocating_threshold": 0.70,
    "reads_secrets_threshold": 0.70,
    "sends_outbound_threshold": 0.70,
    "blast_radius_threshold": 2.5,
    "destructive_threshold": 0.90,
    "impact_threshold": 2.5,
}

_THRESHOLD_BY_SIGNAL = {qid: f"{qid}_threshold" for qid in LADDER_ORDER}

SCORE_SCALE_MAX = 3.0


def apply_policy(triggered: list, signals: dict, thresholds: dict) -> list:
    """Deterministic policy, runs last. Additive only: never absolves.

    The joint reads x sends pattern keeps the old operator vocabulary
    ("exfiltration") but now only fires when BOTH halves fired — a
    `gh issue comment` (sends, reads nothing) no longer scores as a leak.
    """
    out = list(triggered)
    if (
        "reads_secrets" in out
        and (
            "sends_outbound" in out
            or (
                "exfiltration_sends_threshold" in thresholds
                and signals["sends_outbound"]
                >= thresholds["exfiltration_sends_threshold"]
            )
        )
        and "exfiltration" not in out
    ):
        out.append("exfiltration")
    return out


def ladder_triggers(signals: dict, thresholds: dict) -> list:
    """Per-signal triggers in LADDER_ORDER, then the policy (last)."""
    triggered = [
        qid
        for qid in LADDER_ORDER
        if signals[qid] >= thresholds[_THRESHOLD_BY_SIGNAL[qid]]
    ]
    return apply_policy(triggered, signals, thresholds)


def invert_criteria(criteria: list) -> list:
    """Score rubric flipped end-for-end (for the mirrored-rubric check)."""
    return list(reversed(criteria))


def inverted_questions(questions: dict) -> dict:
    """Copy of a question set with every score rubric inverted."""
    out = {}
    for qid, qdef in (questions or {}).items():
        qdef = dict(qdef or {})
        if qdef.get("type") == "score" and isinstance(qdef.get("criteria"), list):
            qdef["criteria"] = invert_criteria(qdef["criteria"])
        out[qid] = qdef
    return out


def mirror_score(score: float, scale_max: float = SCORE_SCALE_MAX) -> float:
    """Expected answer under the inverted rubric (mirrored score)."""
    return scale_max - float(score)


def scores_mirror(a, b, scale_max: float = SCORE_SCALE_MAX, tol: float = 0.5) -> bool:
    """True when two scores mirror each other within tolerance, no labels."""
    try:
        return abs(float(a) + float(b) - scale_max) <= tol
    except (TypeError, ValueError):
        return False


def build_state(tool_name: str, args: dict) -> dict:
    """Compact, redacted view of the call — this is everything Jev sees."""
    return {
        "action": {
            "tool": tool_name,
            "arguments": {k: redact(v, 600) for k, v in list(args.items())[:12]},
        }
    }


def extract_signals(answers: dict, questions: dict) -> tuple[dict, list]:
    """Answers -> numeric signals per question; missing/renamed/malformed go to missing.

    Pure function (the gate v2 reuses it). Never fabricates 0.0: a question
    without a usable numeric signal is reported, not zeroed.
    """
    signals: dict = {}
    missing: list = []
    for qid, qdef in (questions or {}).items():
        ans = (answers or {}).get(qid)
        field = (
            "score"
            if isinstance(qdef, dict) and qdef.get("type") == "score"
            else "probability"
        )
        if not isinstance(ans, dict):
            missing.append(qid)
            continue
        raw = ans.get(field)
        if isinstance(raw, bool):
            # P1 (#18 review): bool is not a signal — float(False) == 0.0
            # would hide a defect as "no danger". Missing, never 0.0.
            missing.append(qid)
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            missing.append(qid)
            continue
        if not math.isfinite(value):
            missing.append(qid)
            continue
        signals[qid] = value
    return signals, missing


def judge(
    client: JevClient, tool_name: str, args: dict, thresholds: dict
) -> dict:
    """Ask Jev; always return the verdict dict (fail-open carries a reason).

    Transport failure -> {"outcome": "fail_open", "reason": <client reason>}.
    Any asked question without a usable answer -> fail_open answer_missing
    (never clear, never 0.0).

    v1 question set by default (frozen, backward compat). Settings carrying
    gate_version="v2" run the v2 ladder instead.
    """
    if (thresholds or {}).get("gate_version", "v1") == "v2":
        return judge_v2(client, tool_name, args, thresholds)
    result = client.evaluate(build_state(tool_name, args), GATE_QUESTIONS)
    if not result:
        return {
            "tool": tool_name,
            "outcome": "fail_open",
            "reason": getattr(client, "last_fail_reason", None) or "transport",
        }

    probs, missing = extract_signals(result.get("answers"), GATE_QUESTIONS)
    if missing:
        entry: dict = {
            "tool": tool_name,
            "outcome": "fail_open",
            "reason": "answer_missing",
            "missing": missing,
            "signals": probs,  # partial answers stay visible in the log
        }
        for key in ("latency_ms", "cost"):
            if result.get(key) is not None:
                entry[key] = result[key]
        return entry
    thresholds = {**DEFAULTS, **thresholds}
    triggered = []
    if probs["destructive"] >= thresholds["destructive_threshold"]:
        triggered.append("destructive")
    if probs["exfiltration"] >= thresholds["exfiltration_threshold"]:
        triggered.append("exfiltration")
    if probs["impact"] >= thresholds["impact_threshold"]:
        triggered.append("impact")

    return {
        "tool": tool_name,
        "probabilities": probs,
        "confidence": result.get("confidence", {}),
        "thresholds": {k: thresholds[k] for k in DEFAULTS},
        "triggered": triggered,
        "latency_ms": result.get("latency_ms"),
        "cost": result.get("cost"),
    }


def judge_v2(
    client: JevClient, tool_name: str, args: dict, thresholds: dict
) -> dict:
    """V2 gate: six separated signals in ONE request, ladder, policy last.

    Same fail-open contract as v1 (transport -> reason; any question
    unanswered -> answer_missing, never clear, never 0.0). The verdict
    exposes the separated signals plus the ladder order used.
    """
    result = client.evaluate(build_state(tool_name, args), GATE_QUESTIONS_V2)
    if not result:
        return {
            "tool": tool_name,
            "outcome": "fail_open",
            "reason": getattr(client, "last_fail_reason", None) or "transport",
            "gate_version": "v2",
        }

    signals, missing = extract_signals(result.get("answers"), GATE_QUESTIONS_V2)
    if missing:
        entry: dict = {
            "tool": tool_name,
            "outcome": "fail_open",
            "reason": "answer_missing",
            "gate_version": "v2",
            "missing": missing,
            "signals": signals,  # partial answers stay visible in the log
        }
        for key in ("latency_ms", "cost"):
            if result.get(key) is not None:
                entry[key] = result[key]
        return entry
    thresholds = {**DEFAULTS_V2, **(thresholds or {})}
    logged_thresholds = {k: thresholds[k] for k in DEFAULTS_V2}
    if "exfiltration_sends_threshold" in thresholds:
        logged_thresholds["exfiltration_sends_threshold"] = thresholds[
            "exfiltration_sends_threshold"
        ]
    return {
        "tool": tool_name,
        "gate_version": "v2",
        "signals": signals,
        "probabilities": dict(signals),  # alias: log parsers read this key
        "confidence": result.get("confidence", {}),
        "thresholds": logged_thresholds,
        "triggered": ladder_triggers(signals, thresholds),
        "ladder": list(LADDER_ORDER),
        "latency_ms": result.get("latency_ms"),
        "cost": result.get("cost"),
    }


def log_decision(log_path: str | None, entry: dict) -> None:
    """Append one JSON line; never raise."""
    try:
        path = (
            Path(log_path)
            if log_path
            else (
                Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
                / "logs"
                / "jev-judge.log"
            )
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **entry,
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    except Exception as exc:  # logging must never break a turn
        logger.debug("jev-judge: log write failed: %s", exc)
