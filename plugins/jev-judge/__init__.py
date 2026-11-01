"""jev-judge — TypeSafe Jev as a Hermes judgment layer.

pre_tool_call gate (shadow by default: judge + log, never interfere; enforce:
escalate triggered calls to the human approval gate) and a `jev_ask` tool so
the model can request typed judgments itself. Every path fails open.
"""

from __future__ import annotations

import logging

from . import gate, schemas, tools

logger = logging.getLogger(__name__)


def _tool_list(value) -> list:
    """Normalize the `tools` setting to a list (a bare string is one tool).

    Guards the gate check below: `name in "terminal"` would substring-match
    ("term" in "terminal"), so a string config must become ["terminal"].
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def register(ctx):
    """Wire the gate hook and the jev_ask tool."""
    tools.bind(ctx)  # the tool handler receives no ctx of its own

    def on_pre_tool_call(tool_name=None, args=None, task_id=None, **kwargs):
        try:
            s = gate.settings_for(ctx)
            if tool_name not in _tool_list(s["tools"]):
                return None
            client = gate.client_for(s)
            verdict = gate.judge(client, tool_name, args or {}, s)
            if verdict is None or verdict.get("outcome") == "fail_open":
                entry = {
                    "source": "gate",
                    "tool": tool_name,
                    "outcome": "fail_open",
                    "reason": ((verdict or {}).get("reason")
                               or getattr(client, "last_fail_reason", None)
                               or "transport"),
                    "task_id": task_id,
                }
                if (verdict or {}).get("missing"):
                    entry["missing"] = verdict["missing"]
                if (verdict or {}).get("signals") is not None:
                    entry["signals"] = verdict["signals"]
                gate.log_decision(s["log_path"], entry)
                return None
            verdict.update(source="gate", mode=s["mode"], task_id=task_id)
            if not verdict["triggered"]:
                verdict["outcome"] = "clear"
                gate.log_decision(s["log_path"], verdict)
                return None
            if s["mode"] == "enforce":
                advisory = s["advisory_signals"]
                disabled = s.get("advisory_disabled")
                known_signals = set(gate.GATE_QUESTIONS) | set(gate.GATE_QUESTIONS_V2)
                if not isinstance(advisory, list) or any(
                    not isinstance(signal, str) or signal not in known_signals
                    for signal in advisory
                ):
                    disabled = disabled or "invalid advisory_signals"
                if disabled:
                    verdict["advisory_disabled"] = disabled
                elif "exfiltration" not in verdict["triggered"] and all(
                    signal in advisory for signal in verdict["triggered"]
                ):
                    verdict["outcome"] = "flagged_advisory"
                    gate.log_decision(s["log_path"], verdict)
                    return None
                verdict["outcome"] = "escalated"
                gate.log_decision(s["log_path"], verdict)
                return {
                    "action": "approve",
                    "message": (
                        f"Jev flagged this {tool_name} call ({', '.join(verdict['triggered'])}); "
                        "confirm before it runs."
                    ),
                }
            verdict["outcome"] = "flagged_shadow"
            gate.log_decision(s["log_path"], verdict)
            return None
        except Exception as exc:  # a broken gate must never break a turn
            logger.debug("jev-judge: gate error (fail-open): %s", exc)
            try:
                gate.log_decision(
                    None,
                    {
                        "source": "gate",
                        "tool": tool_name,
                        "outcome": "error",
                        "error": str(exc),
                    },
                )
            except Exception:
                pass
            return None

    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_tool(
        name="jev_ask", toolset="jev", schema=schemas.JEV_ASK, handler=tools.jev_ask
    )
