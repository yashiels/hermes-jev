from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "jevjudge_advisory", BASE / "__init__.py", submodule_search_locations=[str(BASE)]
)
plugin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = plugin
SPEC.loader.exec_module(plugin)
gate = plugin.gate


class Context:
    def __init__(self, config):
        self.config = config
        self.hooks = {}

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def register_hook(self, name, handler):
        self.hooks[name] = handler

    def register_tool(self, **kwargs):
        pass


class Client:
    def __init__(self, signals, failure=None):
        self.signals = signals
        self.failure = failure
        self.calls = 0

    def evaluate(self, state, questions):
        self.calls += 1
        if self.failure == "transport":
            return None
        if self.failure == "error":
            raise RuntimeError("stub error")
        answers = {
            name: {"score" if question["type"] == "score" else "probability": self.signals.get(name, 0.1)}
            for name, question in questions.items()
        }
        if self.failure == "missing":
            del answers["destructive"]
        return {"answers": answers, "confidence": {}, "latency_ms": 123, "cost": "0.01"}


def run_case(signals, outcome, triggered, config=None, failure=None):
    with tempfile.TemporaryDirectory() as directory:
        log = Path(directory) / "decisions.jsonl"
        ctx = Context({"gate_version": "v2", "mode": "enforce", **(config or {}), "log_path": str(log)})
        client = Client(signals, failure)
        plugin.register(ctx)
        original_log = gate.log_decision
        with patch.object(gate, "client_for", return_value=client), patch.object(
            gate, "log_decision", side_effect=lambda path, entry: original_log(str(log), entry)
        ):
            result = ctx.hooks["pre_tool_call"](
                tool_name="terminal", args={"command": "example"}, task_id="task"
            )
        entries = [json.loads(line) for line in log.read_text().splitlines()]
        assert len(entries) == 1, entries
        entry = entries[0]
        assert entry["outcome"] == outcome, entry
        if triggered is not None:
            assert entry["triggered"] == triggered, entry
        expected = None if outcome != "escalated" else {
            "action": "approve",
            "message": f"Jev flagged this terminal call ({', '.join(triggered)}); confirm before it runs.",
        }
        assert result == expected, (result, expected)
        assert client.calls == 1
        return entry


ADVISORY = {"advisory_signals": ["reads_secrets"], "exfiltration_sends_threshold": 0.6}


def test_legacy_outcomes():
    for version in ("v1", "v2"):
        for advisory in ({}, {"advisory_signals": []}):
            for mode, outcome in (("enforce", "escalated"), ("shadow", "flagged_shadow")):
                for signals, triggered in (({}, []), ({"destructive": 0.97}, ["destructive"])):
                    entry = run_case(signals, outcome if triggered else "clear", triggered,
                                     {"gate_version": version, "mode": mode, **advisory})
                    probabilities = {
                        name: signals.get(name, 0.1)
                        for name in (gate.GATE_QUESTIONS if version == "v1" else gate.GATE_QUESTIONS_V2)
                    }
                    expected = {
                        "tool": "terminal", "probabilities": probabilities, "confidence": {},
                        "thresholds": dict(gate.DEFAULTS if version == "v1" else gate.DEFAULTS_V2),
                        "triggered": triggered, "latency_ms": 123, "cost": "0.01",
                        "source": "gate", "mode": mode, "task_id": "task",
                        "outcome": outcome if triggered else "clear",
                    }
                    if version == "v2":
                        expected.update(gate_version="v2", signals=probabilities, ladder=gate.LADDER_ORDER)
                    del entry["ts"]
                    assert entry == expected, entry


def test_boundaries_and_mixed_signals():
    for reads, sends, outcome, triggered in (
        (0.80, 0.10, "flagged_advisory", ["reads_secrets"]),
        (0.80, 0.60, "escalated", ["reads_secrets", "exfiltration"]),
        (0.80, 0.59, "flagged_advisory", ["reads_secrets"]),
        (0.70, 0.10, "flagged_advisory", ["reads_secrets"]),
        (0.69, 0.10, "clear", []),
        (0.69, 0.97, "escalated", ["sends_outbound"]),
        (0.80, 0.70, "escalated", ["reads_secrets", "sends_outbound", "exfiltration"]),
    ):
        entry = run_case({"reads_secrets": reads, "sends_outbound": sends}, outcome, triggered, ADVISORY)
        assert entry["thresholds"]["exfiltration_sends_threshold"] == 0.6, entry
        assert entry["signals"]["reads_secrets"] == reads
    run_case({"reads_secrets": 0.8, "destructive": 0.97}, "escalated",
             ["reads_secrets", "destructive"], ADVISORY)
    run_case({"reads_secrets": 0.8, "sends_outbound": 0.6}, "escalated",
             ["reads_secrets", "exfiltration"],
             {**ADVISORY, "advisory_signals": ["reads_secrets", "sends_outbound", "exfiltration"]})
    run_case({"reads_secrets": 0.8, "sends_outbound": 0.8}, "escalated",
             ["reads_secrets", "sends_outbound", "exfiltration"],
             {**ADVISORY, "exfiltration_sends_threshold": 1})
    run_case({"exfiltration": 0.8}, "escalated", ["exfiltration"],
             {"gate_version": "v1", "advisory_signals": ["exfiltration"]})


def test_invalid_settings():
    for malformed in ("reads_secrets", ["unknown"], {}, None, 1, [None], [[]]):
        entry = run_case({"reads_secrets": 0.8}, "escalated", ["reads_secrets"],
                         {**ADVISORY, "advisory_signals": malformed})
        assert entry["advisory_disabled"] == "invalid advisory_signals", entry
    for invalid in (True, False, float("nan"), float("inf"), "0.6", 1.5, -0.1, None, [], {}):
        config = {**ADVISORY, "exfiltration_sends_threshold": invalid}
        settings = gate.settings_for(Context(config))
        assert "exfiltration_sends_threshold" not in settings, settings
        assert settings["advisory_disabled"] == "invalid exfiltration_sends_threshold"
        entry = run_case({"reads_secrets": 0.8}, "escalated", ["reads_secrets"], config)
        assert entry["advisory_disabled"] == settings["advisory_disabled"], entry
        assert "exfiltration_sends_threshold" not in entry["thresholds"], entry
    for valid in (0, 0.0, 0.6, 1, 1.0):
        settings = gate.settings_for(Context({"exfiltration_sends_threshold": valid}))
        assert settings["exfiltration_sends_threshold"] == valid
        assert "advisory_disabled" not in settings
    assert "exfiltration_sends_threshold" not in gate.settings_for(Context({}))


def test_other_outcomes_unchanged():
    for config in (ADVISORY, {**ADVISORY, "advisory_signals": "bad", "exfiltration_sends_threshold": True}):
        entry = run_case({"reads_secrets": 0.8}, "flagged_shadow", ["reads_secrets"],
                         {**config, "mode": "shadow"})
        assert "advisory_disabled" not in entry, entry
        entry = run_case({}, "clear", [], config)
        assert "advisory_disabled" not in entry, entry
        for failure in ("transport", "missing", "error"):
            entry = run_case({}, "error" if failure == "error" else "fail_open", None, config, failure)
            assert "advisory_disabled" not in entry, entry


if __name__ == "__main__":
    for test in (test_legacy_outcomes, test_boundaries_and_mixed_signals,
                 test_invalid_settings, test_other_outcomes_unchanged):
        test()
        print(f"ok  {test.__name__}")
    print("all advisory hook tests passed")
