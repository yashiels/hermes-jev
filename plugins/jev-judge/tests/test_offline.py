"""Offline tests for jev-judge — no network, no keys. Run: python3 tests/test_offline.py"""
from __future__ import annotations


# Keep the suite offline on any host: clear credential env vars and point the
# .env fallback at an empty dir BEFORE the plugin modules load.
import os as _os
import tempfile as _tempfile

for _key in ("TYPESAFE_API_KEY", "AI_GATEWAY_API_KEY", "OPENROUTER_API_KEY"):
    _os.environ.pop(_key, None)
_HERMES_HOME_SAVED = _os.environ.get("HERMES_HOME")
_TEMP_HERMES_HOME = _tempfile.TemporaryDirectory()
_os.environ["HERMES_HOME"] = _TEMP_HERMES_HOME.name
import importlib.util
import json
import sys
import types
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

# Load the plugin as a package (dir name has a hyphen, so alias it).
pkg = types.ModuleType("jevjudge")
pkg.__path__ = [str(BASE)]
sys.modules["jevjudge"] = pkg
for name in ("jev", "gate", "tools"):
    spec = importlib.util.spec_from_file_location(
        f"jevjudge.{name}", BASE / f"{name}.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"jevjudge.{name}"] = mod
    spec.loader.exec_module(mod)

jev = sys.modules["jevjudge.jev"]
gate = sys.modules["jevjudge.gate"]
toolsmod = sys.modules["jevjudge.tools"]


class StubClient:
    """Returns a canned evaluate() result, or None to simulate failure."""

    def __init__(self, answers=None, confidence=None, latency=123, cost="0.00002", reason=None):
        self.answers = answers
        self.confidence = confidence or {}
        self.latency = latency
        self.cost = cost
        self.last_fail_reason = reason  # espelha JevClient: motivo do último fail-open

    def evaluate(self, state, questions):
        if self.answers is None:
            return None
        self.last_fail_reason = None  # sucesso limpa o motivo, como no cliente real
        return {
            "answers": self.answers,
            "confidence": self.confidence,
            "cost": self.cost,
            "usage": {},
            "latency_ms": self.latency,
        }


def test_redact():
    fake_key = (
        "sk-" + "a" * 24
    )  # composed so source scanners don't flag a real-looking key
    masked = jev.redact(f"token {fake_key} here")
    assert "[REDACTED]" in masked and fake_key not in masked, masked
    long = jev.redact("lorem ipsum " * 500, limit=100)
    assert long.startswith(("lorem ipsum " * 500)[:100]) and "+5900 chars" in long, long[:120]
    print("ok  redact mascarou chave e truncou")


def test_redact_pocs():
    # Every string is composed below so no secret-shaped literal sits in source.
    jwt = "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
    akia = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
    pem = (
        "-----BEGIN " + "PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
        "-----END " + "PRIVATE KEY-----"
    )
    basic = "Authorization: " + "Bas" + "ic " + "dXNl" + "cjpwYXNzd29yZA=="
    ghp = "gh" + "p_" + "x" * 30
    sk_short = "sk-" + "abc123"
    pat = "github_" + "pat_" + "y" * 22
    slack = "xo" + "xb-123456789012-" + "z" * 24
    google = "AI" + "za" + "SyB12345678901234567890"
    vercel = "vc" + "k_live_" + "z" * 24
    blob = "A" * 32
    for secret in (jwt, akia, pem, basic, ghp, sk_short, pat, slack, google, vercel, blob):
        masked = jev.redact("leak " + secret + " end")
        assert "[REDACTED]" in masked and secret not in masked, (secret, masked)
    bearer = "Bear" + "er " + jwt
    masked = jev.redact("auth " + bearer)
    assert "[REDACTED]" in masked and jwt not in masked, masked
    assert jev.redact("hello world") == "hello world"
    print("ok  redact cobriu PoCs (bearer/jwt, akia, pem, basic, gh, sk curta, generico)")


def test_jev_ask_uses_settings():
    import tempfile

    seen = {}

    class RecClient:
        def __init__(self, base_url="", model="", timeout=0.0, cache_seconds=0,
                     backend="auto", typesafe_model="", typesafe_base_url="",
                     openrouter_model="", openrouter_base_url="",
                     retry_max_wait_s=0.0, breaker_threshold=0,
                     breaker_cooldown_s=0.0, min_interval_s=0.0):
            seen.update(
                base_url=base_url,
                model=model,
                timeout=timeout,
                cache_seconds=cache_seconds,
                backend=backend,
                typesafe_model=typesafe_model,
                typesafe_base_url=typesafe_base_url,
                openrouter_model=openrouter_model,
                openrouter_base_url=openrouter_base_url,
                retry_max_wait_s=retry_max_wait_s,
                breaker_threshold=breaker_threshold,
                breaker_cooldown_s=breaker_cooldown_s,
                min_interval_s=min_interval_s,
            )

        def evaluate(self, state, questions):
            return {
                "answers": {"q": {"probability": 0.9}},
                "confidence": {},
                "cost": "0",
                "usage": {},
                "latency_ms": 1,
            }

    class FakeCtx:
        def __init__(self, cfg):
            self.cfg = dict(cfg)

        def get_config(self, key, default=None):
            return self.cfg.get(key, default)

    old_client, old_ctx = gate.JevClient, toolsmod._CTX
    with tempfile.TemporaryDirectory() as d:
        log = str(Path(d) / "ask.log")
        toolsmod.bind(
            FakeCtx(
                {
                    "jev_model": "custom/model",
                    "jev_base_url": "https://example.invalid/v9",
                    "timeout_s": 9.0,
                    "cache_seconds": 9,
                    "log_path": log,
                }
            )
        )
        gate.JevClient = RecClient
        try:
            out = json.loads(
                toolsmod.jev_ask(
                    {
                        "state": "x",
                        "questions": {"q": {"type": "boolean", "instructions": "?"}},
                    }
                )
            )
        finally:
            gate.JevClient = old_client
            toolsmod.bind(old_ctx)
        assert out["answers"] == {"q": {"probability": 0.9}}, out
        assert seen == {
            "base_url": "https://example.invalid/v9",
            "model": "custom/model",
            "timeout": 9.0,
            "cache_seconds": 9,
            "backend": "auto",
            "typesafe_model": "jev-latest",
            "typesafe_base_url": "https://api.typesafe.ai",
            "openrouter_model": "~typesafe/jev-latest",
            "openrouter_base_url": "https://openrouter.ai/api/alpha",
            "retry_max_wait_s": 2.0,
            "breaker_threshold": 3,
            "breaker_cooldown_s": 120,
            "min_interval_s": 0.25,
        }, seen
        line = json.loads(Path(log).read_text().strip())
        assert line["source"] == "ask" and line["outcome"] == "ok", line
    print("ok  jev_ask usa settings (model, base_url, timeout, log)")


def test_build_state_truncates():
    state = gate.build_state("terminal", {"command": "run tests " * 90, "extra": 1})
    cmd = state["action"]["arguments"]["command"]
    assert len(cmd) < 700 and "chars)" in cmd, cmd[-40:]
    print("ok  build_state truncou argumento longo")


def test_judge_triggers():
    stub = StubClient(
        answers={
            "destructive": {"type": "boolean", "probability": 0.97},
            "exfiltration": {"type": "boolean", "probability": 0.10},
            "impact": {"type": "score", "score": 2.9},
        },
        confidence={"destructive": 0.99},
    )
    v = gate.judge(stub, "terminal", {"command": "rm -rf /tmp/x"}, {})
    assert v["triggered"] == ["destructive", "impact"], v
    assert v["thresholds"]["destructive_threshold"] == 0.90
    print("ok  judge disparou destructive + impact")


def test_judge_clear_and_custom_threshold():
    stub = StubClient(
        answers={
            "destructive": {"type": "boolean", "probability": 0.80},
            "exfiltration": {"type": "boolean", "probability": 0.0},
            "impact": {"type": "score", "score": 0.4},
        }
    )
    assert gate.judge(stub, "terminal", {"command": "ls"}, {})["triggered"] == []
    v = gate.judge(stub, "terminal", {"command": "ls"}, {"destructive_threshold": 0.75})
    assert v["triggered"] == ["destructive"], v
    print("ok  judge limpo por padrão, dispara com limiar customizado")


def test_fail_open():
    v = gate.judge(StubClient(answers=None), "terminal", {"command": "ls"}, {})
    assert v["outcome"] == "fail_open" and v["reason"] == "transport", v
    print("ok  fail-open: cliente sem resposta vira fail_open com motivo")


def test_log_writes_jsonl(tmpdir=None):
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "jev.log"
        gate.log_decision(str(path), {"source": "gate", "outcome": "clear"})
        line = json.loads(path.read_text().strip())
        assert line["source"] == "gate" and "ts" in line, line
    print("ok  log_decision escreveu JSONL válido")


# --- Dual backend (ticket 10): transporte stubado, relógio mockado, sem rede ---

import email.utils as _email_utils
import os as _os
import tempfile as _tempfile
import time as _time
import urllib.error as _urlerror


class _FakeResp:
    def __init__(self, body):
        self._raw = json.dumps(body).encode()

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeRaw:
    """Corpo bruto (ex.: HTML de erro) para exercitar falha de parse."""

    def __init__(self, text):
        self._raw = text.encode() if isinstance(text, str) else bytes(text)

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _http_error(code, retry_after=None):
    hdrs = {}
    if retry_after is not None:
        hdrs["retry-after"] = retry_after
    return _urlerror.HTTPError("https://x.invalid/", code, "limited", hdrs, None)


class _Script:
    """Transporte stubado: ('ok', body) | ('raw', texto) | ('error', exc) | ('http', code, retry-after)."""

    def __init__(self, steps):
        self.steps = list(steps)
        self.calls = []  # (url, headers minúsculos, payload)

    def __call__(self, req, timeout=None):
        headers = {k.lower(): v for k, v in req.header_items()}
        payload = json.loads(req.data.decode())
        self.calls.append((req.full_url, headers, payload))
        kind = self.steps.pop(0)
        if kind[0] == "ok":
            return _FakeResp(kind[1])
        if kind[0] == "raw":
            return _FakeRaw(kind[1])
        if kind[0] == "error":
            raise kind[1]
        raise _http_error(kind[1], kind[2] if len(kind) > 2 else None)


class _Clock:
    def __init__(self):
        self.t = 1000.0
        self.sleeps = []

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


_TS_BODY = {
    "answers": {
        "destructive": {"type": "noul", "noul": 0.97},
        "pick": {
            "type": "choice",
            "choice": "b",
            "probabilities": {"a": 0.1, "b": 0.9},
            "confidence": 0.8,
        },
        "impact": {
            "type": "score",
            "score": 1.6,
            "probabilities": {"0": 0.1, "1": 0.2, "2": 0.5, "3": 0.2},
            "confidence": 0.78,
        },
    },
    "usage": {"input_tokens": 10, "output_tokens": 5},
}

_GW_BODY = {
    "answers": {"destructive": {"type": "boolean", "probability": 0.97}},
    "providerMetadata": {
        "typesafe": {"confidence": {"destructive": 0.99}},
        "gateway": {"cost": "0.00002"},
    },
    "usage": {"input_tokens": 10, "output_tokens": 5},
}

_QUESTIONS = {
    "destructive": {
        "type": "boolean",
        "instructions": "Is it destructive?",
        "criteria": {"true": "loss", "false": "safe"},
    },
    "pick": {
        "type": "choice",
        "instructions": "Which?",
        "criteria": {"a": "first", "b": "second"},
    },
    "impact": {
        "type": "score",
        "instructions": "How bad?",
        "criteria": ["low", "high"],
    },
}


def _dual_client(keys, **kw):
    """Cliente com HERMES_HOME vazio, chaves controladas e estado global zerado."""
    steps = kw.pop("_steps", None) or []
    kw.setdefault("min_interval_s", 0)
    with _tempfile.TemporaryDirectory() as home:
        saved = {
            n: _os.environ.get(n) for n in ("TYPESAFE_API_KEY", "AI_GATEWAY_API_KEY", "HERMES_HOME")
        }
        try:
            for n in ("TYPESAFE_API_KEY", "AI_GATEWAY_API_KEY"):
                _os.environ.pop(n, None)
            for n, v in keys.items():
                _os.environ[n] = v
            _os.environ["HERMES_HOME"] = home
            jev._PACE_LAST.clear()
            jev._BREAKER.clear()
            client = jev.JevClient(**kw)
            clock = _Clock()
            client._clock = clock.monotonic
            client._sleep = clock.sleep
            script = _Script(steps)
            client._urlopen = script
            yield client, script, clock
        finally:
            for n, v in saved.items():
                if v is None:
                    _os.environ.pop(n, None)
                else:
                    _os.environ[n] = v


def _run_dual(keys, **kw):
    """Devolve o context manager; entrar com _enter, sair com _leave."""
    import contextlib

    return contextlib.contextmanager(_dual_client)(keys, **kw)


def _enter(ctx):
    entered = ctx.__enter__()
    entered[0]._test_ctx = ctx
    return entered


def _leave(client):
    client._test_ctx.__exit__(None, None, None)


def test_typesafe_noul_mapping():
    client, script, _ = _enter(_run_dual({"TYPESAFE_API_KEY": "ts-key"}, _steps=[("ok", _TS_BODY)]))
    try:
        res = client.evaluate({"action": "x"}, _QUESTIONS)
        assert res is not None, "typesafe com chave devia responder"
        assert len(script.calls) == 1
        url, headers, payload = script.calls[0]
        assert url == "https://api.typesafe.ai/v1/systemone", url
        assert headers.get("authorization") == "Bearer ts-key", headers
        assert "ai-model-id" not in headers, headers
        assert payload["model"] == "jev-latest", payload
        assert payload["questions"]["destructive"] == {
            "type": "noul",
            "instructions": "Is it destructive?",
            "criteria": {"true": "loss", "false": "safe"},
        }, payload["questions"]["destructive"]
        assert payload["questions"]["pick"]["type"] == "choice"
        assert res["answers"]["destructive"] == {"type": "boolean", "probability": 0.97}, res
        assert res["answers"]["pick"]["choice"] == "b", res
        assert res["answers"]["impact"]["score"] == 1.6, res
        assert res["confidence"] == {"pick": 0.8, "impact": 0.78}, res["confidence"]
        assert res["cost"] is None, res
        assert res["usage"] == {"input_tokens": 10, "output_tokens": 5}, res
    finally:
        _leave(client)
    print("ok  typesafe direto: boolean vira noul, confiança inline, custo None")


def test_gateway_confidence_and_cost():
    client, script, _ = _enter(_run_dual({"AI_GATEWAY_API_KEY": "gw-key"}, _steps=[("ok", _GW_BODY)]))
    try:
        res = client.evaluate({"action": "x"}, _QUESTIONS)
        assert res is not None
        url, headers, payload = script.calls[0]
        assert url == "https://ai-gateway.vercel.sh/v4/ai/evaluation-model", url
        assert headers.get("ai-model-id") == "typesafe-ai/jev", headers
        assert "model" not in payload, payload
        assert payload["questions"]["destructive"]["type"] == "boolean", payload
        assert res["answers"] == _GW_BODY["answers"], res
        assert res["confidence"] == {"destructive": 0.99}, res
        assert res["cost"] == "0.00002", res
    finally:
        _leave(client)
    print("ok  gateway: confiança via providerMetadata, custo repassado")


def _selection_matrix():
    return [
        ({"TYPESAFE_API_KEY": "t", "AI_GATEWAY_API_KEY": "g"}, "auto", "typesafe"),
        ({"AI_GATEWAY_API_KEY": "g"}, "auto", "gateway"),
        ({"TYPESAFE_API_KEY": "t"}, "auto", "typesafe"),
        ({}, "auto", None),
        ({"TYPESAFE_API_KEY": "", "AI_GATEWAY_API_KEY": "g"}, "auto", "gateway"),
        ({"AI_GATEWAY_API_KEY": "g"}, "typesafe", None),
        ({"TYPESAFE_API_KEY": "t"}, "gateway", None),
        ({"TYPESAFE_API_KEY": "t", "AI_GATEWAY_API_KEY": "g"}, "gateway", "gateway"),
        ({"TYPESAFE_API_KEY": "t", "AI_GATEWAY_API_KEY": "g"}, "bogus", "typesafe"),
    ]


def test_backend_selection():
    want_url = {
        "typesafe": "https://api.typesafe.ai/v1/systemone",
        "gateway": "https://ai-gateway.vercel.sh/v4/ai/evaluation-model",
    }
    for keys, backend, want in _selection_matrix():
        steps = [("ok", _GW_BODY)] if want else []
        client, script, _ = _enter(_run_dual(keys, backend=backend, _steps=steps))
        try:
            assert jev.resolve_backend(backend) == want, (keys, backend, want)
            res = client.evaluate({"a": 1}, {"q": {"type": "boolean", "instructions": "?"}})
            if want is None:
                assert res is None and script.calls == [], (keys, backend)
            else:
                assert res is not None and len(script.calls) == 1, (keys, backend)
                assert script.calls[0][0] == want_url[want], script.calls[0][0]
        finally:
            _leave(client)
    # Sem chave e com transporte que explodiria se tocado: silêncio total.
    client, script, _ = _enter(_run_dual({}))
    try:
        assert client.evaluate({"a": 1}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert script.calls == []
    finally:
        _leave(client)
    print("ok  backend auto|typesafe|gateway resolve e silencia sem chave")


def test_retry_after_seconds():
    client, script, clock = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("http", 429, "1"), ("ok", _GW_BODY)])
    )
    try:
        res = client.evaluate({"a": 1}, {"q": {"type": "boolean", "instructions": "?"}})
        assert res is not None and len(script.calls) == 2, script.calls
        assert clock.sleeps == [1.0], clock.sleeps
    finally:
        _leave(client)
    print("ok  retry honrou Retry-After em segundos (1 retry)")


def test_retry_after_http_date():
    when = _email_utils.formatdate(_time.time() + 1, usegmt=True)
    client, script, clock = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("http", 429, when), ("ok", _GW_BODY)])
    )
    try:
        res = client.evaluate({"a": 1}, {"q": {"type": "boolean", "instructions": "?"}})
        assert res is not None and len(script.calls) == 2, script.calls
        assert len(clock.sleeps) == 1 and 0 < clock.sleeps[0] <= 2.0, clock.sleeps
    finally:
        _leave(client)
    print("ok  retry honrou Retry-After como data HTTP")


def test_retry_after_garbage():
    client, script, clock = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("http", 429, "banana")])
    )
    try:
        assert jev.retry_after_s("banana", _time.time()) is None
        assert jev.retry_after_s("", _time.time()) is None
        assert jev.retry_after_s(None, _time.time()) is None
        assert client.evaluate({"a": 1}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert len(script.calls) == 1 and clock.sleeps == [], (script.calls, clock.sleeps)
    finally:
        _leave(client)
    print("ok  Retry-After lixo: sem retry, fail-open")


def test_retry_after_too_long():
    client, script, clock = _enter(
        _run_dual(
            {"AI_GATEWAY_API_KEY": "g"},
            retry_max_wait_s=2.0,
            _steps=[("http", 429, "30")],
        )
    )
    try:
        assert client.evaluate({"a": 1}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert len(script.calls) == 1 and clock.sleeps == [], (script.calls, clock.sleeps)
    finally:
        _leave(client)
    print("ok  espera acima do teto: sem retry, fail-open")


def test_retry_529():
    client, script, clock = _enter(
        _run_dual({"TYPESAFE_API_KEY": "t"}, _steps=[("http", 529, "1"), ("ok", _TS_BODY)])
    )
    try:
        res = client.evaluate({"a": 1}, {"q": {"type": "boolean", "instructions": "?"}})
        assert res is not None and len(script.calls) == 2, script.calls
        assert res["answers"]["destructive"] == {"type": "boolean", "probability": 0.97}, res
    finally:
        _leave(client)
    print("ok  529 tratado como rate limit (1 retry)")


def test_retry_only_once():
    client, script, clock = _enter(
        _run_dual(
            {"AI_GATEWAY_API_KEY": "g"},
            _steps=[("http", 429, "1"), ("http", 429, "1"), ("ok", _GW_BODY)],
        )
    )
    try:
        assert client.evaluate({"a": 1}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert len(script.calls) == 2, script.calls  # nunca em loop
    finally:
        _leave(client)
    print("ok  retry único: segundo 429 não tenta de novo")


def test_breaker_opens_and_recovers():
    client, script, clock = _enter(
        _run_dual(
            {"AI_GATEWAY_API_KEY": "g"},
            breaker_threshold=3,
            breaker_cooldown_s=120,
            _steps=[("http", 429, "lixo")] * 3,
        )
    )
    try:
        for i in range(3):
            assert client.evaluate({"n": i}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert len(script.calls) == 3, script.calls
        # Breaker aberto: silêncio sem tocar o transporte.
        assert client.evaluate({"n": 99}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert len(script.calls) == 3, script.calls
        # Cooldown passou: volta a tentar; sucesso zera o contador.
        clock.t += 121
        script.steps.append(("ok", _GW_BODY))
        res = client.evaluate({"n": 100}, {"q": {"type": "boolean", "instructions": "?"}})
        assert res is not None and len(script.calls) == 4, script.calls
        script.steps.extend([("http", 429, "lixo")] * 2)
        assert client.evaluate({"n": 101}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert client.evaluate({"n": 102}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert len(script.calls) == 6, script.calls  # 2 falhas pós-sucesso não abrem
    finally:
        _leave(client)
    print("ok  breaker abriu após 3, recuperou após cooldown, sucesso zerou")


def test_min_interval_spacing():
    client, script, clock = _enter(
        _run_dual(
            {"AI_GATEWAY_API_KEY": "g"},
            min_interval_s=0.25,
            _steps=[("ok", _GW_BODY), ("ok", _GW_BODY)],
        )
    )
    try:
        assert client.evaluate({"n": 1}, {"q": {"type": "boolean", "instructions": "?"}}) is not None
        assert client.evaluate({"n": 2}, {"q": {"type": "boolean", "instructions": "?"}}) is not None
        assert clock.sleeps == [0.25], clock.sleeps
    finally:
        _leave(client)
    print("ok  min_interval_s espaçou chamadas (clock mockado)")


def test_silence_without_key():
    client, script, _ = _enter(_run_dual({}, _steps=[("ok", _GW_BODY)]))
    try:
        assert client.evaluate({"a": 1}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert script.calls == [], script.calls
    finally:
        _leave(client)
    print("ok  sem chave nenhuma: silencioso, transporte intocado")


def test_retry_after_nonfinite():
    now = _time.time()
    assert jev.retry_after_s("nan", now) is None
    assert jev.retry_after_s("inf", now) is None
    assert jev.retry_after_s("-inf", now) is None
    client, script, clock = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("http", 429, "nan")])
    )
    try:
        assert client.evaluate({"a": 1}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert len(script.calls) == 1 and clock.sleeps == [], (script.calls, clock.sleeps)
    finally:
        _leave(client)
    print("ok  Retry-After nan/inf: sem retry, fail-open")


def test_breaker_counts_once_per_evaluate():
    client, script, clock = _enter(
        _run_dual(
            {"AI_GATEWAY_API_KEY": "g"},
            breaker_threshold=4,
            _steps=[("http", 429, "1"), ("http", 429, "1")] * 3,
        )
    )
    try:
        for i in range(3):
            assert client.evaluate({"n": i}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        # 3 evaluates x 2 attempts; breaker counts 1 per evaluate, still closed.
        assert len(script.calls) == 6, script.calls
        script.steps.append(("http", 429, "lixo"))
        assert client.evaluate({"n": 99}, {"q": {"type": "boolean", "instructions": "?"}}) is None
        assert len(script.calls) == 7, script.calls
    finally:
        _leave(client)
    print("ok  breaker conta 1 por evaluate (429+429 sem retry duplo)")


def test_boolean_criteria_passthrough():
    out = jev.to_typesafe_questions(
        {
            "q": {
                "type": "boolean",
                "instructions": "?",
                "criteria": {"true": "loss", "false": "safe"},
            }
        }
    )
    assert out == {
        "q": {"type": "noul", "instructions": "?", "criteria": {"true": "loss", "false": "safe"}}
    }, out
    plain = jev.to_typesafe_questions({"q": {"type": "boolean", "instructions": "?"}})
    assert plain == {"q": {"type": "noul", "instructions": "?"}}, plain
    print("ok  criteria propagado no boolean->noul")


# --- Hook pre_tool_call (ticket 9): carrega o __init__.py com ctx stub ---

import os as _os_hook
import tempfile as _tempfile_hook


def _hook_module():
    """Load plugins/jev-judge/__init__.py as jevjudge.hook (relative imports)."""
    pkg = sys.modules["jevjudge"]
    for name in ("schemas",):
        if f"jevjudge.{name}" not in sys.modules:
            spec = importlib.util.spec_from_file_location(
                f"jevjudge.{name}", BASE / f"{name}.py"
            )
            mod = importlib.util.module_from_spec(spec)
            sys.modules[f"jevjudge.{name}"] = mod
            spec.loader.exec_module(mod)
    for name in ("gate", "schemas", "tools"):
        setattr(pkg, name, sys.modules[f"jevjudge.{name}"])
    spec = importlib.util.spec_from_file_location("jevjudge.hook", BASE / "__init__.py")
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "jevjudge"  # senão o import relativo clona gate/tools
    sys.modules["jevjudge.hook"] = mod
    spec.loader.exec_module(mod)
    return mod


class _HookCtx:
    def __init__(self, cfg):
        self.cfg = dict(cfg)
        self.hooks = {}
        self.tools = {}

    def get_config(self, key, default=None):
        return self.cfg.get(key, default)

    def register_hook(self, name, callback):
        self.hooks[name] = callback

    def register_tool(self, name, toolset=None, schema=None, handler=None):
        self.tools[name] = handler


def _run_hook(cfg, verdict):
    """Register the hook with cfg; judge stubbed to return verdict. No network."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        with _tempfile_hook.TemporaryDirectory() as home:
            saved = _os_hook.environ.get("HERMES_HOME")
            _os_hook.environ["HERMES_HOME"] = home
            log = str(Path(home) / "hook.log")
            hook = _hook_module()
            ctx = _HookCtx({**cfg, "log_path": log})
            hook.register(ctx)
            calls = {}
            old_judge, old_client_for = gate.judge, gate.client_for

            def fake_judge(client, tool_name, args, thresholds):
                calls["judge"] = (tool_name, args)
                return verdict

            gate.judge = fake_judge
            gate.client_for = lambda s: object()
            try:
                yield ctx.hooks["pre_tool_call"], calls, Path(log)
            finally:
                gate.judge = old_judge
                gate.client_for = old_client_for
                _os_hook.environ.pop("HERMES_HOME", None)
                if saved is not None:
                    _os_hook.environ["HERMES_HOME"] = saved

    return _ctx()


def _triggered():
    return {"triggered": ["destructive"], "probabilities": {}, "confidence": {}}


def test_hook_shadow_no_interfere():
    with _run_hook({"mode": "shadow", "tools": ["terminal"]}, _triggered()) as (h, calls, log):
        assert h(tool_name="terminal", args={"command": "rm -rf /"}, task_id="t1") is None
        assert calls["judge"][0] == "terminal", calls
        line = json.loads(log.read_text().strip())
        assert line["outcome"] == "flagged_shadow" and line["task_id"] == "t1", line
    print("ok  hook shadow dispara mas nao interfere")


def test_hook_enforce_escalates():
    with _run_hook({"mode": "enforce", "tools": ["terminal"]}, _triggered()) as (h, calls, log):
        out = h(tool_name="terminal", args={"command": "rm -rf /"}, task_id="t2")
        assert out["action"] == "approve" and "terminal" in out["message"], out
        line = json.loads(log.read_text().strip())
        assert line["outcome"] == "escalated", line
    print("ok  hook enforce devolve approve")


def test_hook_tool_not_listed():
    with _run_hook({"mode": "enforce", "tools": ["terminal"]}, _triggered()) as (h, calls, log):
        assert h(tool_name="patch", args={}) is None
        assert "judge" not in calls, calls
        assert not log.exists(), "ferramenta fora da lista nem devia logar"
    print("ok  hook ignora ferramenta fora da lista")


def test_hook_tools_string_no_substring():
    with _run_hook({"mode": "enforce", "tools": "terminal"}, _triggered()) as (h, calls, log):
        assert h(tool_name="term", args={}) is None  # substring nao casa
        assert "judge" not in calls, calls
    with _run_hook({"mode": "shadow", "tools": "terminal"}, None) as (h, calls, log):
        assert h(tool_name="terminal", args={}) is None  # fail-open sem resposta
        assert calls["judge"][0] == "terminal", calls
        line = json.loads(log.read_text().strip())
        assert line["outcome"] == "fail_open" and line["reason"] == "transport", line
    print("ok  hook com tools string: sem substring, fail-open sem chave")


def test_hook_clear_verdict():
    verdict = {"triggered": [], "probabilities": {}, "confidence": {}}
    with _run_hook({"mode": "shadow", "tools": ["terminal"]}, verdict) as (h, calls, log):
        assert h(tool_name="terminal", args={"command": "ls"}) is None
        line = json.loads(log.read_text().strip())
        assert line["outcome"] == "clear", line
    print("ok  hook veredito limpo nao interfere")


def test_env_key_strips():
    saved = {n: _os_hook.environ.get(n) for n in ("AI_GATEWAY_API_KEY", "HERMES_HOME")}
    try:
        with _tempfile_hook.TemporaryDirectory() as home:
            _os_hook.environ["HERMES_HOME"] = home
            _os_hook.environ["AI_GATEWAY_API_KEY"] = "  padded-key \r\n"
            assert jev.api_key() == "padded-key", repr(jev.api_key())
            _os_hook.environ.pop("AI_GATEWAY_API_KEY", None)
            (Path(home) / ".env").write_text("AI_GATEWAY_API_KEY=dotenv-key  \r\n")
            assert jev.api_key() == "dotenv-key", repr(jev.api_key())
    finally:
        for n, v in saved.items():
            _os_hook.environ.pop(n, None)
            if v is not None:
                _os_hook.environ[n] = v
    print("ok  api_key com strip (env e .env)")


def test_timeout_clamped():
    assert jev.JevClient(timeout=30).timeout == 10.0
    assert jev.JevClient(timeout=3.0).timeout == 3.0
    print("ok  timeout clampado em 10s")


def test_cache_size_capped():
    client, script, _ = _enter(
        _run_dual(
            {"AI_GATEWAY_API_KEY": "g"},
            _steps=[("ok", _GW_BODY)] * (jev.CACHE_MAX_ENTRIES + 20),
        )
    )
    try:
        for i in range(jev.CACHE_MAX_ENTRIES + 20):
            res = client.evaluate({"n": i}, {"q": {"type": "boolean", "instructions": "?"}})
            assert res is not None
        assert len(client._cache) <= jev.CACHE_MAX_ENTRIES, len(client._cache)
    finally:
        _leave(client)
    print("ok  cache do judge com teto de tamanho")


# --- Ticket 18: fail-open com motivo + contrato estrito de resposta ---

_Q18 = {"q": {"type": "boolean", "instructions": "?"}}


def test_fail_reason_no_key():
    client, script, _ = _enter(_run_dual({}))
    try:
        assert client.evaluate({"a": 1}, _Q18) is None
        assert client.last_fail_reason == "no_key", client.last_fail_reason
        assert script.calls == []
    finally:
        _leave(client)
    print("ok  sem chave: motivo no_key, transporte intocado")


def test_fail_reason_timeout():
    client, script, _ = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("error", TimeoutError("timed out"))])
    )
    try:
        assert client.evaluate({"a": 1}, _Q18) is None
        assert client.last_fail_reason == "timeout", client.last_fail_reason
    finally:
        _leave(client)
    print("ok  timeout: motivo timeout")


def test_fail_reason_transport():
    client, script, _ = _enter(
        _run_dual(
            {"AI_GATEWAY_API_KEY": "g"},
            _steps=[("error", _urlerror.URLError("conn refused"))],
        )
    )
    try:
        assert client.evaluate({"a": 1}, _Q18) is None
        assert client.last_fail_reason == "transport", client.last_fail_reason
    finally:
        _leave(client)
    print("ok  erro de rede: motivo transport")


def test_fail_reason_http_status():
    client, script, _ = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("http", 500)])
    )
    try:
        assert client.evaluate({"a": 1}, _Q18) is None
        assert client.last_fail_reason == "http_500", client.last_fail_reason
        assert len(script.calls) == 1
    finally:
        _leave(client)
    client, script, _ = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("http", 429, "lixo")])
    )
    try:
        assert client.evaluate({"a": 1}, _Q18) is None
        assert client.last_fail_reason == "http_429", client.last_fail_reason
    finally:
        _leave(client)
    print("ok  http_500 e http_429 (sem retry): motivo http_<status>")


def test_transient_502_retried_once():
    client, script, _ = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("http", 502), ("ok", _GW_BODY)])
    )
    try:
        assert client.evaluate({"a": 1}, _Q18) is not None
        assert client.last_fail_reason is None, client.last_fail_reason
        assert len(script.calls) == 2, script.calls
    finally:
        _leave(client)
    client, script, _ = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("http", 503), ("http", 502)])
    )
    try:
        assert client.evaluate({"a": 1}, _Q18) is None
        assert client.last_fail_reason == "http_502", client.last_fail_reason
        assert len(script.calls) == 2, script.calls
    finally:
        _leave(client)
    print("ok  502/503 transitorio: um retry, depois fail-open")


def test_fail_reason_parse():
    client, script, _ = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("raw", "<html>nao e json")])
    )
    try:
        assert client.evaluate({"a": 1}, _Q18) is None
        assert client.last_fail_reason == "parse", client.last_fail_reason
    finally:
        _leave(client)
    print("ok  corpo nao-JSON: motivo parse")


def test_fail_reason_breaker():
    client, script, _ = _enter(
        _run_dual(
            {"AI_GATEWAY_API_KEY": "g"},
            breaker_threshold=1,
            _steps=[("http", 429, "lixo")],
        )
    )
    try:
        assert client.evaluate({"n": 1}, _Q18) is None
        assert client.last_fail_reason == "http_429", client.last_fail_reason
        assert client.evaluate({"n": 2}, _Q18) is None
        assert client.last_fail_reason == "breaker", client.last_fail_reason
        assert len(script.calls) == 1, script.calls
    finally:
        _leave(client)
    print("ok  breaker aberto: motivo breaker sem tocar o transporte")


def test_fail_reason_cleared_on_success():
    client, script, _ = _enter(
        _run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("http", 500), ("ok", _GW_BODY)])
    )
    try:
        assert client.evaluate({"n": 1}, _Q18) is None
        assert client.last_fail_reason == "http_500"
        assert client.evaluate({"n": 2}, _Q18) is not None
        assert client.last_fail_reason is None, client.last_fail_reason
    finally:
        _leave(client)
    print("ok  sucesso limpa o motivo da falha anterior")


def test_extract_signals():
    answers = {
        "destructive": {"type": "boolean", "probability": 0.2},
        "exfiltration": {"type": "boolean", "probability": 0.9},
        "impact": {"type": "score", "score": 2.9},
    }
    signals, missing = gate.extract_signals(answers, gate.GATE_QUESTIONS)
    assert signals == {"destructive": 0.2, "exfiltration": 0.9, "impact": 2.9}, signals
    assert missing == [], missing
    _, missing = gate.extract_signals(
        {"destructive": {"type": "boolean", "probability": 0.2}}, gate.GATE_QUESTIONS
    )
    assert missing == ["exfiltration", "impact"], missing
    renamed = dict(answers)
    renamed["exfiltrated"] = renamed.pop("exfiltration")
    _, missing = gate.extract_signals(renamed, gate.GATE_QUESTIONS)
    assert missing == ["exfiltration"], missing
    bad = dict(answers)
    bad["destructive"] = {"type": "boolean", "probability": "alta"}
    _, missing = gate.extract_signals(bad, gate.GATE_QUESTIONS)
    assert missing == ["destructive"], missing
    print("ok  extract_signals: ausente, renomeada e malformada viram missing")


def test_judge_answer_missing():
    stub = StubClient(
        answers={
            "destructive": {"type": "boolean", "probability": 0.1},
            "impact": {"type": "score", "score": 0.2},
        }
    )
    v = gate.judge(stub, "terminal", {"command": "ls"}, {})
    assert v["outcome"] == "fail_open" and v["reason"] == "answer_missing", v
    assert v["missing"] == ["exfiltration"], v
    assert "triggered" not in v, v  # nunca clear, nunca 0.0
    print("ok  pergunta sem resposta: answer_missing, nunca clear")


def test_judge_fail_open_carries_client_reason():
    v = gate.judge(
        StubClient(answers=None, reason="timeout"), "terminal", {"command": "ls"}, {}
    )
    assert v == {"tool": "terminal", "outcome": "fail_open", "reason": "timeout"}, v
    print("ok  judge repassa o motivo do cliente no fail-open")


def test_hook_fail_open_logs_reason():
    import contextlib

    @contextlib.contextmanager
    def _real_judge_hook(cfg, client):
        with _tempfile_hook.TemporaryDirectory() as home:
            saved = _os_hook.environ.get("HERMES_HOME")
            _os_hook.environ["HERMES_HOME"] = home
            log = str(Path(home) / "hook.log")
            hook = _hook_module()
            ctx = _HookCtx({**cfg, "log_path": log})
            hook.register(ctx)
            old_client_for = gate.client_for
            gate.client_for = lambda s: client
            try:
                yield ctx.hooks["pre_tool_call"], Path(log)
            finally:
                gate.client_for = old_client_for
                _os_hook.environ.pop("HERMES_HOME", None)
                if saved is not None:
                    _os_hook.environ["HERMES_HOME"] = saved

    with _real_judge_hook(
        {"mode": "shadow", "tools": ["terminal"]},
        StubClient(answers=None, reason="timeout"),
    ) as (h, log):
        assert h(tool_name="terminal", args={"command": "ls"}, task_id="t9") is None
        line = json.loads(log.read_text().strip())
        assert line["outcome"] == "fail_open" and line["reason"] == "timeout", line
    with _real_judge_hook(
        {"mode": "shadow", "tools": ["terminal"]},
        StubClient(answers={"destructive": {"type": "boolean", "probability": 0.1}}),
    ) as (h, log):
        assert h(tool_name="terminal", args={"command": "ls"}) is None
        line = json.loads(log.read_text().strip())
        assert line["outcome"] == "fail_open" and line["reason"] == "answer_missing", line
        assert line["missing"] == ["exfiltration", "impact"], line
    print("ok  hook loga o motivo do fail-open (timeout, answer_missing)")


# --- Ticket 19: transporte endurecido + normalização estrita ---

import urllib.request as _urlrequest


def _opener_uses_proxy(opener):
    """True se algum ProxyHandler atua nas cadeias http/https do opener."""
    chains = opener.handle_open.get("http", []) + opener.handle_open.get("https", [])
    return any(isinstance(h, _urlrequest.ProxyHandler) for h in chains)


def test_transport_default_hardened():
    with _run_dual({}):
        fresh = jev.JevClient()  # fresco: _dual_client troca _urlopen pelo stub
        assert fresh._urlopen is jev._urlopen, "default deve ser o transporte endurecido"
        assert fresh._urlopen is not _urlrequest.urlopen
        assert any(isinstance(h, jev._NoRedirect) for h in jev._OPENER.handlers)
        assert not _opener_uses_proxy(jev._OPENER)
    print("ok  transporte default: sem redirect, sem proxy do ambiente")


def test_transport_redirect_fail_open():
    client, script, _ = _enter(_run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("http", 302)]))
    try:
        assert client.evaluate({"a": 1}, _Q18) is None
        assert client.last_fail_reason == "http_302", client.last_fail_reason
        assert len(script.calls) == 1, script.calls  # 3xx nunca é seguido
    finally:
        _leave(client)
    redir = jev._NoRedirect().redirect_request(
        object(), None, 302, "Found", {}, "https://x.invalid/"
    )
    assert redir is None, redir
    print("ok  302 vira fail-open http_302 sem seguir redirect")


def test_transport_ignores_proxy_env():
    saved = {n: _os.environ.get(n) for n in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")}
    try:
        for n in saved:
            _os.environ[n] = "http://proxy.invalid:8080"
        assert _urlrequest.getproxies(), "sanidade: o env vaza para o default do urllib"
        assert _opener_uses_proxy(_urlrequest.build_opener()), "sanidade: opener default usa proxy"
        assert not _opener_uses_proxy(jev._OPENER), "opener endurecido ignora o env"
    finally:
        for n, v in saved.items():
            if v is None:
                _os.environ.pop(n, None)
            else:
                _os.environ[n] = v
    print("ok  proxy do ambiente ignorado mesmo com http(s)_proxy setado")


def test_payload_cap_fail_open():
    big = {"action": "x", "blob": "y" * (jev.MAX_PAYLOAD_BYTES + 1)}
    client, script, _ = _enter(_run_dual({"AI_GATEWAY_API_KEY": "g"}, _steps=[("ok", _GW_BODY)]))
    try:
        assert client.evaluate(big, _Q18) is None
        assert client.last_fail_reason == "payload_too_large", client.last_fail_reason
        assert script.calls == [], script.calls  # nada saiu: nunca vira veredito
        assert client.evaluate({"a": 1}, _Q18) is not None  # sob o cap, passa
        assert len(script.calls) == 1, script.calls
    finally:
        _leave(client)
    print("ok  payload acima do cap: nada enviado, fail-open payload_too_large")


def test_normalize_strict_noul():
    out = jev.normalize_typesafe_answers(
        {
            "ok": {"type": "noul", "noul": 0.97},
            "zero": {"type": "noul", "noul": 0.0},  # 0.0 explícito do servidor passa
            "one": {"type": "noul", "noul": 1.0},  # 1.0 explícito do servidor passa
            "false": {"type": "noul", "noul": False},  # bool não é número: some (#28)
            "true": {"type": "noul", "noul": True},  # bool não é número: some (#28)
            "missing": {"type": "noul"},
            "null": {"type": "noul", "noul": None},
            "garbage": {"type": "noul", "noul": "alta"},
            "nan": {"type": "noul", "noul": "nan"},
            "inf": {"type": "noul", "noul": float("inf")},
            "choice": {"type": "choice", "choice": "b"},
        }
    )
    assert out["ok"] == {"type": "boolean", "probability": 0.97}, out
    assert out["zero"] == {"type": "boolean", "probability": 0.0}, out
    assert out["one"] == {"type": "boolean", "probability": 1.0}, out
    assert out["choice"] == {"type": "choice", "choice": "b"}, out
    for qid in ("missing", "null", "garbage", "nan", "inf", "false", "true"):
        assert qid not in out, (qid, out)  # nunca fabrica 0.0: some, o gate lê missing
    print("ok  noul ausente/malformado some (nunca 0.0); 0.0 explícito passa")


def test_malformed_noul_becomes_missing():
    body = {"answers": {"destructive": {"type": "noul"}}, "usage": {}}
    client, _, _ = _enter(_run_dual({"TYPESAFE_API_KEY": "t"}, _steps=[("ok", body)]))
    try:
        res = client.evaluate({"a": 1}, _Q18)
        assert res is not None and res["answers"] == {}, res
        _, missing = gate.extract_signals(res["answers"], gate.GATE_QUESTIONS)
        assert "destructive" in missing, missing  # defeito, nunca veredito favorável
    finally:
        _leave(client)
    print("ok  noul malformado no fio vira missing no gate")


def test_jev_ask_logs_reason():
    class _FailCtx:
        def __init__(self, cfg):
            self.cfg = dict(cfg)

        def get_config(self, key, default=None):
            return self.cfg.get(key, default)

    old_client, old_ctx = gate.JevClient, toolsmod._CTX
    with _tempfile.TemporaryDirectory() as d:
        log = str(Path(d) / "ask.log")
        toolsmod.bind(_FailCtx({"jev_model": "reason/model", "log_path": log}))
        gate.JevClient = lambda **kw: StubClient(answers=None, reason="timeout")
        try:
            out = json.loads(
                toolsmod.jev_ask(
                    {"state": "x", "questions": {"q": {"type": "boolean", "instructions": "?"}}}
                )
            )
        finally:
            gate.JevClient = old_client
            toolsmod.bind(old_ctx)
        assert out["note"].startswith("fail-open"), out
        line = json.loads(Path(log).read_text().strip())
        assert line["source"] == "ask" and line["outcome"] == "fail_open", line
        assert line["reason"] == "timeout", line
    print("ok  jev_ask loga reason no fail-open como o hook")


def test_malformed_answers_fail_open():
    """A provider body whose answers is not a map must fail open, not raise."""
    script = _Script([("ok", {"model": "x", "answers": "not-a-map", "usage": {}})])
    client = jev.JevClient(backend="openrouter", timeout=1.0, min_interval_s=0.0,
                           cache_seconds=0)
    client._urlopen = script
    clock = _Clock()
    client._clock = clock.monotonic
    client._sleep = clock.sleep
    key_had = _os.environ.get("OPENROUTER_API_KEY")
    _os.environ["OPENROUTER_API_KEY"] = "k-test"
    try:
        out = client.evaluate(
            {"s": 1}, {"q": {"type": "boolean", "instructions": "x?"}})
    finally:
        if key_had is None:
            _os.environ.pop("OPENROUTER_API_KEY", None)
        else:
            _os.environ["OPENROUTER_API_KEY"] = key_had
    assert out is None, out
    print("ok  answers nao-mapa -> fail-open (None), sem excecao")


if __name__ == "__main__":
    for fn in (
        test_redact,
        test_redact_pocs,
        test_jev_ask_uses_settings,
        test_build_state_truncates,
        test_judge_triggers,
        test_judge_clear_and_custom_threshold,
        test_fail_open,
        test_log_writes_jsonl,
        test_typesafe_noul_mapping,
        test_gateway_confidence_and_cost,
        test_backend_selection,
        test_retry_after_seconds,
        test_retry_after_http_date,
        test_retry_after_garbage,
        test_retry_after_too_long,
        test_retry_529,
        test_retry_only_once,
        test_breaker_opens_and_recovers,
        test_min_interval_spacing,
        test_silence_without_key,
        test_retry_after_nonfinite,
        test_breaker_counts_once_per_evaluate,
        test_boolean_criteria_passthrough,
        test_hook_shadow_no_interfere,
        test_hook_enforce_escalates,
        test_hook_tool_not_listed,
        test_hook_tools_string_no_substring,
        test_hook_clear_verdict,
        test_env_key_strips,
        test_timeout_clamped,
        test_cache_size_capped,
        test_malformed_answers_fail_open,
        test_fail_reason_no_key,
        test_fail_reason_timeout,
        test_fail_reason_transport,
        test_fail_reason_http_status,
        test_transient_502_retried_once,
        test_fail_reason_parse,
        test_fail_reason_breaker,
        test_fail_reason_cleared_on_success,
        test_extract_signals,
        test_judge_answer_missing,
        test_judge_fail_open_carries_client_reason,
        test_hook_fail_open_logs_reason,
        test_transport_default_hardened,
        test_transport_redirect_fail_open,
        test_transport_ignores_proxy_env,
        test_payload_cap_fail_open,
        test_normalize_strict_noul,
        test_malformed_noul_becomes_missing,
        test_jev_ask_logs_reason,
    ):
        fn()
    print("\ntodos os testes offline passaram")


# restore host env after the suite
if _HERMES_HOME_SAVED is None:
    _os.environ.pop("HERMES_HOME", None)
else:
    _os.environ["HERMES_HOME"] = _HERMES_HOME_SAVED
_TEMP_HERMES_HOME.cleanup()
