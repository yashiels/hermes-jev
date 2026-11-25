"""Jev client — TypeSafe System One, Vercel AI Gateway, or OpenRouter.

Pure stdlib. Backend selection (`backend: auto|typesafe|gateway|openrouter`,
default `auto`) falls back in this order: TypeSafe direct, OpenRouter, gateway,
then silent when no corresponding key is present. Every failure path returns
None (fail-open) and records a short machine-readable reason on
`last_fail_reason` (`no_key | timeout | breaker | http_<status> |
transport | parse | payload_too_large`).
"""

from __future__ import annotations

import email.utils
import hashlib
import json
import logging
import math
import os
import re
import socket
import time
import urllib.error
import urllib.request
from datetime import timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://ai-gateway.vercel.sh/v4/ai"
DEFAULT_MODEL = "typesafe-ai/jev"
DEFAULT_TYPESAFE_BASE_URL = "https://api.typesafe.ai"
DEFAULT_TYPESAFE_MODEL = "jev-latest"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/alpha"
DEFAULT_OPENROUTER_MODEL = "~typesafe/jev-latest"
PROTOCOL_VERSION = "0.0.1"
SPEC_VERSION = "4"

RATE_LIMIT_CODES = (429, 529)
TRANSIENT_UPSTREAM_CODES = (502, 503, 504)
TRANSIENT_RETRY_PAUSE_S = 0.5

# Hard ceiling for one attempt: the loader fail-closes pre_tool_call past
# hook_callback_timeout (default 30s), so an unbounded timeout_s would turn
# the documented fail-open into a blocked tool. Worst case per call stays
# ~2x this + retry_max_wait_s, under that budget.
MAX_TIMEOUT_S = 10.0

# Cap for the per-process response cache: distinct turns each insert one
# entry, so size must be bounded even though entries also expire by TTL.
CACHE_MAX_ENTRIES = 256

# Cap for the outbound JSON payload: anything bigger fails open without
# sending (a truncated payload must never become a favorable verdict).
MAX_PAYLOAD_BYTES = 65536


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse 3xx: no redirect is ever followed, fail-open instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Hardened transport: no redirects, proxy env ignored.
_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


def _urlopen(req, timeout=None):
    return _OPENER.open(req, timeout=timeout)

# Per-process state, keyed by endpoint URL: client instances are cached per
# settings (or rebuilt per call), but pacing and breaker must survive that.
_PACE_LAST: dict[str, float] = {}  # endpoint -> monotonic time of last attempt
_BREAKER: dict[str, list] = {}  # endpoint -> [consecutive 429/529s, open-until]

# Known secret prefixes: sk- (OpenAI-style), gh?_ / github_pat_ (GitHub),
# AKIA (AWS access key id), xox* (Slack), AIza (Google), vck_ (Vercel).
_PREFIX_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{4,}"
    r"|gh[a-z]?_[A-Za-z0-9]{8,}"
    r"|github_pat_[A-Za-z0-9_-]{8,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|xox[a-z]*-[A-Za-z0-9-]+"
    r"|AIza[A-Za-z0-9_-]{8,}"
    r"|vck_[A-Za-z0-9_-]{8,})"
)
_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/=]+", re.IGNORECASE)
_BASIC_RE = re.compile(r"Basic\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE)
_PEM_RE = re.compile(r"-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*-----")
_JWT_RE = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")
# Cap-and-flag fallback: any long spaceless run is treated as a secret.
_GENERIC_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,}")


def redact(value, limit: int = 4000) -> str:
    """Stringify, mask key-shaped tokens, truncate."""
    text = (
        value
        if isinstance(value, str)
        else json.dumps(value, ensure_ascii=False, default=str)
    )
    text = _PEM_RE.sub("[REDACTED]", text)
    text = _BEARER_RE.sub("[REDACTED]", text)
    text = _BASIC_RE.sub("[REDACTED]", text)
    text = _JWT_RE.sub("[REDACTED]", text)
    text = _PREFIX_RE.sub("[REDACTED]", text)
    text = _GENERIC_RE.sub("[REDACTED]", text)
    if len(text) > limit:
        text = text[:limit] + f"...(+{len(text) - limit} chars)"
    return text


def _env_key(name: str) -> str | None:
    key = os.environ.get(name)
    if key and key.strip():
        return key.strip()
    env_file = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")) / ".env"
    try:
        m = re.search(
            rf'^{name}=["\']?([^"\'\n]+)', env_file.read_text(), re.MULTILINE
        )
        return m.group(1).strip() if m else None
    except OSError:
        return None


def api_key() -> str | None:
    return _env_key("AI_GATEWAY_API_KEY")


def typesafe_api_key() -> str | None:
    return _env_key("TYPESAFE_API_KEY")


def openrouter_api_key() -> str | None:
    return _env_key("OPENROUTER_API_KEY")


def resolve_backend(backend: str = "auto") -> str | None:
    """Pick 'typesafe' | 'openrouter' | 'gateway' | None (no key for the wanted backend)."""
    want = (backend or "auto").strip().lower()
    if want not in ("auto", "typesafe", "openrouter", "gateway"):
        want = "auto"
    has_ts, has_or, has_gw = (
        bool(typesafe_api_key()),
        bool(openrouter_api_key()),
        bool(api_key()),
    )
    if want == "typesafe":
        return "typesafe" if has_ts else None
    if want == "openrouter":
        return "openrouter" if has_or else None
    if want == "gateway":
        return "gateway" if has_gw else None
    if has_ts:
        return "typesafe"
    if has_or:
        return "openrouter"
    return "gateway" if has_gw else None


def to_typesafe_questions(questions: dict) -> dict:
    """Internal boolean -> TypeSafe noul; choice/score pass through."""
    out = {}
    for qid, question in (questions or {}).items():
        question = dict(question or {})
        if question.get("type") == "boolean":
            out[qid] = {
                "type": "noul",
                "instructions": question.get("instructions", ""),
            }
            if "criteria" in question:
                out[qid]["criteria"] = question["criteria"]
        else:
            out[qid] = question
    return out


def _num(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _noul(value) -> float | None:
    """Finite float or None (missing/malformed noul is never 0.0)."""
    if isinstance(value, bool):
        return None  # bool é subclasse de int: float(False) seria 0.0
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    return num if math.isfinite(num) else None


def normalize_typesafe_answers(answers: dict) -> dict:
    """TypeSafe noul -> internal {probability}; choice/score already internal."""
    out = {}
    for qid, answer in (answers or {}).items():
        if not isinstance(answer, dict):
            continue
        if answer.get("type") == "noul":
            prob = _noul(answer.get("noul"))
            if prob is None:
                continue  # missing/malformed: omit, the gate reads it as missing
            out[qid] = {"type": "boolean", "probability": prob}
        else:
            out[qid] = answer
    return out


def typesafe_confidence(answers: dict) -> dict:
    """Per-answer inline confidence (noul answers carry none)."""
    confidence = {}
    for qid, answer in (answers or {}).items():
        if isinstance(answer, dict) and "confidence" in answer:
            confidence[qid] = _num(answer["confidence"])
    return confidence


def retry_after_s(value, now_wall: float) -> float | None:
    """Parse a Retry-After header: seconds or an HTTP date. Garbage -> None."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        wait = float(text)
    except ValueError:
        pass
    else:
        return wait if math.isfinite(wait) else None
    try:
        moment = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    delta = moment.timestamp() - now_wall
    return delta if math.isfinite(delta) else None


def _classify_error(exc: Exception) -> str:
    """Map a transport exception to a short fail-open reason (no policy here)."""
    if isinstance(exc, urllib.error.HTTPError):
        return f"http_{exc.code}"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", None)
        if isinstance(reason, (TimeoutError, socket.timeout)) or (
            "timed out" in str(reason).lower()
        ):
            return "timeout"
    if isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError)):
        return "parse"
    return "transport"


class JevClient:
    """One call = one request = typed answers (choice / score / boolean)."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = 3.0,
        cache_seconds: int = 300,
        backend: str = "auto",
        typesafe_model: str = DEFAULT_TYPESAFE_MODEL,
        typesafe_base_url: str = DEFAULT_TYPESAFE_BASE_URL,
        openrouter_model: str = DEFAULT_OPENROUTER_MODEL,
        openrouter_base_url: str = DEFAULT_OPENROUTER_BASE_URL,
        retry_max_wait_s: float = 2.0,
        breaker_threshold: int = 3,
        breaker_cooldown_s: float = 120,
        min_interval_s: float = 0.25,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = min(float(timeout), MAX_TIMEOUT_S)
        self.cache_seconds = int(cache_seconds)
        self.backend = backend
        self.typesafe_model = typesafe_model
        self.typesafe_base_url = typesafe_base_url.rstrip("/")
        self.openrouter_model = openrouter_model
        self.openrouter_base_url = openrouter_base_url.rstrip("/")
        self.retry_max_wait_s = float(retry_max_wait_s)
        self.breaker_threshold = int(breaker_threshold)
        self.breaker_cooldown_s = float(breaker_cooldown_s)
        self.min_interval_s = float(min_interval_s)
        self._cache: dict[str, tuple[float, dict]] = {}
        # Seams for offline tests (transport stub, clock mock).
        self._urlopen = _urlopen
        self._clock = time.monotonic
        self._sleep = time.sleep
        # Short reason for the last fail-open (None after a success).
        self.last_fail_reason: str | None = None

    def _resolve(self) -> tuple[str | None, str | None]:
        backend = resolve_backend(self.backend)
        if backend == "typesafe":
            return backend, typesafe_api_key()
        if backend == "gateway":
            return backend, api_key()
        if backend == "openrouter":
            return backend, openrouter_api_key()
        return None, None

    def _breaker_open(self, endpoint: str) -> bool:
        state = _BREAKER.get(endpoint)
        return (
            state is not None
            and state[0] >= self.breaker_threshold
            and self._clock() < state[1]
        )

    def _note_ratelimit(self, endpoint: str) -> None:
        state = _BREAKER.get(endpoint) or [0, 0.0]
        state[0] += 1
        if state[0] >= self.breaker_threshold:
            state[1] = self._clock() + self.breaker_cooldown_s
        _BREAKER[endpoint] = state

    def _note_success(self, endpoint: str) -> None:
        _BREAKER.pop(endpoint, None)

    def _pace(self, endpoint: str) -> None:
        """Space outgoing calls by min_interval_s (per process, per endpoint)."""
        if self.min_interval_s <= 0:
            _PACE_LAST[endpoint] = self._clock()
            return
        now = self._clock()
        last = _PACE_LAST.get(endpoint)
        if last is not None and now - last < self.min_interval_s:
            self._sleep(self.min_interval_s - (now - last))
            now = self._clock()
        _PACE_LAST[endpoint] = now

    def _send(self, url: str, data: bytes, headers: dict):
        """One paced POST, returning the parsed JSON body. Raises."""
        self._pace(url)
        req = urllib.request.Request(url, data=data, method="POST", headers=headers)
        with self._urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    def _send_once_more_on_transient(self, url: str, data: bytes, headers: dict):
        try:
            return self._send(url, data, headers)
        except urllib.error.HTTPError as exc:
            if exc.code not in TRANSIENT_UPSTREAM_CODES:
                raise
        self._sleep(TRANSIENT_RETRY_PAUSE_S)
        return self._send(url, data, headers)

    def _post_json(self, url: str, data: bytes, headers: dict):
        """POST with a single rate-limit retry. Returns the body or None."""
        try:
            body = self._send_once_more_on_transient(url, data, headers)
        except urllib.error.HTTPError as exc:
            if exc.code not in RATE_LIMIT_CODES:
                logger.debug(
                    "jev-judge: evaluate failed (%s): %s", type(exc).__name__, exc
                )
                self.last_fail_reason = f"http_{exc.code}"
                return None
            self._note_ratelimit(url)
            wait = retry_after_s(
                exc.headers.get("retry-after") if exc.headers else None,
                time.time(),
            )
            if wait is None or wait > self.retry_max_wait_s:
                self.last_fail_reason = f"http_{exc.code}"
                return None  # fail-open: no (or too long a) wait instructed
            if wait > 0:
                self._sleep(wait)
            try:
                body = self._send(url, data, headers)
            except urllib.error.HTTPError as exc2:
                # Counted once per evaluate (first 429/529 above); no double note.
                logger.debug(
                    "jev-judge: retry failed (%s): %s", type(exc2).__name__, exc2
                )
                self.last_fail_reason = f"http_{exc2.code}"
                return None
            except Exception as exc2:  # timeout, network, parse — fail-open
                logger.debug(
                    "jev-judge: retry failed (%s): %s", type(exc2).__name__, exc2
                )
                self.last_fail_reason = _classify_error(exc2)
                return None
        except Exception as exc:  # timeout, 5xx, network, parse — always fail-open
            logger.debug("jev-judge: evaluate failed (%s): %s", type(exc).__name__, exc)
            self.last_fail_reason = _classify_error(exc)
            return None
        self._note_success(url)
        return body

    def evaluate(self, state, questions: dict) -> dict | None:
        """Return {"answers", "confidence", "cost", "latency_ms", "usage"} or None.

        On None (fail-open) `last_fail_reason` tells why; on success it is None.
        """
        backend, key = self._resolve()
        if backend is None or not key:
            logger.debug("jev-judge: no key for backend; skipping")
            self.last_fail_reason = "no_key"
            return None

        cache_key = hashlib.sha256(
            json.dumps(
                [backend, self.model, self.typesafe_model, state, questions],
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            ).encode()
        ).hexdigest()
        now = time.time()
        hit = self._cache.get(cache_key)
        if hit and hit[0] > now:
            self.last_fail_reason = None
            return hit[1]

        if backend == "typesafe":
            endpoint = f"{self.typesafe_base_url}/v1/systemone"
            payload = json.dumps(
                {
                    "state": state,
                    "model": self.typesafe_model,
                    "questions": to_typesafe_questions(questions),
                },
                ensure_ascii=False,
                default=str,
            ).encode()
            headers = {
                "Authorization": f"Bearer {key}",
                "content-type": "application/json",
            }
        elif backend == "openrouter":
            # OpenRouter alpha Decisions API: same wire question shapes as
            # TypeSafe (noul/choice/score with criteria), different endpoint,
            # model slug goes IN the payload, key is the OpenRouter one.
            endpoint = f"{self.openrouter_base_url}/decisions"
            payload = json.dumps(
                {
                    "model": self.openrouter_model,
                    "state": state,
                    "questions": to_typesafe_questions(questions),
                },
                ensure_ascii=False,
                default=str,
            ).encode()
            headers = {
                "Authorization": f"Bearer {key}",
                "content-type": "application/json",
            }
        else:
            endpoint = f"{self.base_url}/evaluation-model"
            payload = json.dumps(
                {"state": state, "questions": questions},
                ensure_ascii=False,
                default=str,
            ).encode()
            headers = {
                "Authorization": f"Bearer {key}",
                "ai-gateway-protocol-version": PROTOCOL_VERSION,
                "ai-evaluation-model-specification-version": SPEC_VERSION,
                "ai-model-id": self.model,
                "content-type": "application/json",
            }
        if self._breaker_open(endpoint):
            logger.debug("jev-judge: breaker open for %s; skipping", endpoint)
            self.last_fail_reason = "breaker"
            return None
        if len(payload) > MAX_PAYLOAD_BYTES:
            logger.debug(
                "jev-judge: payload %d bytes over cap; failing open", len(payload)
            )
            self.last_fail_reason = "payload_too_large"
            return None
        started = self._clock()
        body = self._post_json(endpoint, payload, headers)
        if body is None:
            if not self.last_fail_reason:
                self.last_fail_reason = "transport"
            return None
        if not isinstance(body, dict) or not isinstance(body.get("answers"), dict):
            logger.debug("jev-judge: malformed provider response; fail-open")
            return None
        raw_answers = body["answers"]

        if backend == "typesafe":
            result = {
                "answers": normalize_typesafe_answers(raw_answers),
                "confidence": typesafe_confidence(raw_answers),
                "cost": None,  # TypeSafe direct reports usage in tokens, no $ cost
                "usage": body.get("usage"),
                "latency_ms": round((self._clock() - started) * 1000),
            }
        elif backend == "openrouter":
            # Same answer shapes as TypeSafe direct (noul/choice/score).
            result = {
                "answers": normalize_typesafe_answers(raw_answers),
                "confidence": typesafe_confidence(raw_answers),
                "cost": None,  # usage reported in tokens; billed via OpenRouter key
                "usage": body.get("usage"),
                "latency_ms": round((self._clock() - started) * 1000),
            }
        else:
            result = {
                "answers": raw_answers,
                "confidence": (
                    body.get("providerMetadata", {}).get("typesafe", {}) or {}
                ).get("confidence", {}),
                "cost": (body.get("providerMetadata", {}).get("gateway", {}) or {}).get(
                    "cost"
                ),
                "usage": body.get("usage"),
                "latency_ms": round((self._clock() - started) * 1000),
            }
        self._cache[cache_key] = (now + self.cache_seconds, result)
        if len(self._cache) > CACHE_MAX_ENTRIES:
            self._cache.pop(next(iter(self._cache)))  # oldest-inserted first
        self.last_fail_reason = None
        return result
