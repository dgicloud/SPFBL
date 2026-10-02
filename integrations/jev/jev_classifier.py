"""Metadata-only, advisory Jev classifier for the HAD AntiSpam gateway.

This module is intentionally separate from the SPFBL core and never changes
the baseline mail decision. It sends only enumerated technical signals: no
email addresses, IPs, domains, subject, headers, or message body.
"""
from __future__ import annotations

import json
import math
import os
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions"
DEFAULT_MODEL = "typesafe/jev-1.13"


class AuthResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    UNKNOWN = "unknown"


class SPFBLResult(str, Enum):
    PASS = "pass"
    WHITE = "white"
    ACCEPT = "accept"
    FLAG = "flag"
    GREYLIST = "greylist"
    HOLD = "hold"
    BLOCKED = "blocked"
    FAIL = "fail"
    UNKNOWN = "unknown"


class RspamdBucket(str, Enum):
    BELOW_THRESHOLD = "below_threshold"
    BORDERLINE = "borderline"
    ABOVE_THRESHOLD = "above_threshold"
    UNKNOWN = "unknown"


class Alignment(str, Enum):
    ALIGNED = "aligned"
    MISALIGNED = "misaligned"
    NONE = "none"
    UNKNOWN = "unknown"


class BaselineDecision(str, Enum):
    HAM = "ham"
    SPAM = "spam"
    REVIEW = "review"
    UNKNOWN = "unknown"


class JevChoice(str, Enum):
    HAM = "ham"
    SPAM = "spam"
    REVIEW = "review"


class AdviceStatus(str, Enum):
    SKIPPED_NO_CONFIDENCE = "skipped_no_confidence"
    SKIPPED_CONFIDENT = "skipped_confident"
    NOT_CONFIGURED = "not_configured"
    BUSY = "busy"
    UNAVAILABLE = "unavailable"
    ADVICE = "advice"


class JevError(RuntimeError):
    """Safe provider error. It deliberately excludes response/request bodies."""


class JevBusy(JevError):
    """The configured outbound concurrency limit has been reached."""


class Transport(Protocol):
    def post(self, url: str, headers: Mapping[str, str], body: bytes,
             timeout: float) -> bytes:
        """Perform one bounded HTTPS request and return the response bytes."""


@dataclass(frozen=True)
class TechnicalMetadata:
    """Allowlisted, low-cardinality features; no user or message identifiers."""

    spf: AuthResult = AuthResult.UNKNOWN
    dkim: AuthResult = AuthResult.UNKNOWN
    dmarc: AuthResult = AuthResult.UNKNOWN
    spfbl: SPFBLResult = SPFBLResult.UNKNOWN
    rspamd: RspamdBucket = RspamdBucket.UNKNOWN
    dmarc_alignment: Alignment = Alignment.UNKNOWN
    reverse_dns_valid: Optional[bool] = None
    authenticated_smtp: Optional[bool] = None
    smtp_tls: Optional[bool] = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TechnicalMetadata":
        if not isinstance(value, Mapping):
            raise ValueError("metadata must be an object")
        allowed = {
            "spf", "dkim", "dmarc", "spfbl", "rspamd", "dmarc_alignment",
            "reverse_dns_valid", "authenticated_smtp", "smtp_tls",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError("metadata contains unsupported fields")

        enums = {
            "spf": AuthResult,
            "dkim": AuthResult,
            "dmarc": AuthResult,
            "spfbl": SPFBLResult,
            "rspamd": RspamdBucket,
            "dmarc_alignment": Alignment,
        }
        parsed: Dict[str, Any] = {}
        for name, enum_type in enums.items():
            raw = value.get(name, "unknown")
            if not isinstance(raw, str):
                raise ValueError("metadata enum values must be strings")
            try:
                parsed[name] = enum_type(raw)
            except ValueError:
                raise ValueError("metadata contains an unsupported enum value")
        for name in ("reverse_dns_valid", "authenticated_smtp", "smtp_tls"):
            raw = value.get(name)
            if raw is not None and not isinstance(raw, bool):
                raise ValueError("metadata boolean values must be true, false, or null")
            parsed[name] = raw
        return cls(**parsed)

    def as_state(self) -> Dict[str, Any]:
        return {
            "spf": self.spf.value,
            "dkim": self.dkim.value,
            "dmarc": self.dmarc.value,
            "spfbl": self.spfbl.value,
            "rspamd": self.rspamd.value,
            "dmarc_alignment": self.dmarc_alignment.value,
            "reverse_dns_valid": self.reverse_dns_valid,
            "authenticated_smtp": self.authenticated_smtp,
            "smtp_tls": self.smtp_tls,
        }


@dataclass(frozen=True)
class JevAdvice:
    choice: JevChoice
    confidence: float
    probabilities: Mapping[str, float]
    model: str
    request_id: Optional[str]
    input_tokens: Optional[int]
    output_tokens: Optional[int]
    cost: Optional[float]


@dataclass(frozen=True)
class AdviceResult:
    status: AdviceStatus
    baseline: BaselineDecision
    local_confidence: Optional[float]
    advice: Optional[JevAdvice] = None

    @property
    def effective_decision(self) -> BaselineDecision:
        """Always return the existing SPFBL/Exim decision during shadow mode."""
        return self.baseline


def _number(value: Any, name: str, minimum: float = 0.0,
            maximum: Optional[float] = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JevError("invalid provider response: " + name)
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise JevError("invalid provider response: " + name)
    if maximum is not None and result > maximum:
        raise JevError("invalid provider response: " + name)
    return result


class UrllibTransport:
    class _NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, request, response, code, message, headers, new_url):
            return None

    def post(self, url: str, headers: Mapping[str, str], body: bytes,
             timeout: float) -> bytes:
        request = Request(url, data=body, headers=dict(headers), method="POST")
        opener = build_opener(self._NoRedirect())
        try:
            with opener.open(request, timeout=timeout) as response:
                if response.status != 200:
                    raise JevError("provider returned HTTP status {0}".format(response.status))
                payload = response.read(16385)
                if len(payload) > 16384:
                    raise JevError("provider response exceeded the size limit")
                return payload
        except HTTPError as exc:
            exc.close()
            raise JevError("provider returned HTTP status {0}".format(exc.code))
        except URLError:
            raise JevError("provider connection failed")
        except OSError as exc:
            if isinstance(exc, TimeoutError):
                raise JevError("provider request timed out")
            raise JevError("provider connection failed")


class JevClient:
    """One-request Jev client with strict payload and concurrency bounds."""

    def __init__(self, api_key: str, timeout_seconds: float,
                 max_in_flight: int = 8, model: str = DEFAULT_MODEL,
                 transport: Optional[Transport] = None) -> None:
        if not api_key or "\n" in api_key or "\r" in api_key:
            raise ValueError("a valid API key is required")
        if timeout_seconds <= 0 or not math.isfinite(timeout_seconds):
            raise ValueError("timeout_seconds must be a positive finite number")
        if max_in_flight < 1:
            raise ValueError("max_in_flight must be at least one")
        if not model or any(char.isspace() for char in model):
            raise ValueError("invalid model id")
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._model = model
        self._slots = threading.BoundedSemaphore(max_in_flight)
        self._transport = transport or UrllibTransport()

    @classmethod
    def from_environment(cls, timeout_seconds: float = 1.5,
                         max_in_flight: int = 8) -> "JevClient":
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY is not configured")
        model = os.environ.get("JEV_MODEL", DEFAULT_MODEL)
        return cls(api_key, timeout_seconds, max_in_flight, model)

    def classify(self, metadata: TechnicalMetadata,
                 baseline: BaselineDecision,
                 local_confidence: float) -> JevAdvice:
        local_confidence = _number(local_confidence, "local_confidence", maximum=1.0)
        if not self._slots.acquire(blocking=False):
            raise JevBusy("Jev concurrency limit reached")
        try:
            payload = {
                "model": self._model,
                "state": {
                    "baseline_decision": baseline.value,
                    "local_confidence": local_confidence,
                    "technical_metadata": metadata.as_state(),
                },
                "questions": {
                    "classification": {
                        "type": "choice",
                        "instructions": "Classify the message using only the supplied technical email signals.",
                        "criteria": {
                            "ham": "The supplied technical signals indicate a legitimate message.",
                            "spam": "The supplied technical signals indicate unsolicited or harmful mail.",
                            "review": "The available technical signals are insufficient or contradictory.",
                        },
                    }
                },
            }
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            raw = self._transport.post(
                DECISIONS_URL,
                {"Authorization": "Bearer " + self._api_key,
                 "Content-Type": "application/json"},
                body,
                self._timeout_seconds,
            )
            return self._parse_response(raw)
        finally:
            self._slots.release()

    def _parse_response(self, raw: bytes) -> JevAdvice:
        try:
            document = json.loads(raw.decode("utf-8"))
            if not isinstance(document, dict):
                raise JevError("invalid provider response")
            answers = document.get("answers")
            usage = document.get("usage") or {}
            if not isinstance(answers, dict) or not isinstance(usage, dict):
                raise JevError("invalid provider response")
            answer = answers["classification"]
            if not isinstance(answer, dict):
                raise JevError("invalid provider response")
            choice = JevChoice(answer["choice"])
            confidence = _number(answer["confidence"], "confidence", maximum=1.0)
            raw_probabilities = answer["probabilities"]
            if not isinstance(raw_probabilities, dict):
                raise JevError("invalid provider response: probabilities")
            probabilities: Dict[str, float] = {}
            for option in JevChoice:
                probabilities[option.value] = _number(
                    raw_probabilities[option.value], "probability", maximum=1.0)
            input_tokens = usage.get("input_tokens")
            output_tokens = usage.get("output_tokens")
            if input_tokens is not None and (isinstance(input_tokens, bool) or not isinstance(input_tokens, int) or input_tokens < 0):
                raise JevError("invalid provider response: input_tokens")
            if output_tokens is not None and (isinstance(output_tokens, bool) or not isinstance(output_tokens, int) or output_tokens < 0):
                raise JevError("invalid provider response: output_tokens")
            raw_cost = usage.get("cost")
            cost = None if raw_cost is None else _number(raw_cost, "cost")
            model = document.get("model", self._model)
            if not isinstance(model, str) or not model:
                raise JevError("invalid provider response: model")
            request_id = document.get("id")
            if request_id is not None and not isinstance(request_id, str):
                raise JevError("invalid provider response: id")
            return JevAdvice(choice, confidence, probabilities, model, request_id,
                             input_tokens, output_tokens, cost)
        except JevError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            raise JevError("invalid provider response")


def advise_if_uncertain(
    baseline: BaselineDecision,
    metadata: TechnicalMetadata,
    local_confidence: Optional[float],
    confidence_threshold: float,
    client: Optional[JevClient],
) -> AdviceResult:
    """Call Jev below a configured local-confidence threshold; never enforce it."""
    threshold = _number(confidence_threshold, "confidence_threshold", maximum=1.0)
    if local_confidence is None:
        return AdviceResult(AdviceStatus.SKIPPED_NO_CONFIDENCE, baseline, None)
    confidence = _number(local_confidence, "local_confidence", maximum=1.0)
    if confidence >= threshold:
        return AdviceResult(AdviceStatus.SKIPPED_CONFIDENT, baseline, confidence)
    if client is None:
        return AdviceResult(AdviceStatus.NOT_CONFIGURED, baseline, confidence)
    try:
        advice = client.classify(metadata, baseline, confidence)
    except JevBusy:
        return AdviceResult(AdviceStatus.BUSY, baseline, confidence)
    except JevError:
        return AdviceResult(AdviceStatus.UNAVAILABLE, baseline, confidence)
    return AdviceResult(AdviceStatus.ADVICE, baseline, confidence, advice)
