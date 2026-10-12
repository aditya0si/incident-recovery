"""Provider eligibility, truthful client metadata, and durable paid-call accounting.

This module is the Task 2 runtime gate for the isolated staging tenant
investigation.  It encodes three reviewed rules:

1. **Eligibility is unresolved for Go non-coding runtime use.**  The official
   OpenCode Go documentation (``https://opencode.ai/docs/go/``, section
   *Where can I use it*) describes Go as intended for OpenCode and coding agents
   issuing *similar* coding-agent traffic.  It does **not** explicitly approve a
   non-coding runtime incident-investigation workload.  The safe default is
   therefore :data:`EligibilityStatus.BLOCKED`; a blocked gate prevents **any**
   provider transport call.  Enabling the runtime requires reviewed, scoped
   eligibility evidence supplied through secure orchestrator configuration --
   a user's account authorization is *not* provider permission, and no boolean
   or self-asserted status can turn the gate on.

2. **The client tells the truth.**  The staging adapter sends a fixed, honest
   ``User-Agent: incident-recovery-staging`` and a stable ``x-opencode-session``
   derived from the incident id (same session across every turn and retry, a
   different session for a different incident).  It never impersonates another
   client or spoofs an approved one.

3. **Paid calls are bounded durably.**  A bounded batch admits at most 12
   investigations plus one smoke call, sequential concurrency 1, at most 8
   provider turns per incident, 4096 output tokens and 20000 input characters
   per call.  Attempts (HTTP calls, including retries) are counted separately
   from turns and can never exceed the paid allowance.  Counters live in a
   staging-specific durable JSON ledger, never a module global, so restarting a
   process resumes the same limits instead of resetting them.  Unknown provider
   usage/cost is recorded as *unknown* (``None``), never as zero.

Secrets are never placed in errors, evidence, the ledger, or command lines; the
adapter routes every error string through the shared redaction helpers.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional, Protocol
from uuid import UUID, uuid5

from .models import InvestigationBudgetExhausted, ModelUnavailable, utcnow
from .tools import redact_secrets

# --- truthful client identity -------------------------------------------------

USER_AGENT = "incident-recovery-staging"
GO_PROVIDER = "opencode-go"
GO_RUNTIME_SCOPE = "runtime:incident-investigation"
OFFICIAL_DOC_URL = "https://opencode.ai/docs/go/"
OFFICIAL_DOC_SECTION = "Where can I use it"
OFFICIAL_DOC_FINDING = (
    "Official Go documentation describes Go as designed for OpenCode and coding "
    "agents issuing similar requests; it does not explicitly approve a "
    "non-coding runtime incident-investigation workload, so eligibility for this "
    "runtime application is unresolved."
)

SESSION_NAMESPACE = UUID("6f4c2f7e-2b0a-4e5f-9d2f-0c3a1b6e7d81")
SMOKE_SESSION = "staging-smoke"
SMOKE_KEY = "__smoke__"

DEFAULT_LEDGER_PATH = "staging/.state/provider_budget.json"
ELIGIBILITY_ENV_VAR = "OPENCODE_GO_RUNTIME_ELIGIBILITY"
LEDGER_ENV_VAR = "STAGING_PROVIDER_LEDGER"


def session_for_incident(incident_id) -> str:
    """Return the stable, incident-derived provider session identifier.

    Deterministic across turns and retries within a process and across process
    restarts (it is derived from the incident id), and distinct for distinct
    incidents.  It is never a random process-global identifier.
    """

    return "staging-" + uuid5(SESSION_NAMESPACE, str(incident_id)).hex


# --- eligibility --------------------------------------------------------------


class EligibilityStatus(str, Enum):
    """Closed set of eligibility statuses; only ``verified`` may enable the gate."""

    VERIFIED = "verified"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class EligibilityEvidence:
    """Reviewed, scoped evidence that the runtime workload is provider-eligible."""

    scope: str
    reviewer: str
    reference: str
    reviewed_at: datetime

    def is_scoped(self, scope: str) -> bool:
        return (
            self.scope == scope
            and bool(self.reviewer.strip())
            and bool(self.reference.strip())
        )


@dataclass(frozen=True)
class ProviderEligibility:
    provider: str
    scope: str
    status: str
    source: str
    checked_at: datetime
    evidence: Optional[EligibilityEvidence] = None
    note: str = ""


def default_go_runtime_eligibility(now: Optional[datetime] = None) -> ProviderEligibility:
    """The safe default: blocked, recording the official source and its scope gap."""

    return ProviderEligibility(
        provider=GO_PROVIDER,
        scope=GO_RUNTIME_SCOPE,
        status=EligibilityStatus.BLOCKED.value,
        source=OFFICIAL_DOC_URL,
        checked_at=now or utcnow(),
        evidence=None,
        note=OFFICIAL_DOC_FINDING,
    )


def go_runtime_eligible(eligibility: ProviderEligibility) -> bool:
    """Whether reviewed, scoped eligibility authorizes the Go non-coding runtime.

    Every condition must hold.  A self-asserted ``verified`` status, an
    unsupported provider, a mismatched scope, or missing/blank reviewed evidence
    all fail closed and cannot enable the runtime.
    """

    if eligibility is None:
        return False
    if eligibility.status != EligibilityStatus.VERIFIED.value:
        return False
    if eligibility.provider != GO_PROVIDER:
        return False
    if eligibility.scope != GO_RUNTIME_SCOPE:
        return False
    evidence = eligibility.evidence
    if evidence is None or not evidence.is_scoped(GO_RUNTIME_SCOPE):
        return False
    return True


def eligibility_from_document(document: Mapping[str, Any]) -> ProviderEligibility:
    """Build eligibility from a reviewed config document.

    A malformed or incomplete document yields the safe blocked default rather
    than an enabled gate.
    """

    if not isinstance(document, Mapping):
        return default_go_runtime_eligibility()
    try:
        reviewed_at = datetime.fromisoformat(str(document["reviewed_at"]))
    except (KeyError, ValueError, TypeError):
        return default_go_runtime_eligibility()
    if reviewed_at.tzinfo is None:
        reviewed_at = reviewed_at.replace(tzinfo=timezone.utc)
    evidence = EligibilityEvidence(
        scope=str(document.get("scope", "")),
        reviewer=str(document.get("reviewer", "")),
        reference=str(document.get("reference", "")),
        reviewed_at=reviewed_at,
    )
    return ProviderEligibility(
        provider=str(document.get("provider", "")),
        scope=str(document.get("scope", "")),
        status=str(document.get("status", EligibilityStatus.BLOCKED.value)),
        source=str(document.get("source", OFFICIAL_DOC_URL)),
        checked_at=reviewed_at,
        evidence=evidence,
        note=str(document.get("note", "reviewed scoped eligibility")),
    )


def load_go_runtime_eligibility(env: Optional[Mapping[str, str]] = None) -> ProviderEligibility:
    """Load reviewed eligibility from secure orchestrator configuration.

    The configuration points at a reviewed JSON evidence document.  Absent or
    unreadable configuration is blocked; this never reads credential stores and
    never treats a user's account authorization as provider permission.
    """

    env = dict(os.environ if env is None else env)
    reference = (env.get(ELIGIBILITY_ENV_VAR) or "").strip()
    if not reference:
        return default_go_runtime_eligibility()
    path = Path(reference)
    if not path.is_file():
        return default_go_runtime_eligibility()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default_go_runtime_eligibility()
    return eligibility_from_document(document)


# --- errors -------------------------------------------------------------------


class ProviderPolicyError(Exception):
    """Base class for provider-policy failures."""


class ProviderNotEligible(ModelUnavailable):
    """Runtime use is blocked by unresolved provider eligibility.

    Raised *before* any transport call; never carries credential material.
    """


class ProviderBudgetExceeded(InvestigationBudgetExhausted):
    """A paid provider call was refused by the durable budget ledger."""


class ProviderBillingRefusal(ModelUnavailable):
    """The provider refused on account/billing grounds; execution must stop.

    No alternate model or tier is selected automatically.
    """


# --- limits -------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderLimits:
    max_investigations: int = 12
    max_smoke_calls: int = 1
    max_turns_per_incident: int = 8
    max_attempts_per_incident: int = 8
    max_output_tokens: int = 4096
    max_input_chars: int = 20000
    max_tool_calls: int = 12
    max_seconds: float = 120.0
    concurrency: int = 1


# --- usage --------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderUsage:
    """Actual provider usage, when the provider supplies it.  Unknown is ``None``."""

    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    cost: Optional[float] = None

    @classmethod
    def from_payload(cls, payload: Optional[Mapping[str, Any]]) -> "ProviderUsage":
        if not isinstance(payload, Mapping):
            return cls()

        def _int(name: str) -> Optional[int]:
            value = payload.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return None
            return value

        cost = payload.get("cost")
        if isinstance(cost, bool) or not isinstance(cost, (int, float)) or cost < 0:
            cost = None
        else:
            cost = float(cost)
        return cls(
            input_tokens=_int("prompt_tokens"),
            output_tokens=_int("completion_tokens"),
            total_tokens=_int("total_tokens"),
            cost=cost,
        )


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    reason: str = ""
    remaining: Optional[int] = None


# --- durable ledger -----------------------------------------------------------

LEDGER_SCHEMA = 2


if os.name == "nt":  # pragma: no cover - exercised on Windows CI/host
    import msvcrt

    def _lock_fd(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)

    def _unlock_fd(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:  # already released / closed
            pass

else:  # pragma: no cover - POSIX path
    import fcntl

    def _lock_fd(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock_fd(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextlib.contextmanager
def _interprocess_lock(lock_path: Path) -> Iterator[None]:
    """A cross-process exclusive lock that is released automatically on exit.

    The lock is file-descriptor/owned-process scoped, so a crashed holder never
    orphans it (unlike an ``O_EXCL`` sentinel).  It serializes every mutation of
    the ledger so that two instances -- in one process or across processes --
    can never both read a stale snapshot and then write divergent state.
    """

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT)
    try:
        if os.fstat(fd).st_size == 0:
            # Some platforms cannot lock an empty region; seed one byte.
            os.write(fd, b"\0")
        _lock_fd(fd)
        try:
            yield
        finally:
            _unlock_fd(fd)
    finally:
        os.close(fd)


def _empty_state() -> dict:
    return {
        "schema": LEDGER_SCHEMA,
        "scope": GO_RUNTIME_SCOPE,
        "smoke_calls": 0,
        "admitted": [],
        "active_investigation": None,
        "turns": {},
        "attempts": {},
        "input_chars": {},
        "usage": {},
        "billing_refused": False,
        "billing_reason": None,
        "updated_at": None,
    }


def _normalize_state(data: Any) -> dict:
    state = _empty_state()
    if not isinstance(data, Mapping):
        return state
    state["smoke_calls"] = int(data.get("smoke_calls", 0) or 0)
    admitted = data.get("admitted", [])
    state["admitted"] = [str(item) for item in admitted] if isinstance(admitted, list) else []
    active = data.get("active_investigation")
    state["active_investigation"] = str(active) if active is not None else None
    for key in ("turns", "attempts", "input_chars"):
        raw = data.get(key, {})
        if isinstance(raw, Mapping):
            state[key] = {str(k): int(v) for k, v in raw.items()}
    raw_usage = data.get("usage", {})
    if isinstance(raw_usage, Mapping):
        state["usage"] = {
            str(k): dict(v) for k, v in raw_usage.items() if isinstance(v, Mapping)
        }
    state["billing_refused"] = bool(data.get("billing_refused", False))
    reason = data.get("billing_reason")
    state["billing_reason"] = redact_secrets(str(reason)) if reason is not None else None
    state["updated_at"] = data.get("updated_at")
    return state


def _ledger_key(incident_id: Any) -> str:
    return SMOKE_KEY if incident_id is None else str(incident_id)


def _redact_snapshot(value: Any) -> Any:
    """Scrub secret-shaped text from a snapshot without masking numeric counters.

    The ledger never stores credentials, but a snapshot may include an incident
    key or note, so every string is passed through the shared redaction.  Numeric
    usage counters (which are not secrets) are preserved so they stay inspectable.
    """

    if isinstance(value, Mapping):
        return {redact_secrets(str(k)): _redact_snapshot(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_snapshot(item) for item in value]
    if isinstance(value, str):
        return redact_secrets(value)
    return value


class BudgetLedger(Protocol):
    """Durable paid-call accounting.  Implementations must persist across restart."""

    @property
    def limits(self) -> ProviderLimits: ...

    def snapshot(self) -> dict: ...

    def admit_investigation(self, incident_id: str) -> BudgetDecision: ...

    def release_investigation(self, incident_id: str) -> None: ...

    def admit_smoke(self) -> BudgetDecision: ...

    def is_admitted(self, incident_id: Any) -> bool: ...

    def smoke_admitted(self) -> bool: ...

    def mark_billing_refused(self, reason: Optional[str] = None) -> None: ...

    def billing_refused(self) -> bool: ...

    def begin_turn(self, incident_id: Any) -> BudgetDecision: ...

    def begin_attempt(self, incident_id: Any) -> BudgetDecision: ...

    def record_input(self, incident_id: Any, input_chars: int) -> BudgetDecision: ...

    def record_output(
        self,
        incident_id: Any,
        *,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
        total_tokens: Optional[int] = None,
        cost: Optional[float] = None,
    ) -> BudgetDecision: ...


class JsonBudgetLedger:
    """A staging-scoped, restart-persistent JSON ledger.

    Every mutation runs inside a *cross-process* transaction: an exclusive file
    lock is taken, the state is re-read from disk, the mutation is applied to
    that fresh state, and the result is persisted atomically before the lock is
    released.  There is no per-instance cache, so two instances (in one process
    or in separate processes) can never both act on a stale snapshot.  There are
    no module-global counters, and a crashed holder releases the lock
    automatically rather than orphaning it.
    """

    def __init__(
        self,
        path: os.PathLike | str,
        *,
        limits: Optional[ProviderLimits] = None,
        clock=utcnow,
    ) -> None:
        self._path = Path(path)
        self._limits = limits or ProviderLimits()
        self._clock = clock
        self._lock = threading.RLock()
        self._lock_path = self._path.with_name(self._path.name + ".lock")
        # Fail closed on an unreadable existing ledger at construction time.
        with self._locked_read():
            pass

    @property
    def limits(self) -> ProviderLimits:
        return self._limits

    @property
    def path(self) -> Path:
        return self._path

    @property
    def lock_path(self) -> Path:
        return self._lock_path

    # -- transaction primitives --

    @contextlib.contextmanager
    def _locked_read(self) -> Iterator[dict]:
        with self._lock:
            with _interprocess_lock(self._lock_path):
                yield self._read()

    @contextlib.contextmanager
    def _locked_write(self) -> Iterator[dict]:
        with self._lock:
            with _interprocess_lock(self._lock_path):
                state = self._read()
                yield state
                self._write(state)

    def _read(self) -> dict:
        if not self._path.is_file():
            return _empty_state()
        try:
            return _normalize_state(json.loads(self._path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            raise ProviderPolicyError("provider_budget_ledger_unreadable") from exc

    def _write(self, state: dict) -> None:
        state["updated_at"] = self._clock().isoformat()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(self._path.name + ".tmp")
        tmp.write_text(
            json.dumps(state, separators=(",", ":"), sort_keys=True), encoding="utf-8"
        )
        os.replace(tmp, self._path)

    def snapshot(self) -> dict:
        with self._locked_read() as state:
            return _redact_snapshot(copy.deepcopy(state))

    # -- admissions --

    def admit_investigation(self, incident_id: str) -> BudgetDecision:
        key = str(incident_id)
        with self._locked_write() as state:
            if state["active_investigation"] not in (None, key):
                return BudgetDecision(False, "concurrency_limit")
            if key in state["admitted"]:
                state["active_investigation"] = key
                return BudgetDecision(True, "already_admitted")
            if len(state["admitted"]) >= self._limits.max_investigations:
                return BudgetDecision(
                    False, "batch_limit",
                    self._limits.max_investigations - len(state["admitted"]),
                )
            state["admitted"].append(key)
            state["active_investigation"] = key
            remaining = self._limits.max_investigations - len(state["admitted"])
            return BudgetDecision(True, "admitted", remaining)

    def release_investigation(self, incident_id: str) -> None:
        key = str(incident_id)
        with self._locked_write() as state:
            if state["active_investigation"] == key:
                state["active_investigation"] = None

    def admit_smoke(self) -> BudgetDecision:
        with self._locked_write() as state:
            if state["active_investigation"] is not None:
                return BudgetDecision(False, "concurrency_limit")
            if state["smoke_calls"] >= self._limits.max_smoke_calls:
                return BudgetDecision(False, "smoke_limit", 0)
            state["smoke_calls"] += 1
            remaining = self._limits.max_smoke_calls - state["smoke_calls"]
            return BudgetDecision(True, "smoke_admitted", remaining)

    def is_admitted(self, incident_id: Any) -> bool:
        key = str(incident_id)
        with self._locked_read() as state:
            return state["active_investigation"] == key and key in state["admitted"]

    def smoke_admitted(self) -> bool:
        with self._locked_read() as state:
            return int(state["smoke_calls"]) >= 1

    def mark_billing_refused(self, reason: Optional[str] = None) -> None:
        with self._locked_write() as state:
            state["billing_refused"] = True
            if reason is not None:
                state["billing_reason"] = redact_secrets(str(reason))

    def billing_refused(self) -> bool:
        with self._locked_read() as state:
            return bool(state["billing_refused"])

    def billing_reason(self) -> Optional[str]:
        with self._locked_read() as state:
            return state.get("billing_reason")

    # -- per-turn / per-attempt --

    def begin_turn(self, incident_id: Any) -> BudgetDecision:
        key = _ledger_key(incident_id)
        with self._locked_write() as state:
            used = int(state["turns"].get(key, 0))
            if used >= self._limits.max_turns_per_incident:
                return BudgetDecision(False, "turn_limit", 0)
            state["turns"][key] = used + 1
            return BudgetDecision(True, "turn", self._limits.max_turns_per_incident - used - 1)

    def begin_attempt(self, incident_id: Any) -> BudgetDecision:
        key = _ledger_key(incident_id)
        with self._locked_write() as state:
            used = int(state["attempts"].get(key, 0))
            if used >= self._limits.max_attempts_per_incident:
                return BudgetDecision(False, "attempt_limit", 0)
            state["attempts"][key] = used + 1
            return BudgetDecision(
                True, "attempt", self._limits.max_attempts_per_incident - used - 1
            )

    # -- usage --

    def record_input(self, incident_id: Any, input_chars: int) -> BudgetDecision:
        key = _ledger_key(incident_id)
        if isinstance(input_chars, bool) or not isinstance(input_chars, int) or input_chars < 0:
            return BudgetDecision(False, "invalid_input_chars")
        if input_chars > self._limits.max_input_chars:
            return BudgetDecision(False, "input_limit", 0)
        with self._locked_write() as state:
            state["input_chars"][key] = int(state["input_chars"].get(key, 0)) + input_chars
        return BudgetDecision(True, "input_recorded")

    def record_output(
        self,
        incident_id: Any,
        *,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
        total_tokens: Optional[int] = None,
        cost: Optional[float] = None,
    ) -> BudgetDecision:
        key = _ledger_key(incident_id)

        def _valid(value):
            return isinstance(value, int) and not isinstance(value, bool) and value >= 0

        if output_tokens is not None and _valid(output_tokens) and (
            output_tokens > self._limits.max_output_tokens
        ):
            return BudgetDecision(False, "output_limit", 0)

        # Values the provider did not supply -- or supplied as invalid -- are
        # recorded as *unknown* (``None``), never silently coerced to zero.
        if not _valid(input_tokens):
            input_tokens = None
        if not _valid(output_tokens):
            output_tokens = None
        if not _valid(total_tokens):
            total_tokens = None
        if not (isinstance(cost, (int, float)) and not isinstance(cost, bool) and cost >= 0):
            cost = None

        with self._locked_write() as state:
            entry = state["usage"].setdefault(
                key,
                {"input_tokens": None, "output_tokens": None, "total_tokens": None, "cost": None},
            )
            if input_tokens is not None:
                entry["input_tokens"] = (entry["input_tokens"] or 0) + input_tokens
            if output_tokens is not None:
                entry["output_tokens"] = (entry["output_tokens"] or 0) + output_tokens
            if total_tokens is not None:
                entry["total_tokens"] = (entry["total_tokens"] or 0) + total_tokens
            if cost is not None:
                entry["cost"] = (entry["cost"] or 0.0) + float(cost)
        return BudgetDecision(True, "usage_recorded")


def load_budget_ledger(
    env: Optional[Mapping[str, str]] = None,
    *,
    default_path: Optional[os.PathLike | str] = None,
    limits: Optional[ProviderLimits] = None,
) -> JsonBudgetLedger:
    env = dict(os.environ if env is None else env)
    raw = (env.get(LEDGER_ENV_VAR) or "").strip()
    path = raw or default_path or DEFAULT_LEDGER_PATH
    return JsonBudgetLedger(path, limits=limits)


# --- policy -------------------------------------------------------------------


class StagingProviderPolicy:
    """Bundles the runtime eligibility gate with truthful identity and accounting."""

    def __init__(
        self,
        *,
        eligibility: ProviderEligibility,
        ledger: BudgetLedger,
        clock=utcnow,
    ) -> None:
        self._eligibility = eligibility
        self._ledger = ledger
        self._clock = clock
        self._call_lock: Optional[asyncio.Lock] = None

    @property
    def eligibility(self) -> ProviderEligibility:
        return self._eligibility

    @property
    def limits(self) -> ProviderLimits:
        return self._ledger.limits

    @property
    def user_agent(self) -> str:
        return USER_AGENT

    def require_runtime_eligible(self) -> None:
        if not go_runtime_eligible(self._eligibility):
            raise ProviderNotEligible(self._eligibility.note or "provider_runtime_not_eligible")

    def session_for(self, incident_id: Any) -> str:
        if incident_id is None:
            return SMOKE_SESSION
        return session_for_incident(incident_id)

    def call_lock(self) -> asyncio.Lock:
        """A single in-process lock enforcing concurrency 1 across provider calls."""

        if self._call_lock is None:
            self._call_lock = asyncio.Lock()
        return self._call_lock

    def admit_investigation(self, incident_id: Any) -> BudgetDecision:
        self.require_runtime_eligible()
        return self._ledger.admit_investigation(str(incident_id))

    def release_investigation(self, incident_id: Any) -> None:
        self._ledger.release_investigation(str(incident_id))

    def admit_smoke(self) -> BudgetDecision:
        self.require_runtime_eligible()
        return self._ledger.admit_smoke()

    def check_investigation_admission(self, incident_id: Any) -> BudgetDecision:
        """Refuse any provider turn for an incident that is not currently admitted."""

        self.require_runtime_eligible()
        if self._ledger.is_admitted(str(incident_id)):
            return BudgetDecision(True, "admitted")
        return BudgetDecision(False, "investigation_not_admitted")

    def check_smoke_admission(self) -> BudgetDecision:
        """Refuse the smoke transport unless a smoke call was authoritatively admitted."""

        self.require_runtime_eligible()
        if self._ledger.smoke_admitted():
            return BudgetDecision(True, "smoke_admitted")
        return BudgetDecision(False, "smoke_not_admitted")

    def mark_billing_refused(self, reason: Optional[str] = None) -> None:
        self._ledger.mark_billing_refused(reason)

    def billing_refused(self) -> bool:
        return self._ledger.billing_refused()

    def begin_turn(self, incident_id: Any) -> BudgetDecision:
        return self._ledger.begin_turn(incident_id)

    def begin_attempt(self, incident_id: Any) -> BudgetDecision:
        return self._ledger.begin_attempt(incident_id)

    def record_input(self, incident_id: Any, input_chars: int) -> BudgetDecision:
        return self._ledger.record_input(incident_id, input_chars)

    def record_output(
        self,
        incident_id: Any,
        *,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
        total_tokens: Optional[int] = None,
        cost: Optional[float] = None,
    ) -> BudgetDecision:
        return self._ledger.record_output(
            incident_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            cost=cost,
        )

    def snapshot(self) -> dict:
        return self._ledger.snapshot()
