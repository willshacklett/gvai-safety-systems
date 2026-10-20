"""Pure offline transition model. No authentication, authority or execution."""

from __future__ import annotations

from dataclasses import dataclass, replace
import re


@dataclass(frozen=True)
class Context:
    domain: str
    supervisor: str
    environment: str
    tenant: str
    boot: int
    workload_digest: str
    action_digest: str
    effects: tuple[str, ...]
    policy_digest: str
    policy_epoch: int
    grants_epoch: int
    observation_digest: str
    revocation_generation: int = 0
    shutdown_generation: int = 0


@dataclass(frozen=True)
class SyntheticRequest:
    """An unauthenticated test scenario, never a credential."""

    issuer: str
    principal: str
    scope: tuple[str, ...]
    decision: str
    approval_id: str
    challenge: str
    context: Context
    issued_at: int
    not_before: int
    expires_at: int


@dataclass(frozen=True)
class Attempt:
    request: SyntheticRequest
    phase: str


@dataclass(frozen=True)
class ModelState:
    context: Context
    now: int
    consumed: frozenset[tuple[str, str, str]] = frozenset()
    challenges: frozenset[tuple[str, str, int, str]] = frozenset()
    revoked: frozenset[tuple[str, str, str]] = frozenset()
    attempts: tuple[Attempt, ...] = ()
    stopped: bool = False
    uncertain: bool = False


@dataclass(frozen=True)
class ModelResult:
    state: ModelState
    reason: str

    @property
    def allowed(self) -> bool:
        return False

    @property
    def authenticated(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


def _integer(value: object) -> bool:
    return type(value) is int and 0 <= value < 2**63


def _identifier(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None


def _identifiers(value: object, *, empty: bool = False) -> bool:
    return (
        type(value) is tuple and int(not empty) <= len(value) <= 128
        and all(_identifier(item) for item in value)
        and value == tuple(sorted(set(value)))
    )


def _context(value: object) -> bool:
    if type(value) is not Context:
        return False
    identifiers = (
        value.domain, value.supervisor, value.environment, value.tenant,
    )
    digests = (
        value.workload_digest, value.action_digest, value.policy_digest,
        value.observation_digest,
    )
    numbers = (
        value.boot, value.policy_epoch, value.grants_epoch,
        value.revocation_generation, value.shutdown_generation,
    )
    return (
        all(_identifier(item) for item in identifiers)
        and all(type(item) is str and re.fullmatch(r"[0-9a-f]{64}", item) for item in digests)
        and all(_integer(item) for item in numbers)
        and _identifiers(value.effects, empty=True)
    )


def _request(value: object, now: int) -> bool:
    return (
        type(value) is SyntheticRequest and _context(value.context)
        and all(_identifier(item) for item in (
            value.issuer, value.principal, value.decision, value.approval_id, value.challenge,
        ))
        and _identifiers(value.scope)
        and all(_integer(item) for item in (value.issued_at, value.not_before, value.expires_at))
        and value.issued_at <= value.not_before <= now < value.expires_at
        and value.expires_at - value.issued_at <= 60
    )


def _key(request: SyntheticRequest) -> tuple[str, str, str]:
    return request.context.domain, request.issuer, request.approval_id


def _challenge(request: SyntheticRequest) -> tuple[str, str, int, str]:
    context = request.context
    return context.domain, context.supervisor, context.boot, request.challenge


def _cancel(state: ModelState) -> ModelState:
    return replace(state, attempts=tuple(
        replace(item, phase="cancel_required") if item.phase == "modeled_running" else item
        for item in state.attempts
    ))


def transition(
    state: ModelState,
    event: str,
    *,
    now: int,
    request: SyntheticRequest | None = None,
    context: Context | None = None,
) -> ModelResult:
    """Apply one serialized scenario event; never redeem this result for execution.

    Caller-supplied scenarios assume hypothetical authentication for modeling only.
    There is no verifier injection or credential/envelope entry point. Event order
    models a linearization order, not actual locks, persistence or cancellation.
    """
    if type(state) is not ModelState:
        raise ValueError("A model state is required.")
    if not _context(state.context) or not _integer(state.now):
        return ModelResult(_cancel(replace(state, uncertain=True)), "invalid_state")
    if not _integer(now) or now < state.now:
        if event == "shutdown":
            state = replace(state, stopped=True, context=replace(
                state.context, shutdown_generation=state.context.shutdown_generation + 1,
            ))
        return ModelResult(_cancel(replace(state, uncertain=True)), "clock_uncertain")
    state = replace(state, now=now, attempts=tuple(
        replace(item, phase="cancel_required")
        if item.phase == "modeled_running" and now >= item.request.expires_at else item
        for item in state.attempts
    ))
    if event in ("verifier_unavailable", "store_unavailable", "audit_unavailable",
                 "crash", "cancellation_uncertain"):
        return ModelResult(_cancel(replace(state, uncertain=True)), event)
    if event == "restart":
        state = replace(state, context=replace(state.context, boot=state.context.boot + 1),
                        uncertain=True)
        return ModelResult(_cancel(state), "independent_recovery_required")
    if event == "shutdown":
        state = replace(state, stopped=True, context=replace(
            state.context, shutdown_generation=state.context.shutdown_generation + 1,
        ))
        return ModelResult(_cancel(state), "shutdown_latched")
    if event == "revoke":
        if (
            type(request) is not SyntheticRequest or not _context(request.context)
            or not _identifier(request.issuer) or not _identifier(request.approval_id)
        ):
            return ModelResult(_cancel(replace(state, uncertain=True)), "invalid_revocation")
        state = replace(state, revoked=state.revoked | {_key(request)}, context=replace(
            state.context, revocation_generation=state.context.revocation_generation + 1,
        ))
        return ModelResult(_cancel(state), "revocation_modeled")
    if event == "context_change":
        if (
            not _context(context)
            or context.domain != state.context.domain
            or context.supervisor != state.context.supervisor
            or context.environment != state.context.environment
            or context.tenant != state.context.tenant
            or context.boot != state.context.boot
            or context.revocation_generation != state.context.revocation_generation
            or context.shutdown_generation != state.context.shutdown_generation
            or context.policy_epoch <= state.context.policy_epoch
            or context.grants_epoch < state.context.grants_epoch
        ):
            return ModelResult(_cancel(replace(state, uncertain=True)), "invalid_context_change")
        return ModelResult(_cancel(replace(state, context=context)), "context_changed")
    if event == "tick":
        return ModelResult(state, "time_observed")
    if state.stopped or state.uncertain:
        return ModelResult(state, "blocked")
    if event not in ("attempt", "complete") or not _request(request, now):
        return ModelResult(state, "invalid_scenario")
    if request.context != state.context or _key(request) in state.revoked:
        return ModelResult(state, "context_or_revocation_mismatch")
    if event == "attempt":
        if _key(request) in state.consumed or _challenge(request) in state.challenges:
            return ModelResult(state, "replay")
        state = replace(
            state, consumed=state.consumed | {_key(request)},
            challenges=state.challenges | {_challenge(request)},
            attempts=state.attempts + (Attempt(request, "modeled_running"),),
        )
        return ModelResult(state, "consumed_in_model_only")
    for index, item in enumerate(state.attempts):
        if item.request == request and item.phase == "modeled_running":
            attempts = list(state.attempts)
            attempts[index] = replace(item, phase="modeled_complete")
            return ModelResult(replace(state, attempts=tuple(attempts)), "completed_in_model_only")
    return ModelResult(state, "no_running_attempt")
