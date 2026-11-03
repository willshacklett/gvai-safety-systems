"""Deny-only offline admission diagnostics; not an execution authorization API."""

from __future__ import annotations

from dataclasses import dataclass
import re


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_STATES = frozenset({"stable", "warning", "critical", "irrecoverable"})
_MAX_OBSERVATION_AGE = 60


@dataclass(frozen=True)
class AdmissionDenial:
    reasons: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _revision(value: object) -> bool:
    return type(value) is str and _REVISION.fullmatch(value) is not None


def _fields(value: object, expected: set[str]) -> bool:
    return (
        type(value) is dict
        and all(type(key) is str for key in value)
        and set(value) == expected
    )


def _identifiers(value: object) -> bool:
    return (
        type(value) is list
        and 0 < len(value) <= 128
        and all(_identifier(item) for item in value)
        and len(set(value)) == len(value)
    )


class OfflineAuthorityAdmission:
    """Validate claimed prerequisites, but always deny: authentication is absent.

    There is no verifier injection, registry adapter, gate bypass, execution,
    shutdown operation, or production ALLOW path. Trusted callers would need to
    supply time and workload context; matching claims do not authenticate them.
    """

    def evaluate(
        self,
        *,
        target_id: object = None,
        revision: object = None,
        now: object = None,
        control_status: object = None,
        observation: object = None,
        enforcement: object = None,
        approval: object = None,
        registry_evidence: object = None,
    ) -> AdmissionDenial:
        reasons = ["non_operational_contract", "independent_approval_unavailable"]
        try:
            if not _identifier(target_id) or not _revision(revision):
                reasons.append("invalid_workload_context")
            if type(now) is not int or now < 0:
                reasons.append("invalid_trusted_time")
            if type(control_status) is not str or control_status != "verified":
                reasons.append("control_not_explicitly_verified")
            if registry_evidence is not None:
                reasons.append("registry_evidence_is_not_authority")

            if not _fields(
                observation,
                {"target_id", "revision", "source_id", "status", "halted",
                 "observed_at", "expires_at"},
            ):
                reasons.append("missing_or_malformed_observation")
            else:
                status = observation["status"]
                if type(status) is not str or status not in _STATES:
                    reasons.append("unknown_sentinel_state")
                elif status != "stable":
                    reasons.append("safety_state_not_admissible")
                if (
                    type(observation["halted"]) is not bool
                    or observation["halted"] is True
                    or (status == "irrecoverable" and observation["halted"] is not True)
                ):
                    reasons.append("halted_or_contradictory_observation")
                if (
                    observation["target_id"] != target_id
                    or observation["revision"] != revision
                    or not _identifier(observation["source_id"])
                ):
                    reasons.append("observation_context_mismatch")
                if not self._fresh(
                    observation["observed_at"], observation["expires_at"], now,
                    _MAX_OBSERVATION_AGE,
                ):
                    reasons.append("stale_or_invalid_observation_time")

            if not _fields(
                enforcement, {"invariant_ids", "effect_requirements", "independent_shutdown"},
            ):
                reasons.append("missing_or_malformed_enforcement")
            else:
                if not _identifiers(enforcement["invariant_ids"]):
                    reasons.append("missing_required_invariants")
                if not _identifiers(enforcement["effect_requirements"]):
                    reasons.append("missing_effect_enforcement")
                if enforcement["independent_shutdown"] is not True:
                    reasons.append("independent_shutdown_not_established")

            if not _fields(
                approval,
                {"issuer_id", "target_id", "revision", "issued_at", "expires_at", "signature"},
            ):
                reasons.append("missing_or_malformed_external_approval")
            elif (
                not _identifier(approval["issuer_id"])
                or approval["target_id"] != target_id
                or approval["revision"] != revision
                or type(approval["signature"]) is not str
                or not 1 <= len(approval["signature"]) <= 4096
                or not self._fresh(approval["issued_at"], approval["expires_at"], now, 300)
            ):
                reasons.append("invalid_external_approval_claim")
            elif not self._verify_approval(approval):
                reasons.append("external_approval_not_authenticated")
        except Exception:
            # Diagnostic errors never remove the unconditional denial blockers.
            reasons.append("admission_check_failed_closed")
        return AdmissionDenial(tuple(reasons))

    @staticmethod
    def _fresh(issued: object, expires: object, now: object, max_age: int) -> bool:
        return (
            type(issued) is int and type(expires) is int and type(now) is int
            and 0 <= issued <= now < expires
            and now - issued <= max_age
            and expires - issued <= max_age
        )

    @staticmethod
    def _verify_approval(approval: dict) -> bool:
        """No independent approval verifier exists; syntax is not authentication."""
        return False
