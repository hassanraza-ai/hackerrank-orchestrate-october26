"""Map a record's category and observed state to audit steps."""

from __future__ import annotations

from dataclasses import dataclass

# Operation order is the order required inside each phase.
FINDING_ORDER = (
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
)
REMEDIATION_ORDER = (
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
)
VERIFICATION_ORDER = (
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
)

DELETE_CATEGORIES = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "SUPPORT_ATTACHMENT",
    "USER_EXPORT",
    "MARKETING_PROFILE",
    "PRODUCT_TELEMETRY",
}
ANONYMIZE_CATEGORIES = {"ANALYTICS_PROFILE"}
REDACT_CATEGORIES = {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}
RETAIN_CATEGORIES = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}


@dataclass(frozen=True)
class ResourceState:
    system_id: str
    resource_id: str
    category: str
    present: bool
    direct_pii: bool
    linked_subject: bool
    flow_enabled: bool | None
    restore_allowed: bool | None
    evidence_id: str
    observed_at: str

    def sort_key(self) -> tuple[str, str]:
        return (self.system_id, self.resource_id)


@dataclass(frozen=True)
class Step:
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str

    def as_dict(self, step_no: int) -> dict[str, object]:
        return {
            "step_no": step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


def _step(phase: str, resource: ResourceState, operation: str, state: str, evidence_id: str) -> Step:
    return Step(
        phase=phase,
        system_id=resource.system_id,
        resource_id=resource.resource_id,
        operation=operation,
        state=state,
        evidence_id=evidence_id,
    )


def steps_for_resource(resource: ResourceState) -> list[Step]:
    """Return the finding, remediation, and verification steps for one resource.

    Evidence is attached only to findings here. Callers clear evidence on
    future verification when the case is incomplete, and keep it when the
    case is already complete.
    """
    category = resource.category
    proof = resource.evidence_id
    steps: list[Step] = []

    if category in DELETE_CATEGORIES:
        if resource.present:
            steps.append(_step("FINDING", resource, "REPORT_REMAINING_RECORD", "PRESENT", proof))
            steps.append(_step("REMEDIATION", resource, "DELETE_RECORD", "ABSENT", ""))
            steps.append(_step("VERIFICATION", resource, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
        else:
            steps.append(_step("VERIFICATION", resource, "VERIFY_RECORD_ABSENT", "ABSENT", proof))
        return steps

    if category in ANONYMIZE_CATEGORIES:
        if not resource.present:
            steps.append(_step("VERIFICATION", resource, "VERIFY_RECORD_ABSENT", "ABSENT", proof))
            return steps
        attributable = resource.direct_pii or resource.linked_subject
        if attributable:
            steps.append(_step("FINDING", resource, "REPORT_EXPOSED_PII", "PRESENT", proof))
            steps.append(_step("REMEDIATION", resource, "ANONYMIZE_RECORD", "ANONYMIZED", ""))
            steps.append(_step("VERIFICATION", resource, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
        else:
            steps.append(_step("VERIFICATION", resource, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", proof))
        return steps

    if category in REDACT_CATEGORIES:
        if not resource.present:
            return steps
        if resource.direct_pii:
            steps.append(_step("FINDING", resource, "REPORT_EXPOSED_PII", "PRESENT", proof))
            steps.append(_step("REMEDIATION", resource, "REDACT_RECORD", "REDACTED", ""))
            steps.append(_step("VERIFICATION", resource, "VERIFY_RECORD_REDACTED", "REDACTED", ""))
        else:
            steps.append(_step("VERIFICATION", resource, "VERIFY_RECORD_REDACTED", "REDACTED", proof))
        return steps

    if category in RETAIN_CATEGORIES:
        if resource.present:
            steps.append(_step("VERIFICATION", resource, "VERIFY_RECORD_PRESENT", "PRESENT", proof))
        return steps

    if category == "BACKUP_ARCHIVE":
        if resource.restore_allowed:
            steps.append(_step("FINDING", resource, "REPORT_RESTORE_RISK", "ACTIVE", proof))
            steps.append(_step("REMEDIATION", resource, "BLOCK_RESTORE", "BLOCKED", ""))
            steps.append(_step("VERIFICATION", resource, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
        elif resource.restore_allowed is False:
            steps.append(_step("VERIFICATION", resource, "VERIFY_RESTORE_BLOCKED", "BLOCKED", proof))
        return steps

    if category == "DATA_FLOW":
        if resource.flow_enabled:
            steps.append(_step("FINDING", resource, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", proof))
            steps.append(_step("REMEDIATION", resource, "DISABLE_DATA_FLOW", "DISABLED", ""))
            steps.append(_step("VERIFICATION", resource, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
        elif resource.flow_enabled is False:
            steps.append(_step("VERIFICATION", resource, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", proof))
        return steps

    return steps


def order_steps(steps: list[Step]) -> list[Step]:
    phase_rank = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    op_rank = {name: index for index, name in enumerate(FINDING_ORDER + REMEDIATION_ORDER + VERIFICATION_ORDER)}

    def key(step: Step) -> tuple:
        return (
            phase_rank[step.phase],
            op_rank[step.operation],
            step.system_id,
            step.resource_id,
        )

    return sorted(steps, key=key)
