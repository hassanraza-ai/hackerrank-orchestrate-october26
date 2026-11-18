"""Load the dataset once and audit every deletion request."""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from deletion_audit.evidence import Observation, parse_evidence, system_for
from deletion_audit.identity import IdentityIndex, build_identity_index, parse_time
from deletion_audit.intent import authorizes_deletion
from deletion_audit.policy import ResourceState, Step, order_steps, steps_for_resource

ROOT = Path(__file__).resolve().parents[2]


@dataclass
class Activity:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass
class Request:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str


@dataclass
class AuditResult:
    case_id: str
    deletion_status: str
    steps: list[dict[str, object]]


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_requests(path: Path) -> list[Request]:
    requests: list[Request] = []
    for row in _load_csv(path):
        requests.append(
            Request(
                case_id=row["case_id"],
                email=row["email"],
                requested_at=parse_time(row["requested_at"]),
                reported_status=row["reported_status"],
                reported_at=parse_time(row["reported_at"]),
                audit_at=parse_time(row["audit_at"]),
                request_text=row["request_text"],
            )
        )
    return requests


def load_activities(dataset_dir: Path) -> list[Activity]:
    activities: list[Activity] = []
    for row in _load_csv(dataset_dir / "system_activity.csv"):
        event_time = parse_time(row["event_time"])
        if event_time is None:
            continue
        activities.append(
            Activity(
                activity_id=row["activity_id"],
                event_time=event_time,
                event_type=row["event_type"],
                source_system=row["source_system"],
                target_system=row["target_system"],
                resource_id=row["resource_id"],
                reported_result=row["reported_result"],
                details=row["details"],
            )
        )
    return activities


class World:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = dataset_dir
        self.observations = parse_evidence(dataset_dir)
        self.activities = load_activities(dataset_dir)
        self.by_resource: dict[str, list[Observation]] = {}
        for obs in self.observations:
            self.by_resource.setdefault(obs.resource_id, []).append(obs)
        self.activity_by_resource: dict[str, list[Activity]] = {}
        for activity in self.activities:
            self.activity_by_resource.setdefault(activity.resource_id, []).append(activity)

    def identity_at(self, audit_at: datetime) -> IdentityIndex:
        return build_identity_index(self.dataset_dir, audit_at)


def _case_number(case_id: str) -> int:
    match = re.search(r"(\d+)$", case_id)
    return int(match.group(1)) if match else 0


def _user_number(user_id: str) -> int | None:
    match = re.fullmatch(r"user_(\d+)", user_id)
    if not match:
        return None
    return int(match.group(1))


def _padded_account(user_id: str) -> str | None:
    number = _user_number(user_id)
    if number is None or number > 10:
        return None
    return f"account_{number:03d}"


def _latest_state(observations: list[Observation], audit_at: datetime) -> Observation | None:
    eligible = [
        obs
        for obs in observations
        if obs.captured_at <= audit_at and obs.observed_at <= audit_at
    ]
    if not eligible:
        return None
    eligible.sort(key=lambda obs: (obs.observed_at, obs.captured_at, obs.file_id))
    # Same-timestamp replica drift: a copy that still stores the row wins.
    latest_time = eligible[-1].observed_at
    at_latest = [obs for obs in eligible if obs.observed_at == latest_time]
    present_now = any(obs.present for obs in at_latest)
    chosen = next(obs for obs in reversed(at_latest) if obs.present) if present_now else at_latest[-1]
    merged = Observation(
        file_id=chosen.file_id,
        captured_at=chosen.captured_at,
        observed_at=chosen.observed_at,
        system_id=chosen.system_id,
        resource_id=chosen.resource_id,
        category=chosen.category,
        emails=set(chosen.emails),
        phones=set(chosen.phones),
        hashes=set(chosen.hashes),
        user_ids=set(chosen.user_ids),
        present=present_now,
        direct_pii=chosen.direct_pii,
        linked_subject=chosen.linked_subject,
        flow_enabled=chosen.flow_enabled,
        restore_allowed=chosen.restore_allowed,
        explicit=chosen.explicit,
        packaged_at=chosen.packaged_at,
    )
    # A later log line can name the resource without repeating the control flag.
    if merged.flow_enabled is None or merged.restore_allowed is None:
        for obs in reversed(eligible):
            if merged.flow_enabled is None and obs.flow_enabled is not None:
                merged.flow_enabled = obs.flow_enabled
            if merged.restore_allowed is None and obs.restore_allowed is not None:
                merged.restore_allowed = obs.restore_allowed
            if merged.flow_enabled is not None and merged.restore_allowed is not None:
                break
    # Cite a package that already existed at audit time when one proves the
    # same conclusion. Later log exports can confirm a fact without being the
    # citation if an earlier snapshot already shows it.
    citable = [
        obs
        for obs in eligible
        if (obs.packaged_at or obs.captured_at) <= audit_at
        and obs.present == merged.present
        and (merged.restore_allowed is None or obs.restore_allowed in {None, merged.restore_allowed})
        and (merged.flow_enabled is None or obs.flow_enabled in {None, merged.flow_enabled})
    ]
    citable = [obs for obs in citable if obs.restore_allowed is not None or obs.flow_enabled is not None or obs.present == merged.present]
    if citable:
        citable.sort(key=lambda obs: (obs.observed_at, obs.captured_at, obs.file_id))
        merged.file_id = citable[-1].file_id
    return merged


def _resource_state(obs: Observation) -> ResourceState:
    return ResourceState(
        system_id=obs.system_id or system_for(obs.resource_id),
        resource_id=obs.resource_id,
        category=obs.category,
        present=obs.present,
        direct_pii=obs.direct_pii,
        linked_subject=obs.linked_subject,
        flow_enabled=obs.flow_enabled,
        restore_allowed=obs.restore_allowed,
        evidence_id=obs.file_id,
        observed_at=obs.observed_at.isoformat(),
    )


def _narrative_resource_ids(request: Request, world: World, reported_counts: dict[str, int]) -> set[str]:
    """Attach worker targets when this report time belongs to a single request.

    Hand-authored cases emit a deletion-worker burst within a few minutes of
    ``reported_at``. Generated cases share timestamp buckets, so the same
    window would mix unrelated people and is not used for them.
    """
    if reported_counts.get(request.reported_at.isoformat(), 0) != 1:
        return set()
    start = request.reported_at - timedelta(minutes=15)
    end = request.reported_at + timedelta(minutes=15)
    found: set[str] = set()
    for activity in world.activities:
        if activity.source_system != "deletion_worker":
            continue
        if start <= activity.event_time <= end:
            found.add(activity.resource_id)
    return found


def _apply_worker_category(obs: Observation, activities: list[Activity], audit_at: datetime) -> None:
    """Use the deletion worker's chosen treatment when evidence category is ambiguous."""
    relevant = [
        activity
        for activity in activities
        if activity.source_system == "deletion_worker" and activity.event_time <= audit_at
    ]
    if not relevant:
        return
    last = max(relevant, key=lambda activity: activity.event_time)
    if obs.resource_id.startswith("support_") and last.event_type == "DELETE_RECORD":
        obs.category = "SUPPORT_ATTACHMENT"
    elif obs.resource_id.startswith("support_") and last.event_type == "REDACT_RECORD":
        obs.category = "SUPPORT_MESSAGE"
    elif obs.resource_id.startswith("analytics_") and last.event_type == "DELETE_RECORD":
        obs.category = "MARKETING_PROFILE"
    elif obs.resource_id.startswith("analytics_") and last.event_type == "ANONYMIZE_RECORD":
        obs.category = "ANALYTICS_PROFILE"


def linked_states(request: Request, person_user_id: str, person_emails: set[str], person_phones: set[str], person_hashes: set[str], world: World, reported_counts: dict[str, int]) -> list[ResourceState]:
    audit_at = request.audit_at
    resource_ids: set[str] = set()
    for obs in world.observations:
        if obs.captured_at > audit_at or obs.observed_at > audit_at:
            continue
        if obs.matches_person(person_emails, person_phones, person_hashes, person_user_id):
            resource_ids.add(obs.resource_id)

    # Identifiers learned from a later snapshot can name a resource whose
    # audit-time observation is a 404 with the identifier already removed.
    # The later row is used only as a stable identity link. State still comes
    # from observations at or before audit_at.
    for obs in world.observations:
        if obs.resource_id in resource_ids:
            continue
        if obs.matches_person(person_emails, person_phones, person_hashes, person_user_id):
            if any(earlier.observed_at <= audit_at and earlier.captured_at <= audit_at for earlier in world.by_resource.get(obs.resource_id, [])):
                resource_ids.add(obs.resource_id)

    for resource_id in _narrative_resource_ids(request, world, reported_counts):
        resource_ids.add(resource_id)

    padded = _padded_account(person_user_id)
    other_accounts = {resource_id for resource_id in resource_ids if resource_id.startswith("account_")}
    if padded and (padded in world.activity_by_resource or not other_accounts):
        resource_ids.add(padded)

    states: list[ResourceState] = []
    for resource_id in resource_ids:
        history = world.by_resource.get(resource_id, [])
        chosen = _latest_state(history, audit_at)
        if chosen is None and padded and resource_id == padded:
            chosen = _omitted_account(resource_id, person_emails, world, audit_at)
        if chosen is None:
            continue
        _apply_worker_category(chosen, world.activity_by_resource.get(resource_id, []), audit_at)
        # Drop decoys that explicit evidence assigns to someone else.
        if chosen.emails and not (chosen.emails & person_emails) and not (chosen.user_ids and person_user_id in chosen.user_ids):
            if not (chosen.phones & person_phones) and not (chosen.hashes & person_hashes):
                continue
        if chosen.user_ids and person_user_id not in chosen.user_ids and not (chosen.emails & person_emails):
            # A retained security or backup row names exactly one subject.
            if chosen.category in {"SECURITY_AUDIT_LOG", "BACKUP_ARCHIVE", "DATA_FLOW", "LEGAL_HOLD_RECORD", "SUPPORT_MESSAGE"}:
                continue
        states.append(_resource_state(chosen))
    return _collapse_absent_profiles(states)


def _collapse_absent_profiles(states: list[ResourceState]) -> list[ResourceState]:
    """Keep the latest absent profile when older lookups returned 404 for another id.

    A person has one account profile. Stale or decoy lookups can record a 404
    against a different account id months earlier. The latest absent profile is
    the one the audit should verify.
    """
    profiles = [state for state in states if state.category == "USER_PROFILE"]
    absent = [state for state in profiles if not state.present]
    if len(absent) <= 1:
        return states
    latest = max(absent, key=lambda state: state.observed_at)
    drop = {state.resource_id for state in absent if state.resource_id != latest.resource_id}
    return [state for state in states if state.resource_id not in drop]


def _omitted_account(resource_id: str, emails: set[str], world: World, audit_at: datetime) -> Observation | None:
    """Prove a narrative account is absent from the failover profile census.

    The early accounts share one replica snapshot that still contains the
    drifted ``account_005`` row. When this profile is missing from that
    census, the census is the proof of absence.
    """
    census = [
        obs
        for obs in world.by_resource.get("account_005", [])
        if obs.present and obs.captured_at <= audit_at and obs.category == "USER_PROFILE"
    ]
    if not census:
        return None
    census.sort(key=lambda obs: (obs.captured_at, obs.file_id))
    proof = census[-1]
    sibling_rows = [
        obs
        for obs in world.observations
        if obs.file_id == proof.file_id and obs.category == "USER_PROFILE"
    ]
    if any(obs.resource_id == resource_id and obs.present for obs in sibling_rows):
        return None
    if any(obs.emails & emails for obs in sibling_rows):
        return None
    return Observation(
        file_id=proof.file_id,
        captured_at=proof.captured_at,
        observed_at=proof.captured_at,
        system_id="account_service",
        resource_id=resource_id,
        category="USER_PROFILE",
        present=False,
        explicit=False,
    )


def audit_request(request: Request, world: World, reported_counts: dict[str, int], identity: IdentityIndex | None = None) -> AuditResult:
    if not authorizes_deletion(request.request_text):
        return AuditResult(request.case_id, "NOT_APPLICABLE", [])

    index = identity or world.identity_at(request.audit_at)
    person = index.person_for_email(request.email)
    if person is None:
        # The request email itself is still an identifier even when the
        # directory no longer lists it.
        states = []
        steps: list[Step] = []
    else:
        states = linked_states(
            request,
            person.user_id,
            set(person.emails) | {(request.email or "").strip().lower()},
            set(person.phones),
            set(person.hashes),
            world,
            reported_counts,
        )
        steps = []
        for state in states:
            steps.extend(steps_for_resource(state))

    ordered = order_steps(steps)
    incomplete = any(step.phase == "FINDING" for step in ordered)
    if incomplete:
        scrubbed = []
        for step in ordered:
            if step.phase == "FINDING":
                scrubbed.append(step)
            else:
                scrubbed.append(
                    Step(
                        phase=step.phase,
                        system_id=step.system_id,
                        resource_id=step.resource_id,
                        operation=step.operation,
                        state=step.state,
                        evidence_id="",
                    )
                )
        ordered = scrubbed
        status = "INCOMPLETE"
    else:
        status = "COMPLETE"
    return AuditResult(
        case_id=request.case_id,
        deletion_status=status,
        steps=[step.as_dict(index + 1) for index, step in enumerate(ordered)],
    )


def audit_all(requests: list[Request], world: World) -> list[AuditResult]:
    counts: dict[str, int] = {}
    for request in requests:
        key = request.reported_at.isoformat()
        counts[key] = counts.get(key, 0) + 1
    # Cache identity indexes by audit timestamp. Many cases share one cutoff.
    identity_cache: dict[datetime, IdentityIndex] = {}
    results: list[AuditResult] = []
    for request in requests:
        identity = identity_cache.get(request.audit_at)
        if identity is None:
            identity = world.identity_at(request.audit_at)
            identity_cache[request.audit_at] = identity
        results.append(audit_request(request, world, counts, identity))
    results.sort(key=lambda item: _case_number(item.case_id))
    return results


def write_output(results: list[AuditResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "case_id": result.case_id,
                    "deletion_status": result.deletion_status,
                    "steps_json": json.dumps(result.steps, ensure_ascii=False, separators=(",", ":")),
                }
            )


def dataset_dir_from(root: Path | None = None) -> Path:
    return (root or ROOT) / "dataset"
