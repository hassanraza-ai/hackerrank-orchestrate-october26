"""Parse participant evidence into time-stamped resource observations."""

from __future__ import annotations

import csv
import json
import re
import sqlite3
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from deletion_audit.identity import norm_email, norm_hash, norm_phone, norm_user_id, parse_time

RESOURCE_RE = re.compile(
    r"\b(account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|marketing|cache|email_delivery|legal_hold|object)_\d+\b"
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(?:\"([^\"]*)\"|'([^']*)'|([^\s,]+))")

SYSTEM_BY_PREFIX = (
    ("data_flow_", "integration_service"),
    ("audit_record_", "security_service"),
    ("email_delivery_", "email_delivery_service"),
    ("legal_hold_", "legal_service"),
    ("account_", "account_service"),
    ("search_", "search_service"),
    ("analytics_", "analytics_platform"),
    ("support_", "support_platform"),
    ("export_", "export_service"),
    ("backup_", "backup_service"),
    ("tombstone_", "identity_service"),
    ("marketing_", "marketing_platform"),
    ("cache_", "cache_service"),
    ("object_", "object_storage"),
)

CATEGORY_BY_PREFIX = {
    "account_": "USER_PROFILE",
    "search_": "SEARCH_INDEX_ENTRY",
    "analytics_": "ANALYTICS_PROFILE",
    "support_": "SUPPORT_MESSAGE",
    "export_": "USER_EXPORT",
    "backup_": "BACKUP_ARCHIVE",
    "data_flow_": "DATA_FLOW",
    "audit_record_": "SECURITY_AUDIT_LOG",
    "tombstone_": "ACCOUNT_TOMBSTONE",
    "marketing_": "MARKETING_PROFILE",
    "cache_": "CACHE_ENTRY",
    "email_delivery_": "EMAIL_DELIVERY_LOG",
    "legal_hold_": "LEGAL_HOLD_RECORD",
    "object_": "SUPPORT_ATTACHMENT",
}

COLLECTION_CATEGORY = {
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "support_conversations": "SUPPORT_MESSAGE",
    "support_records": "SUPPORT_MESSAGE",
    "customer_exports": "USER_EXPORT",
    "connector_configurations": "DATA_FLOW",
    "connector_subscriptions": "DATA_FLOW",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "security_audit_records": "SECURITY_AUDIT_LOG",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "retained_order_records": "LEGAL_HOLD_RECORD",
    "backup_restore_entries": "BACKUP_ARCHIVE",
}

NULL_STRINGS = {"", "null", "none", "nil", "no direct identifier"}


@dataclass
class Observation:
    file_id: str
    captured_at: datetime
    observed_at: datetime
    system_id: str
    resource_id: str
    category: str
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    user_ids: set[str] = field(default_factory=set)
    present: bool = True
    direct_pii: bool = False
    linked_subject: bool = False
    flow_enabled: bool | None = None
    restore_allowed: bool | None = None
    explicit: bool = True
    packaged_at: datetime | None = None

    def matches_person(self, emails: set[str], phones: set[str], hashes: set[str], user_id: str) -> bool:
        if self.user_ids and user_id in self.user_ids:
            return True
        if self.emails & emails:
            return True
        if self.phones & phones:
            return True
        if self.hashes & hashes:
            return True
        return False


def system_for(resource_id: str, fallback: str = "") -> str:
    for prefix, system_id in SYSTEM_BY_PREFIX:
        if resource_id.startswith(prefix):
            return system_id
    return fallback or "unknown_system"


def category_for(resource_id: str, explicit: str = "") -> str:
    if explicit:
        token = explicit.strip().upper()
        aliases = {
            "DATA_FLOW": "DATA_FLOW",
            "USER_PROFILE": "USER_PROFILE",
            "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",
            "ANALYTICS_PROFILE": "ANALYTICS_PROFILE",
            "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",
            "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT",
            "USER_EXPORT": "USER_EXPORT",
            "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",
            "SECURITY_AUDIT_LOG": "SECURITY_AUDIT_LOG",
            "ACCOUNT_TOMBSTONE": "ACCOUNT_TOMBSTONE",
            "MARKETING_PROFILE": "MARKETING_PROFILE",
            "CACHE_ENTRY": "CACHE_ENTRY",
            "EMAIL_DELIVERY_LOG": "EMAIL_DELIVERY_LOG",
            "LEGAL_HOLD_RECORD": "LEGAL_HOLD_RECORD",
            "SECONDARY_IDENTIFIER": "SECONDARY_IDENTIFIER",
            "PRODUCT_TELEMETRY": "PRODUCT_TELEMETRY",
        }
        if token in aliases:
            return aliases[token]
    for prefix, category in CATEGORY_BY_PREFIX.items():
        if resource_id.startswith(prefix):
            return category
    return explicit or "USER_PROFILE"


def _as_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"", "null", "none"}:
        return None
    if text in {"1", "true", "yes", "enabled", "active", "delivered"}:
        return True
    if text in {"0", "false", "no", "disabled", "stopped", "blocked", "inactive"}:
        return False
    return None


def _clean(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower() in NULL_STRINGS:
        return ""
    return text


def _absorb_identifiers(obs: Observation, blob: str) -> None:
    for email in EMAIL_RE.findall(blob):
        cleaned = norm_email(email)
        if cleaned:
            obs.emails.add(cleaned)
    for user_id in USER_RE.findall(blob):
        obs.user_ids.add(user_id)
    for digest in HASH_RE.findall(blob):
        cleaned = norm_hash(digest)
        if cleaned:
            obs.hashes.add(cleaned)
    for match in re.finditer(r"\+\d[\d\s().-]{6,}\d", blob):
        phone = norm_phone(match.group(0))
        if phone:
            obs.phones.add(phone)


def _finalize(obs: Observation) -> Observation:
    obs.direct_pii = bool(obs.emails or obs.phones or obs.hashes)
    # A subject reference on a profile, analytics row, or support row means the
    # record can still be tied to the person. Security logs and legal holds are
    # supposed to keep that reference.
    if obs.category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY", "SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE"}:
        obs.linked_subject = bool(obs.user_ids) and obs.category != "ACCOUNT_TOMBSTONE"
        if obs.category == "ACCOUNT_TOMBSTONE":
            obs.linked_subject = False
    else:
        obs.linked_subject = False
    if obs.category == "ANALYTICS_PROFILE" and obs.user_ids and not obs.direct_pii:
        obs.linked_subject = True
    return obs


def _obs_from_fields(
    *,
    file_id: str,
    captured_at: datetime,
    observed_at: datetime | None,
    system_id: str,
    resource_id: str,
    category: str,
    emails: set[str] | None = None,
    phones: set[str] | None = None,
    hashes: set[str] | None = None,
    user_ids: set[str] | None = None,
    present: bool = True,
    flow_enabled: bool | None = None,
    restore_allowed: bool | None = None,
    text_blob: str = "",
    packaged_at: datetime | None = None,
) -> Observation | None:
    if not resource_id or not RESOURCE_RE.fullmatch(resource_id):
        found = RESOURCE_RE.search(resource_id or "")
        if not found:
            return None
        resource_id = found.group(0)
    obs = Observation(
        file_id=file_id,
        captured_at=captured_at,
        observed_at=observed_at or captured_at,
        system_id=system_id or system_for(resource_id),
        resource_id=resource_id,
        category=category_for(resource_id, category),
        emails=set(emails or ()),
        phones=set(phones or ()),
        hashes=set(hashes or ()),
        user_ids=set(user_ids or ()),
        present=present,
        flow_enabled=flow_enabled,
        restore_allowed=restore_allowed,
        packaged_at=packaged_at or captured_at,
    )
    if text_blob:
        _absorb_identifiers(obs, text_blob)
    return _finalize(obs)


def load_manifest(dataset_dir: Path) -> list[dict[str, str]]:
    path = dataset_dir / "evidence_files.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_evidence(dataset_dir: Path) -> list[Observation]:
    observations: list[Observation] = []
    for row in load_manifest(dataset_dir):
        captured = parse_time(row["captured_at"])
        if captured is None:
            continue
        path = dataset_dir / row["file_path"]
        if not path.exists():
            continue
        parser = _parser_for(path)
        try:
            observations.extend(parser(path, row["file_id"], captured))
        except Exception:
            # One unreadable artifact should not sink the audit.
            continue
    observations.sort(key=lambda item: (item.observed_at, item.captured_at, item.file_id, item.resource_id))
    return observations


def _parser_for(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".sql":
        return _parse_sql
    if suffix == ".json":
        return _parse_json
    if suffix == ".log":
        return _parse_log
    if suffix == ".txt":
        return _parse_text
    if suffix == ".pdf":
        return _parse_pdf
    if suffix == ".png":
        return _parse_image
    return lambda *_args, **_kwargs: []


def _parse_sql(path: Path, file_id: str, captured_at: datetime) -> list[Observation]:
    script = path.read_text(encoding="utf-8", errors="replace")
    header_time = _comment_time(script) or captured_at
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(script)
    except sqlite3.DatabaseError:
        connection.close()
        return _parse_sql_regex(script, file_id, header_time)
    observations: list[Observation] = []
    tables = [
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    ]
    for table in tables:
        if table == "snapshot_scope":
            continue
        columns = [row[1] for row in connection.execute(f"PRAGMA table_info('{table}')")]
        for values in connection.execute(f"SELECT * FROM '{table}'"):
            record = {column: value for column, value in zip(columns, values)}
            observations.extend(
                _observations_from_record(record, file_id, header_time, table, file_captured_at=captured_at)
            )
    connection.close()
    return observations


def _parse_sql_regex(script: str, file_id: str, captured_at: datetime) -> list[Observation]:
    observations: list[Observation] = []
    for match in re.finditer(r"INSERT INTO\s+\"?([A-Za-z0-9_]+)\"?\s+VALUES\((.*?)\);", script, re.I | re.S):
        body = match.group(2)
        try:
            row = next(csv.reader([body], delimiter=",", quotechar="'"))
        except csv.Error:
            continue
        if not row:
            continue
        resource_id = row[0].strip().strip("'\"")
        payload = row[3] if len(row) >= 4 else ""
        system_id = row[1].strip().strip("'\"") if len(row) >= 2 else ""
        collection = row[2].strip().strip("'\"") if len(row) >= 3 else ""
        record = {
            "resource_id": resource_id,
            "system_id": system_id,
            "collection": collection,
            "payload": payload,
        }
        observations.extend(
            _observations_from_record(record, file_id, captured_at, match.group(1), file_captured_at=captured_at)
        )
    return observations


def _parse_json(path: Path, file_id: str, captured_at: datetime) -> list[Observation]:
    data = json.loads(path.read_text(encoding="utf-8"))
    observations: list[Observation] = []
    _walk_json(data, file_id, captured_at, observations, inherited={})
    return observations


def _walk_json(node: object, file_id: str, captured_at: datetime, sink: list[Observation], inherited: dict) -> None:
    if isinstance(node, list):
        for item in node:
            _walk_json(item, file_id, captured_at, sink, inherited)
        return
    if not isinstance(node, dict):
        return
    context = dict(inherited)
    for key in ("data_store", "source", "service", "system_id"):
        if isinstance(node.get(key), str):
            context["system_id"] = node[key]
    if isinstance(node.get("collection"), str):
        context["collection"] = node["collection"]
    if isinstance(node.get("captured_at"), str):
        context["captured_at"] = node["captured_at"]
    if isinstance(node.get("observed_at"), str):
        context["observed_at"] = node["observed_at"]
    if isinstance(node.get("exported_at"), str):
        context.setdefault("observed_at", node["exported_at"])

    if "resource_id" in node or ("profile" in node and "status_code" in node):
        record = dict(node)
        record.setdefault("system_id", context.get("system_id", ""))
        record.setdefault("collection", context.get("collection", ""))
        observed = parse_time(str(context.get("observed_at") or node.get("observed_at") or node.get("updated_at") or "")) or parse_time(str(context.get("captured_at") or "")) or captured_at
        sink.extend(
            _observations_from_record(
                record,
                file_id,
                observed,
                context.get("collection", ""),
                file_captured_at=captured_at,
            )
        )

    for key, value in node.items():
        if isinstance(value, (dict, list)) and key not in {"profile", "hits", "documents", "metrics"}:
            _walk_json(value, file_id, captured_at, sink, context)
        elif key in {"profile", "hits", "documents"} and isinstance(value, (dict, list)):
            _walk_json(value, file_id, captured_at, sink, context)


def _observations_from_record(
    record: dict,
    file_id: str,
    observed_at: datetime,
    table: str,
    file_captured_at: datetime | None = None,
    manifest_at: datetime | None = None,
) -> list[Observation]:
    expanded = _expand_payload(record)
    resource_id = _clean(expanded.get("resource_id"))
    if not resource_id:
        for value in expanded.values():
            if isinstance(value, str) and RESOURCE_RE.fullmatch(value):
                resource_id = value
                break
    if not resource_id:
        return []

    collection = _clean(expanded.get("collection") or table)
    category = COLLECTION_CATEGORY.get(collection, "")
    explicit_category = _clean(expanded.get("category") or expanded.get("data_category"))
    if explicit_category:
        category = explicit_category

    system_id = _clean(expanded.get("system_id") or expanded.get("data_store") or expanded.get("service"))
    if system_id and system_id not in {item[1] for item in SYSTEM_BY_PREFIX}:
        # Collection payloads store the real system in the second column.
        if system_id.endswith("_service") or system_id.endswith("_platform"):
            pass
        else:
            system_id = system_for(resource_id, system_id if "_" in system_id else "")
    if not system_id:
        system_id = system_for(resource_id)

    emails: set[str] = set()
    phones: set[str] = set()
    hashes: set[str] = set()
    user_ids: set[str] = set()
    blob_parts: list[str] = []

    email_keys = {
        "email",
        "owner_email",
        "customer_email",
        "requester_email",
        "lookup_key",
        "query",
        "match_key",
        "correlation_key",
        "subject_key",
        "subject_selector",
    }
    phone_keys = {"phone", "owner_phone", "requester_phone", "customer_phone"}
    hash_keys = {"email_hash"}
    user_keys = {"user_id", "customer_reference", "subject_reference", "subject_ref", "subject_reference_id"}
    name_keys = {"full_name", "display_name", "name", "requester_name"}

    for key, value in expanded.items():
        if isinstance(value, (dict, list)):
            blob_parts.append(json.dumps(value, ensure_ascii=False))
            continue
        text = _clean(value)
        if not text:
            continue
        blob_parts.append(text)
        if key in email_keys:
            email = norm_email(text)
            if email:
                emails.add(email)
            user_id = norm_user_id(text)
            if user_id:
                user_ids.add(user_id)
        elif key in phone_keys:
            phone = norm_phone(text)
            if phone:
                phones.add(phone)
        elif key in hash_keys:
            digest = norm_hash(text)
            if digest:
                hashes.add(digest)
        elif key in user_keys:
            user_id = norm_user_id(text)
            if user_id:
                user_ids.add(user_id)
        elif key in name_keys:
            pass

    present = True
    status_code = expanded.get("status_code") or expanded.get("http_status")
    rows = expanded.get("rows")
    result = _clean(expanded.get("result") or expanded.get("status") or expanded.get("raw_status")).upper()
    if str(status_code) in {"404", "410"} or str(rows) == "0" or result in {"NOT_FOUND", "MISS", "ABSENT"}:
        present = False
    if expanded.get("profile") is None and str(status_code) in {"404", "410"}:
        present = False
    account_status = _clean(expanded.get("account_status")).upper()
    if account_status == "DELETED" and category_for(resource_id, category) == "USER_PROFILE":
        # A deleted profile row that still stores direct identifiers is still present.
        present = True

    event = _clean(expanded.get("event")).lower()
    if "attachment" in event or "attachment" in collection:
        category = "SUPPORT_ATTACHMENT"
    elif "contact_query" in event or "contact_lookup" in event or "legacy_contact" in " ".join(blob_parts).lower():
        if resource_id.startswith("support_"):
            category = "SECONDARY_IDENTIFIER"
        elif resource_id.startswith("analytics_"):
            category = "MARKETING_PROFILE"
    if "email_opt_in" in expanded and resource_id.startswith("analytics_"):
        category = "MARKETING_PROFILE"
    message = _clean(expanded.get("message_text") or expanded.get("message_excerpt"))
    if message == "[REDACTED]":
        emails.clear()
        phones.clear()
        hashes.clear()

    flow_enabled = None
    if "enabled" in expanded:
        flow_enabled = _as_bool(expanded.get("enabled"))
    restore_allowed = None
    if "restore_allowed" in expanded:
        restore_allowed = _as_bool(expanded.get("restore_allowed"))
    elif "eligible" in expanded or "deletion_block" in expanded:
        eligible = _as_bool(expanded.get("eligible"))
        blocked = _as_bool(expanded.get("deletion_block"))
        if blocked is True or eligible is False:
            restore_allowed = False
        elif eligible is True and blocked is False:
            restore_allowed = True

    observed = parse_time(_clean(expanded.get("observed_at") or expanded.get("updated_at") or expanded.get("indexed_at"))) or observed_at
    obs = _obs_from_fields(
        file_id=file_id,
        captured_at=file_captured_at or observed_at,
        observed_at=observed,
        system_id=system_id,
        resource_id=resource_id,
        category=category,
        emails=emails,
        phones=phones,
        hashes=hashes,
        user_ids=user_ids,
        present=present,
        flow_enabled=flow_enabled,
        restore_allowed=restore_allowed,
        text_blob="\n".join(blob_parts),
        packaged_at=manifest_at or file_captured_at or observed_at,
    )
    if obs and message == "[REDACTED]":
        obs.direct_pii = False
        obs.emails.clear()
        obs.phones.clear()
        obs.hashes.clear()
    return [obs] if obs else []


def _expand_payload(record: dict) -> dict:
    expanded = dict(record)
    for key, value in list(record.items()):
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text or text[0] not in "{[":
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            for child_key, child_value in parsed.items():
                expanded.setdefault(child_key, child_value)
            if isinstance(parsed.get("document"), dict):
                for child_key, child_value in parsed["document"].items():
                    expanded.setdefault(child_key, child_value)
        elif isinstance(parsed, list):
            expanded[key] = parsed
    profile = expanded.get("profile")
    if isinstance(profile, dict):
        for key, value in profile.items():
            expanded.setdefault(key, value)
    hits = expanded.get("hits")
    if isinstance(hits, dict):
        documents = hits.get("documents") or []
        if documents and isinstance(documents[0], dict):
            for key, value in documents[0].items():
                expanded.setdefault(key, value)
            if not expanded.get("resource_id") and documents[0].get("resource_id"):
                expanded["resource_id"] = documents[0]["resource_id"]
    return expanded


def _log_fields(line: str) -> dict[str, str]:
    fields = {match.group(1): match.group(2) or match.group(3) or match.group(4) for match in KV_RE.finditer(line)}
    message = fields.get("message")
    if message and "=" in message:
        unescaped = message.replace('\\"', '"')
        for match in KV_RE.finditer(unescaped):
            fields.setdefault(match.group(1), match.group(2) or match.group(3) or match.group(4))
    brace = line.find("{")
    if brace >= 0:
        try:
            payload = json.loads(line[brace:])
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(value, (str, int, float)):
                    fields.setdefault(str(key), str(value))
    return fields


def _parse_log(path: Path, file_id: str, captured_at: datetime) -> list[Observation]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    parsed: list[dict] = []
    for line in lines:
        timestamp = _leading_time(line) or captured_at
        fields = _log_fields(line)
        fields["__line"] = line
        fields["__time"] = timestamp.isoformat()
        parsed.append(fields)

    by_trace: dict[str, dict] = {}
    for fields in parsed:
        trace = fields.get("trace_id") or fields.get("requestId") or fields.get("request_id")
        if not trace:
            continue
        bucket = by_trace.setdefault(trace, {})
        for key, value in fields.items():
            if value and key not in bucket:
                bucket[key] = value

    observations: list[Observation] = []
    seen: set[tuple] = set()
    for fields in parsed:
        trace = fields.get("trace_id") or fields.get("requestId") or fields.get("request_id")
        merged = dict(by_trace.get(trace, {}))
        merged.update({key: value for key, value in fields.items() if value})
        resource_id = merged.get("resource_id", "")
        if not RESOURCE_RE.fullmatch(resource_id or ""):
            continue
        observed = parse_time(merged.get("__time")) or captured_at
        record = dict(merged)
        record["resource_id"] = resource_id
        record["service"] = merged.get("service") or merged.get("function") or ""
        # Log lines are timestamped facts. The manifest time is when the
        # export was packaged, which can be later than the events themselves.
        produced = _observations_from_record(
            record,
            file_id,
            observed,
            "",
            file_captured_at=observed,
            manifest_at=captured_at,
        )
        for obs in produced:
            key = (obs.resource_id, obs.observed_at, obs.present, obs.category)
            if key in seen:
                continue
            seen.add(key)
            observations.append(obs)
    return observations


def _parse_text(path: Path, file_id: str, captured_at: datetime) -> list[Observation]:
    observations: list[Observation] = []
    line_re = re.compile(
        r"^(?P<time>\S+)\s+\|\s+(?P<system>[^|]+?)\s+\|\s+(?P<resource>[^|]+?)\s+\|\s+(?P<category>[^|]+?)\s+\|\s+(?P<status>[^|]+?)\s+\|\s+(?P<ident>.*)$"
    )
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = line_re.match(line.strip().lstrip("- ").strip())
        if not match:
            continue
        status = match.group("status").strip().upper()
        present = status not in {"NOT_FOUND", "ABSENT", "MISSING"}
        flow_enabled = None
        restore_allowed = None
        category = match.group("category").strip().upper()
        if category == "DATA_FLOW":
            flow_enabled = status in {"ACTIVE", "ENABLED"}
            if status in {"DISABLED", "STOPPED"}:
                flow_enabled = False
        if category == "BACKUP_ARCHIVE":
            restore_allowed = status in {"ACTIVE", "RESTORABLE"}
            if status in {"BLOCKED", "DISABLED"}:
                restore_allowed = False
        ident = match.group("ident").strip()
        emails = set()
        user_ids = set()
        email = norm_email(ident)
        if email:
            emails.add(email)
        user_id = norm_user_id(ident)
        if user_id:
            user_ids.add(user_id)
        observed = parse_time(match.group("time")) or captured_at
        direct = status in {"IDENTIFIABLE", "FOUND", "ACTIVE"} and bool(emails)
        anonymized = status == "ANONYMIZED"
        redacted = status == "REDACTED"
        obs = _obs_from_fields(
            file_id=file_id,
            captured_at=captured_at,
            observed_at=observed,
            system_id=match.group("system").strip(),
            resource_id=match.group("resource").strip(),
            category=category,
            emails=emails if not anonymized and not redacted else set(),
            user_ids=user_ids,
            present=present,
            flow_enabled=flow_enabled,
            restore_allowed=restore_allowed,
        )
        if obs:
            if anonymized:
                obs.direct_pii = False
                obs.linked_subject = False
                obs.emails.clear()
            if redacted:
                obs.direct_pii = False
                obs.emails.clear()
            if direct:
                obs.direct_pii = True
            observations.append(obs)
    return observations


def _parse_pdf(path: Path, file_id: str, captured_at: datetime) -> list[Observation]:
    text = _pdf_text(path)
    observations = _observations_from_free_text(text, file_id, captured_at)
    for obs in observations:
        if obs.resource_id.startswith("support_") or obs.resource_id.startswith("object_"):
            obs.category = "SUPPORT_ATTACHMENT"
    return observations


def _parse_image(path: Path, file_id: str, captured_at: datetime) -> list[Observation]:
    text = _ocr_text(path)
    return _observations_from_free_text(text, file_id, captured_at)


def _observations_from_free_text(text: str, file_id: str, captured_at: datetime) -> list[Observation]:
    if not text:
        return []
    observations: list[Observation] = []
    resources = list(dict.fromkeys(RESOURCE_RE.findall(text) and RESOURCE_RE.finditer(text) and [m.group(0) for m in RESOURCE_RE.finditer(text)] or []))
    # RESOURCE_RE.findall with groups returns only the prefix. Use finditer.
    resources = []
    seen = set()
    for match in RESOURCE_RE.finditer(text):
        if match.group(0) not in seen:
            seen.add(match.group(0))
            resources.append(match.group(0))
    emails = {norm_email(item) for item in EMAIL_RE.findall(text)}
    emails.discard(None)
    user_ids = set(USER_RE.findall(text))
    phones = set()
    for match in re.finditer(r"\+\d[\d\s().-]{6,}\d", text):
        phone = norm_phone(match.group(0))
        if phone:
            phones.add(phone)
    hashes = {norm_hash(item) for item in HASH_RE.findall(text)}
    hashes.discard(None)
    lowered = text.lower()
    for resource_id in resources:
        window_start = max(0, text.find(resource_id) - 400)
        window = text[window_start:text.find(resource_id) + 400]
        local_emails = {norm_email(item) for item in EMAIL_RE.findall(window)}
        local_emails.discard(None)
        local_users = set(USER_RE.findall(window))
        category = category_for(resource_id)
        if "attachment" in window.lower() or resource_id.startswith("object_"):
            category = "SUPPORT_ATTACHMENT" if not resource_id.startswith("object_") else "SUPPORT_ATTACHMENT"
        if "tombstone" in window.lower() or "deleted-account" in window.lower() or "deleted account" in window.lower():
            if resource_id.startswith("tombstone_"):
                category = "ACCOUNT_TOMBSTONE"
        present = "not found" not in window.lower() and "no longer exists" not in window.lower()
        obs = _obs_from_fields(
            file_id=file_id,
            captured_at=captured_at,
            observed_at=captured_at,
            system_id=system_for(resource_id),
            resource_id=resource_id,
            category=category,
            emails=set(local_emails or emails),
            phones=phones,
            hashes=set(hashes),
            user_ids=local_users or user_ids,
            present=present,
            text_blob=window,
        )
        if obs:
            if "redacted" in lowered and resource_id.startswith("support_"):
                obs.direct_pii = False
            observations.append(obs)
    return observations


def _pdf_text(path: Path) -> str:
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:
        data = path.read_bytes()
        parts = re.findall(rb"\((?:\\.|[^\\)]){4,}\)", data)
        return "\n".join(part[1:-1].decode("latin1", errors="ignore") for part in parts)


def _ocr_text(path: Path) -> str:
    try:
        completed = subprocess.run(
            ["tesseract", str(path), "stdout", "--psm", "6"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout or ""


def _leading_time(line: str) -> datetime | None:
    match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", line)
    if not match:
        return None
    return parse_time(match.group(1))


def _comment_time(script: str) -> datetime | None:
    match = re.search(r"Captured at:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", script)
    if not match:
        match = re.search(r"snapshot_completed_at=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", script)
    if not match:
        return None
    return parse_time(match.group(1))
