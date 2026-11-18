"""Resolve a person to the identifiers that may still appear in evidence."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def norm_email(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip().lower()
    if "@" not in text or text in {"null", "none"}:
        return None
    return text


def norm_phone(value: str | None) -> str | None:
    if not value:
        return None
    digits = re.sub(r"\D", "", value)
    if len(digits) < 8:
        return None
    return digits


def norm_hash(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1]
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return text
    return None


def norm_user_id(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if re.fullmatch(r"user_\d+", text):
        return text
    return None


@dataclass
class Person:
    user_id: str
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)

    def matches_token(self, token: str) -> bool:
        email = norm_email(token)
        if email and email in self.emails:
            return True
        phone = norm_phone(token)
        if phone and phone in self.phones:
            return True
        digest = norm_hash(token)
        if digest and digest in self.hashes:
            return True
        user_id = norm_user_id(token)
        if user_id and user_id == self.user_id:
            return True
        return False


@dataclass
class IdentityIndex:
    by_user: dict[str, Person]
    email_to_user: dict[str, str]

    def person_for_email(self, email: str, audit_at: datetime | None = None) -> Person | None:
        del audit_at  # email map is already time-scoped by the caller via rebuild
        user_id = self.email_to_user.get((email or "").strip().lower())
        if not user_id:
            return None
        return self.by_user.get(user_id)


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def build_identity_index(dataset_dir: Path, audit_at: datetime | None = None) -> IdentityIndex:
    """Build identifier sets as they were known at ``audit_at``.

    Future identity edits are undone. Every email, phone, and hash that belonged
    to the person at or before the cutoff is kept, because older systems can
    still store those values.
    """
    identities = _load_csv(dataset_dir / "user_identities.csv")
    audit_rows = _load_csv(dataset_dir / "user_audit_log.csv")
    events_by_user: dict[str, list[dict[str, str]]] = {}
    for row in audit_rows:
        events_by_user.setdefault(row["user_id"], []).append(row)

    by_user: dict[str, Person] = {}
    email_to_user: dict[str, str] = {}

    for row in identities:
        user_id = row["user_id"]
        state = {
            "name": row.get("name") or "",
            "email": row.get("email") or "",
            "phone": row.get("phone") or "",
            "email_hash": row.get("email_hash") or "",
        }
        events = sorted(
            events_by_user.get(user_id, []),
            key=lambda item: item["event_time"],
            reverse=True,
        )
        historical: list[dict[str, str]] = []
        for event in events:
            event_time = parse_time(event["event_time"])
            if audit_at and event_time and event_time > audit_at:
                field_name = event["field_name"]
                if field_name in state and state[field_name] == event["new_value"]:
                    state[field_name] = event["old_value"]
                continue
            historical.append(event)

        person = Person(user_id=user_id)
        if state["name"]:
            person.names.add(state["name"])
        email = norm_email(state["email"])
        if email:
            person.emails.add(email)
        phone = norm_phone(state["phone"])
        if phone:
            person.phones.add(phone)
        digest = norm_hash(state["email_hash"])
        if digest:
            person.hashes.add(digest)

        for event in historical:
            field_name = event["field_name"]
            for raw in (event.get("old_value"), event.get("new_value")):
                if field_name == "email":
                    value = norm_email(raw)
                    if value:
                        person.emails.add(value)
                elif field_name == "phone":
                    value = norm_phone(raw)
                    if value:
                        person.phones.add(value)
                elif field_name == "email_hash":
                    value = norm_hash(raw)
                    if value:
                        person.hashes.add(value)
                elif field_name == "name" and raw:
                    person.names.add(raw)

        by_user[user_id] = person
        for email in person.emails:
            # A historical address can theoretically be reused. Prefer the
            # current owner when two people share a string, otherwise keep the
            # first observed subject.
            email_to_user.setdefault(email, user_id)

    # Current emails win over a historical collision.
    if audit_at is None:
        for row in identities:
            email = norm_email(row.get("email"))
            if email:
                email_to_user[email] = row["user_id"]
    else:
        for row in identities:
            updated = parse_time(row.get("updated_at"))
            email = norm_email(row.get("email"))
            if email and (updated is None or updated <= audit_at):
                email_to_user[email] = row["user_id"]

    return IdentityIndex(by_user=by_user, email_to_user=email_to_user)
