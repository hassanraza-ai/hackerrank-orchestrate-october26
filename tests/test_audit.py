"""Tests for the deletion-audit pipeline."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))

from deletion_audit.identity import build_identity_index, parse_time
from deletion_audit.intent import authorizes_deletion
from deletion_audit.pipeline import World, audit_all, dataset_dir_from, load_requests
from deletion_audit.policy import (
    FINDING_ORDER,
    REMEDIATION_ORDER,
    VERIFICATION_ORDER,
    ResourceState,
    order_steps,
    steps_for_resource,
)


class IntentTests(unittest.TestCase):
    def test_explicit_non_deletion_requests(self) -> None:
        samples = [
            "The mobile number on my profile is out of date. Please replace it with the new one and leave the account active.",
            "Please stop the promotional emails. I still need the account and my order history, so I am not asking for deletion.",
            "I'd like to download my account information in a portable format. Please keep the account as it is.",
            "I can't access my profile and need help resetting the login. Do not close the account.",
            "My surname is misspelled on the account. Can you correct it without removing any of my records?",
            "Please remove me from marketing lists only. I still want receipts and service messages for this account.",
            "Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.",
            "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place.",
            "Please change the email address used for this account. I want to continue using the service.",
            "Could you send me a copy of the information held on my account? I still use it, so please don't delete or change anything.",
        ]
        for text in samples:
            self.assertFalse(authorizes_deletion(text), text)

    def test_multilingual_deletion_requests(self) -> None:
        samples = [
            "Please permanently delete the account associated with this email address.",
            "Je demande la suppression définitive du compte associé à cette adresse e-mail.",
            "Solicito la eliminación permanente de la cuenta asociada a este correo.",
            "Solicito a exclusão permanente da conta associada a este e-mail.",
            "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.",
            "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
            "I found an old report saying my account still existed. Please check the latest state and confirm that the profile is gone.",
        ]
        for text in samples:
            self.assertTrue(authorizes_deletion(text), text)


class IdentityTests(unittest.TestCase):
    def test_historical_email_resolves_to_current_user(self) -> None:
        index = build_identity_index(dataset_dir_from(ROOT), parse_time("2026-09-18T12:25:00Z"))
        person = index.person_for_email("nadia.ionescu@yahoo.com")
        self.assertIsNotNone(person)
        assert person is not None
        self.assertEqual(person.user_id, "user_10")
        self.assertIn("n.petrescu@yahoo.com", person.emails)


class PolicyOrderTests(unittest.TestCase):
    def test_phases_and_operations_follow_the_contract(self) -> None:
        flow = ResourceState(
            "integration_service",
            "data_flow_1",
            "DATA_FLOW",
            True,
            False,
            False,
            True,
            None,
            "evidence_01",
            "2026-09-01T00:00:00+00:00",
        )
        record = ResourceState(
            "search_service",
            "search_9",
            "SEARCH_INDEX_ENTRY",
            True,
            True,
            False,
            None,
            None,
            "evidence_01",
            "2026-09-01T00:00:00+00:00",
        )
        ordered = order_steps(steps_for_resource(record) + steps_for_resource(flow))
        phases = [step.phase for step in ordered]
        self.assertEqual(phases, sorted(phases, key=lambda phase: {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}[phase]))
        finding_ops = [step.operation for step in ordered if step.phase == "FINDING"]
        self.assertEqual(finding_ops, sorted(finding_ops, key=FINDING_ORDER.index))
        remediation_ops = [step.operation for step in ordered if step.phase == "REMEDIATION"]
        self.assertEqual(remediation_ops, sorted(remediation_ops, key=REMEDIATION_ORDER.index))
        self.assertEqual(remediation_ops[0], "DISABLE_DATA_FLOW")
        verification_ops = [step.operation for step in ordered if step.phase == "VERIFICATION"]
        self.assertEqual(verification_ops, sorted(verification_ops, key=VERIFICATION_ORDER.index))

    def test_complete_case_keeps_evidence_and_incomplete_case_clears_future_steps(self) -> None:
        dataset = dataset_dir_from(ROOT)
        world = World(dataset)
        requests = {item.case_id: item for item in load_requests(dataset / "sample_deletion_requests.csv")}
        results = {item.case_id: item for item in audit_all(list(requests.values()), world)}
        complete = results["case_01"]
        self.assertEqual(complete.deletion_status, "COMPLETE")
        self.assertTrue(all(step["evidence_id"] for step in complete.steps))
        incomplete = results["case_05"]
        self.assertEqual(incomplete.deletion_status, "INCOMPLETE")
        self.assertTrue(all(step["evidence_id"] for step in incomplete.steps if step["phase"] == "FINDING"))
        self.assertTrue(all(step["evidence_id"] == "" for step in incomplete.steps if step["phase"] != "FINDING"))


class SampleContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        dataset = dataset_dir_from(ROOT)
        world = World(dataset)
        requests = load_requests(dataset / "sample_deletion_requests.csv")
        cls.results = {item.case_id: item for item in audit_all(requests, world)}
        import csv

        with (dataset / "sample_output.csv").open(newline="", encoding="utf-8") as handle:
            cls.expected = {row["case_id"]: row for row in csv.DictReader(handle)}

    def test_every_sample_status_matches(self) -> None:
        for case_id, row in self.expected.items():
            self.assertEqual(self.results[case_id].deletion_status, row["deletion_status"], case_id)

    def test_steps_are_valid_and_numbered(self) -> None:
        allowed = set(FINDING_ORDER + REMEDIATION_ORDER + VERIFICATION_ORDER)
        for case_id, result in self.results.items():
            for index, step in enumerate(result.steps, start=1):
                self.assertEqual(step["step_no"], index, case_id)
                self.assertIn(step["operation"], allowed, case_id)
                self.assertIn(step["phase"], {"FINDING", "REMEDIATION", "VERIFICATION"}, case_id)
                json.dumps(step)

    def test_known_exact_cases(self) -> None:
        for case_id in ("case_01", "case_05", "case_06", "case_08", "case_12"):
            expected = json.loads(self.expected[case_id]["steps_json"])
            got = self.results[case_id].steps
            self.assertEqual(
                [(step["operation"], step["resource_id"], step["evidence_id"]) for step in got],
                [(step["operation"], step["resource_id"], step["evidence_id"]) for step in expected],
                case_id,
            )


if __name__ == "__main__":
    unittest.main()
