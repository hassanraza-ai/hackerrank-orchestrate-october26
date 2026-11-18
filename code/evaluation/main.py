#!/usr/bin/env python3
"""Compare the auditor with dataset/sample_output.csv and print field accuracy."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from deletion_audit.pipeline import ROOT, World, audit_all, dataset_dir_from, load_requests


def _load_expected(path: Path) -> dict[str, dict[str, str]]:
    import csv

    with path.open(newline="", encoding="utf-8") as handle:
        return {row["case_id"]: row for row in csv.DictReader(handle)}


def compare() -> dict[str, float]:
    dataset_dir = dataset_dir_from(ROOT)
    world = World(dataset_dir)
    requests = load_requests(dataset_dir / "sample_deletion_requests.csv")
    results = {item.case_id: item for item in audit_all(requests, world)}
    expected = _load_expected(dataset_dir / "sample_output.csv")

    status_hits = 0
    step_hits = 0
    step_total = 0
    field_hits = 0
    field_total = 0
    sequence_hits = 0

    for case_id, row in expected.items():
        got = results[case_id]
        if got.deletion_status == row["deletion_status"]:
            status_hits += 1
        exp_steps = json.loads(row["steps_json"])
        got_steps = got.steps
        if [step["operation"] for step in exp_steps] == [step["operation"] for step in got_steps] and [
            step["resource_id"] for step in exp_steps
        ] == [step["resource_id"] for step in got_steps]:
            sequence_hits += 1
        step_total += max(len(exp_steps), len(got_steps))
        for index in range(max(len(exp_steps), len(got_steps))):
            if index >= len(exp_steps) or index >= len(got_steps):
                continue
            step_hits += 1
            for field in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total += 1
                if exp_steps[index].get(field) == got_steps[index].get(field):
                    field_hits += 1
        if len(exp_steps) != len(got_steps):
            field_total += abs(len(exp_steps) - len(got_steps)) * 6

    cases = len(expected)
    metrics = {
        "cases": cases,
        "status_accuracy": status_hits / cases,
        "sequence_accuracy": sequence_hits / cases,
        "step_recall": step_hits / step_total if step_total else 1.0,
        "field_accuracy": field_hits / field_total if field_total else 1.0,
    }
    print(json.dumps(metrics, indent=2))
    mismatches = []
    for case_id, row in expected.items():
        got = results[case_id]
        exp_steps = json.loads(row["steps_json"])
        if got.deletion_status != row["deletion_status"] or got.steps != exp_steps:
            mismatches.append(case_id)
    print("mismatched cases:", ", ".join(mismatches) if mismatches else "none")
    return metrics


if __name__ == "__main__":
    compare()
