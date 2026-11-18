#!/usr/bin/env python3
"""Audit every request in dataset/deletion_requests.csv and write output.csv."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from deletion_audit.pipeline import ROOT, World, audit_all, dataset_dir_from, load_requests, write_output


def main() -> None:
    dataset_dir = dataset_dir_from(ROOT)
    requests_path = dataset_dir / "deletion_requests.csv"
    output_path = ROOT / "output.csv"
    print(f"Loading evidence from {dataset_dir}")
    world = World(dataset_dir)
    requests = load_requests(requests_path)
    print(f"Auditing {len(requests)} requests")
    results = audit_all(requests, world)
    write_output(results, output_path)
    counts: dict[str, int] = {}
    for result in results:
        counts[result.deletion_status] = counts.get(result.deletion_status, 0) + 1
    print(f"Wrote {len(results)} rows to {output_path}")
    print("Status counts:", counts)


if __name__ == "__main__":
    main()
