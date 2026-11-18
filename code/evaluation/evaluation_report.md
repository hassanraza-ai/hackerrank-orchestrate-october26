# Evaluation report

The numbers below are from the public sample in `dataset/sample_deletion_requests.csv` compared with `dataset/sample_output.csv`, plus three custom checks. The 518-row hidden set has no participant-visible labels, so hidden accuracy is not claimed.

Run: `python3 -m unittest tests.test_audit` and `python3 code/main.py` on 2026-11-18.

## Case-level deletion status

| Set | Cases | Status matches | Accuracy |
| --- | ---: | ---: | ---: |
| Public sample | 32 | 32 | 100% |
| Full `deletion_requests.csv` | 518 | labels not available | n/a |

Full-run status mix written to `output.csv`: 170 `COMPLETE`, 338 `INCOMPLETE`, 10 `NOT_APPLICABLE`. The 10 non-applicable rows are `case_533` through `case_542`, the requests that ask for correction, access, export, marketing opt-out, or login help.

## Step, field, and sequence accuracy

Measured on the 32 public samples. A sequence match means the same operations and resource ids in the same order. A field match compares `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id` on aligned steps. Missing or extra steps count as field misses.

| Metric | Result |
| --- | ---: |
| Sequence accuracy | 16 / 32 = 50.0% |
| Step recall (a predicted step occupied an expected position) | 87.6% |
| Field accuracy | 892 / 1158 = 77.0% |

Status is right on every public sample. The remaining misses are missing resources, not wrong treatments of resources the auditor did link. The usual gaps are:

- an analytics row that has already been anonymized and therefore no longer carries an email, phone, hash, or user id;
- an account id that appears only as a 404 without the subject's email in the snapshot that the sample cites;
- the security-audit id that is tied to that account rather than to a direct identifier in the same file.

## Additional evaluation cases

These three checks are implemented in `tests/test_audit.py` and passed on 2026-11-18.

1. **Non-deletion corpus.** All ten explicit non-deletion texts in the full request file (phone correction, promotional opt-out, portable export, login reset, name correction, marketing-list removal, access request, invoice copy, email change, and "please don't delete") return `NOT_APPLICABLE`. French, Spanish, Portuguese, Korean, and Japanese deletion requests stay authorized, including a confirmation that "the profile is gone" without repeating the word delete.
2. **Historical identity.** `nadia.ionescu@yahoo.com` at the `case_10` audit time resolves to `user_10` and still carries the later address `n.petrescu@yahoo.com`, so older systems can be searched under both.
3. **Remediation order.** A live data flow and a remaining search document produce `DISABLE_DATA_FLOW` before `DELETE_RECORD`, and the phases stay `FINDING`, then `REMEDIATION`, then `VERIFICATION`. `case_01` keeps a non-empty evidence id on its verification step. `case_05` keeps evidence only on the finding.

## Failures found and improvements made

- Empty entry points could not read the dataset. The pipeline now loads every manifest file, including SQL replicas, JSON exports, logs, handover notes, PDFs, and screenshots.
- Non-deletion requests that still say "remove" were easy to mark as deletions. The intent check now keys off the explicit "keep the account" language, which matches the ten non-deletion rows and no sample deletion.
- Activity `reported_result` values contradicted later snapshots (a failed delete whose profile was already gone, and a successful delete whose profile was still present). State comes from evidence timestamps, not from the worker claim.
- A failover replica still held `account_005` after the primary copy was gone. Same-time observations treat any remaining copy as present.
- A September log export repeated an earlier backup fact and was about to replace the in-time SQL citation. Citations prefer a package whose manifest time is at or before `audit_at`.
- A March 404 for `account_6523` was a stale lookup for the same person as a later account id. When several absent profiles exist, only the latest one is kept.
- Support attachments were being redacted instead of deleted. PDF attachments and worker `DELETE_RECORD` actions on support ids are deleted. Conversation messages stay on the redact path. Marketing-style analytics rows with `email_opt_in` or a delete action are deleted rather than anonymized.

## What is still open

Anonymized analytics rows and some account ids are still joined only when an email, phone, hash, user id, trace, or the early padded account census links them. Batch deletion jobs that list several account ids and then several anonymize actions do not, by themselves, say which anonymized row belongs to which person. Those public-sample rows are why sequence accuracy is 50% even though every sample status is correct.
