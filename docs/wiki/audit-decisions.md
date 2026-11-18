# Audit decisions

Recorded 2026-11-18 while implementing the auditor under `code/deletion_audit/`.

- A request is `NOT_APPLICABLE` when its text matches the keep-the-account phrases used by `case_533` through `case_542`. Other request texts in this dataset authorize deletion, including confirmations that the profile is already gone.
- Identity uses values known at or before `audit_at`. Older emails, phones, and hashes stay searchable because downstream copies can still hold them.
- Resource state comes from evidence observations at or before `audit_at`. `system_activity.csv` `reported_result` is a claim. It is used to disambiguate delete versus redact versus anonymize when the artifact does not say, and to notice the early `account_00N` profiles.
- If any replica at the latest observation time still stores a row, the row is present.
- Citations prefer an evidence package whose manifest time is at or before `audit_at` when that package proves the same conclusion as a later log export.
- When several absent account profiles match one person, the latest observation is kept. That dropped a March 404 for `account_6523` that the public sample does not attribute to the later account.
- Step order follows the operation tables in `problem_statement.md`, then `system_id`, then `resource_id`.

Related: [project state](project-state.md).
