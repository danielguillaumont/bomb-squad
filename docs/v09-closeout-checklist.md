# BOMB SQUAD v0.9 - Release Candidate Closeout

Status: Development release candidate, not a public release.

Branch: `feat/v09-release-candidate`

## Completed and locally verified

- [x] v0.9 release gate tests implemented.
- [x] Full .NET Release suite: 317 tests passed.
- [x] Desktop Debug build succeeded.
- [x] Desktop source inspection, pasted input, malformed input, batch analysis and comparison smoke scenarios exercised.
- [x] ZIP structural preflight implemented before extraction.
- [x] ZIP preflight synthetic regression cases: 5 passed.
- [x] Distribution manifest and extracted SHA-256 checks exercised.
- [x] Local preview ZIP launch previously verified on developer PC.
- [x] Desktop JSON export read-back verification implemented.
- [x] Desktop sample JSON export validated: 9,026 bytes, six commands, six findings and zero diagnostics.
- [x] Single-file CLI smoke scenarios: 5 passed.
- [x] Comparison CLI targeted suite: 13 tests passed.
- [x] Desktop displays "v0.9 release candidate".
- [x] Version-label change committed and pushed.

## Remaining before v0.9 milestone closeout

- [ ] Review export validation failure-path regression coverage.
- [ ] Synchronize README development status and milestone table.
- [ ] Review user-facing warnings, documentation and limitations.
- [ ] Confirm final Windows CI on the latest feature-branch commit.
- [ ] Confirm final Windows Distribution Preview CI.
- [ ] Review final distribution artifact and integrity verification.
- [ ] Review pull request from feature branch into main.
- [ ] Merge after required checks and review pass.

## Explicitly deferred / not verified

- [ ] Fresh non-administrative Windows x64 machine without SDK.
- [ ] Public installer validation.
- [ ] Code signing and publisher authentication.
- [ ] Public production release.
- [ ] End-to-end automated desktop storage failure injection.

These are not completed gates. Do not claim them as passed.

## Product and security boundaries

BOMB SQUAD performs read-only, static PowerShell analysis.
Inspected PowerShell is never executed by the application.

Only six detection rule IDs are implemented. No findings does
not establish safety. Parser failures suppress rule evaluation
for the affected input.

Comparison requires compatible snapshots with matching source
file identities. Relocated paths or edited evidence text can
change comparison results. UX simplification is future work.

Reports can include local file paths and matched source excerpts.
Review exported JSON before sharing it.

The application version is v0.9 release candidate.
Engine and rule-set identifiers remain 0.2.0-dev.
They are separate identifiers used by comparison compatibility.

## Milestone acceptance

v0.9 may close as a development release-candidate milestone
after final verification and PR review.

Do not create or advertise a public signed release or claim
clean-machine compatibility based only on development PC or CI.
