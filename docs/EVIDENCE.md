# Validation evidence ledger

This file separates observed evidence from planned or synthetic validation.

| Claim | Evidence | Status | Date |
|---|---|---|---|
| Six templates compile with Bicep | Local `az bicep build --stdout` | Passed | 2026-07-11 |
| Pull-request validation | GitHub Actions draft PR #1 | Passed: six detections, endpoint Bicep, stable IDs, five fixtures, and nine safety boundaries | 2026-07-11 |
| Provider rejects a GUID beginning with a number | Live direct-Bicep canary deployment returned `Invalid rule identifier` | Observed | 2026-07-11 |
| Stable letter-prefixed ID reaches provider | Direct-Bicep deployment reached Microsoft Security provider | Observed; provider repeatedly returned an internal error during execution | 2026-07-11 |
| Preview accepts one tactic per rule | Graph API rejected a two-tactic rule with `Only one tactic is currently supported` | Observed; CI guard added | 2026-07-11 |
| Rule engine accepts corrected pack | Graph API create/read/delete round trip, then live validation deployment | Passed: five enabled rules, one disabled canary, zero response actions | 2026-07-11 |
| Native Sentinel Repository connection | Source Controls API plus generated OIDC workflow and repository commits | Connected to `main` with `CustomDetection`; Defender portal shows the correct content type | 2026-07-11 |
| Native Sentinel Repository synchronization | Generated GitHub workflow runs `29178665606` and `29180501340` | Observed preview failure: the latest run again returned `InvalidTemplateDeployment` / inner `ProviderError` for all six exact templates; the Repository connection now visibly reports `Failed` | 2026-07-12 |
| Repository identity authorization | Token-safe diagnostic using the connection identity | Passed: app-only token contained `CustomDetection.ReadWrite.All`, exact Graph GET returned 200, and Azure deployment rights were present | 2026-07-11 |
| Provider-versus-Graph isolation | Same connection identity, same rule ID | Provider validation failed internally while direct Graph authorization succeeded; current Microsoft documentation lists no additional app-only role | 2026-07-11 |
| Broad-role diagnostic | Temporary Azure Security Admin at the exact resource-group scope | Did not change the failure after a fresh login and full propagation interval; assignment removed | 2026-07-11 |
| Graph fallback canary | Manual workflow run `29180371449` | Passed: exact canary ID updated/read back, disabled, with zero response actions | 2026-07-12 |
| Graph fallback full pack | Manual workflow run `29180593038` | Passed: all six exact IDs updated/read back; canary disabled, five behavior rules enabled, and zero response actions on every rule | 2026-07-12 |
| Dedicated Graph fallback identity | Entra app-role and Azure RBAC audits plus GitHub OIDC configuration | Passed: only Graph application permission `CustomDetection.ReadWrite.All`, environment-scoped federated OIDC, no stored client secret, and zero Azure role assignments | 2026-07-12 |
| Deployment-path sequencing | GitHub Actions run order and completion timestamps | Passed: canary run `29180371449` completed, native retry `29180501340` then completed in `Failed`, and full-pack run `29180593038` began afterward; native and fallback paths were never concurrent | 2026-07-12 |
| Deployment ownership | Native failure state plus exact-ID Graph read-back | Observed: the six current rules were created or updated by the Graph fallback; the failed Repository connection does not own them | 2026-07-12 |
| Disposable endpoint onboarded | MDE extension, guest verification, machine API, and `DeviceInfo` | Passed: endpoint `Onboarded` and `Active`, SENSE running, default inbound deny with no custom inbound NSG rules | 2026-07-11 |
| Safe endpoint jobs executed | Azure managed Run Command instance views | Passed: task/registry, custom-log clear, filename-only `mc.exe`, and eight decoy renames all exited 0 | 2026-07-11 |
| Live KQL validation | Defender XDR Advanced Hunting using the exact checked-in queries | Passed for NLS-GW-001, NLS-GW-003, NLS-GW-004, and NLS-GW-005 against real benign events | 2026-07-11 |
| `.candy` rename collection | Three bounded decoy runs on Windows Server 2022 | Passed after ingestion delay: seven `FileRenamed` rows surfaced from the Public Documents copy-plus-move variant and satisfied the five-in-five-minutes threshold | 2026-07-11 |
| Synthetic query fixtures | Live Advanced Hunting execution of `tests/synthetic-unit-tests.kql` | Passed: five named test rows, including recovery tampering and `.candy` aggregation | 2026-07-11 |
| Safe activity produced a custom-rule alert | Defender XDR | Pending: no custom `NLS-GW` alert is claimed; query matches and successful rule deployment are separate evidence levels | 2026-07-12 |
| Safe filename emulator produced built-in coverage | Defender for Endpoint alert API | Passed: `System executable renamed and launched`; recorded separately and not presented as a GigaWiper or custom-rule alert | 2026-07-11 |
| Destructive behavior executed | Prohibited | Not performed |
| Built-in Microsoft GigaWiper alert reproduced | Requires malware; outside lab boundary | Not claimed |

## ID validation finding

The preview provider requires an ID that is numeric **or** starts with a letter
and then contains only letters, numbers, dashes, and underscores, up to 100
characters. A conventional GUID beginning with a number failed live provider
validation even though the Bicep compiler accepted it. The checked-in rule IDs
therefore use readable, stable `nls-gw-*` identifiers.

## Tactic validation finding

The Bicep compiler and ARM validation accepted rules with multiple tactic
objects. The live Graph rule API returned `InvalidInput` because the preview
currently accepts only one tactic per rule. The pack now keeps the primary
tactic for each rule and `Test-Lab.ps1` enforces that runtime contract.

## Repository preview provider finding

The Repository connection itself is valid: it targets `main`, selects
`CustomDetection`, creates the expected OIDC deployment workflow, and provisions
an identity with Microsoft Sentinel Contributor plus the documented Graph
application permission `CustomDetection.ReadWrite.All`. A token-safe diagnostic
confirmed that the exact identity could call the custom-detection Graph API.

Despite that, native workflow run `29178665606` failed all six resources during
three provider-validation attempts, and the later run `29180501340` again failed
all six with `InvalidTemplateDeployment` and an inner `ProviderError:
Encountered internal server error`. The Repository connection now visibly
reports **Failed**. Direct deployment of the same compiled Bicep succeeded under
the delegated user path, and a direct Graph GET retrieved the disabled canary
by stable ID. Reproducing with Bicep CLI `v0.45.6` excluded the runner's older
compiler as the cause.

A temporary Azure Security Admin assignment was used only to falsify the
missing-Azure-role hypothesis. It did not change the result after propagation
and was removed. No current Microsoft documentation requires that broad role
for the app-only custom-detection path. The evidence therefore supports a
preview Microsoft Security provider/app-only path defect, not malformed lab
content or missing documented IAM.

The bounded fallback uses a separate Graph-only application with no Azure role
assignments. Its workflow is manual, restricted to `main`, compiles the same
Bicep source, creates or updates only the six stable IDs, performs no deletion,
and verifies each rule by exact ID. Native Repository synchronization and the
fallback must not run concurrently.

Canary workflow run `29180371449` succeeded first. Full-pack workflow run
`29180593038` then updated and read back all six exact IDs: the canary remained
disabled, all five behavior rules were enabled, and every rule had zero response
actions. The dedicated identity used only the Microsoft Graph application
permission `CustomDetection.ReadWrite.All` through environment-scoped GitHub
OIDC and had zero Azure RBAC assignments. Because the Repository path failed,
it does not own these Graph-created or Graph-updated rules.

Successful deployment is not evidence of a custom alert. The safe telemetry
produced live query matches for four behavior rules, but a custom `NLS-GW` alert
remains pending and is not claimed.

## Endpoint activation finding

The MDE extension requires the protected subscription onboarding payload. The
endpoint template retrieves it through the same
`Microsoft.Security/mdeOnboardings/Windows` resource used by Microsoft's
built-in Defender policy. The extension then reported onboarding success and
the SENSE service reported a current cloud connection. During first-time
activation, the machine API initially returned `Account mode is inactive` even
though the local sensor was healthy. After activation completed, the machine
API reported the endpoint `Onboarded` and `Active`, and Advanced Hunting began
receiving `DeviceInfo`. The bounded process, registry, and file-table telemetry
then became available for live query validation.

## Sensor-fidelity finding

The Server 2022 sensor collected the scheduled-task and TaskCache correlation,
the custom lab-log clear, and the filename-only `mc.exe` execution quickly.
Small text-file renames under ProgramData initially surfaced only the directory
creation. A third safe variant copied the signed Windows `cmd.exe` eight times
to Public Documents, renamed the inert copies from `.tmp` to `.candy`, and never
executed them. Seven `FileRenamed` rows arrived after a longer ingestion delay,
and the exact NLS-GW-005 aggregation returned one seven-file match. The checked-
in harness uses this observed path and still retains synthetic fixtures.

## Evidence levels

- **Passed:** directly validated with the named tool or live platform.
- **Observed:** platform behavior captured, including an expected failure.
- **Synthetic:** query logic tested with fabricated rows only.
- **Pending:** no public claim should be made until evidence is captured.
- **Not claimed:** deliberately outside the safety or access boundary.
