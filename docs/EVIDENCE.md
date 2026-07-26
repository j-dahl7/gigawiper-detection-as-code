# Validation evidence ledger

This file separates observed evidence from planned or synthetic validation.

> **Current source-audit boundary (July 25, 2026):** the present repository
> passed its offline `Test-Lab.ps1 -Json` suite. A separate new read-only
> Advanced Hunting attempt returned `Account mode is inactive` before executing
> the synthetic query. It therefore produced no fresh live result. All live
> deployment, telemetry, scheduler, alert, and retirement evidence below remains
> tied to its stated July 11–14 date.

> **Post-audit hardening:** NLS-GW-001 now deduplicates only after a valid
> process/registry time correlation, and NLS-GW-005 now evaluates an optimized
> five-minute time-key window join. Both current queries were re-run read-only
> against the retained live telemetry on July 12 and returned the same expected
> one-row results (NLS-GW-005 retained `CandyFileCount=7`). The LIVE-001
> alert remains evidence for the then-checked-in query revision used by portal
> rule 152; no new alert is attributed to the hardened revision. This remediation
> was not applied to the six then-live Graph-fallback objects, so their retained
> deployment read-back remains evidence for the validation revision.

> **Public-release workflow posture:** The original connection-generated native
> workflow and helper now live under
> `evidence/generated/sentinel-repository/` with explicit non-reuse notices.
> They remain intact as connection-specific evidence but are outside
> `.github/workflows` and cannot be dispatched by GitHub Actions. The bounded,
> manual Graph fallback is the only active custom-detection writer. A native
> retest requires a new Repository connection to generate fresh files for the
> new environment.

> **Post-retirement workflow posture:** On July 14, the original validation
> tenant's fallback app, service principal, federated credential, Graph grant,
> and GitHub environment variables were removed. The checked-in fallback
> workflow remains reviewable reference code, but no longer has authorization
> to that tenant.

> **Publication posture:** The companion
> [case study](https://nineliveszerotrust.com/blog/gigawiper-detections-as-code/)
> and [lab guide](https://nineliveszerotrust.com/labs/gigawiper-detection-as-code/)
> are published. Focused production PR #340 was merged; the earlier editorial
> review PR #339 was closed without merge and is retained only as provenance.

| Claim | Evidence | Status | Date |
|---|---|---|---|
| Current repository source audit | Local `./scripts/Test-Lab.ps1 -Json` against the current tree | Passed offline: six compiled marker-owned rules and unique IDs; ten exact-query fixture contracts; pinned endpoint image, Az modules, and manifest lifecycle controls; non-mutating direct validation; Graph collision/action guards; safe telemetry ownership and cleanup controls; pinned Linux CI runner, actions, and Bicep CLI | 2026-07-25 |
| Fresh live synthetic API refresh | `./scripts/Invoke-SyntheticKqlTests.ps1` using the active read-only API path | Not executed by Defender: the API returned `Account mode is inactive` before query execution. This is not recorded as a new pass or as a KQL failure; the July 12 live synthetic result remains the latest completed run. | 2026-07-25 |
| Six templates compile with Bicep | Local `az bicep build --stdout` | Passed | 2026-07-11 |
| Pull-request validation | GitHub Actions draft PR #1 | Passed: six detections, endpoint Bicep, stable IDs, five fixtures, and nine safety boundaries | 2026-07-11 |
| Live provider validation rejected a GUID-form ID beginning with a digit | Live direct-Bicep canary deployment returned `Invalid rule identifier` | Observed | 2026-07-11 |
| Stable letter-prefixed ID reaches provider | Direct-Bicep deployment reached Microsoft Security provider | Observed; repeated deployment attempts returned the recorded internal error during execution | 2026-07-11 |
| Preview accepts one tactic per rule | Graph API rejected a two-tactic rule with `Only one tactic is currently supported` | Observed; CI guard added | 2026-07-11 |
| Rule engine accepts corrected pack | Graph API create/read/delete round trip, then live validation deployment | Passed: five enabled rules, one disabled canary, zero response actions | 2026-07-11 |
| Native Sentinel Repository connection | Source Controls API plus generated OIDC workflow and repository commits | Connected to `main` with `CustomDetection`; Defender portal shows the correct content type | 2026-07-11 |
| Native Sentinel Repository synchronization | Generated GitHub workflow runs `29178665606` and `29180501340` | Observed: the latest run returned `InvalidTemplateDeployment` / inner `ProviderError` for all six exact templates; the Repository connection reports `Failed` | 2026-07-12 |
| Repository identity authorization | Token-safe diagnostic using the connection identity | Passed: app-only token contained `CustomDetection.ReadWrite.All`, exact Graph GET returned 200, and Azure deployment rights were present | 2026-07-11 |
| Native/Graph path comparison | Same connection identity, same rule ID | Native validation returned the recorded internal error; the same identity completed an exact Graph GET; no additional app-only role was identified in the referenced documentation | 2026-07-11 |
| Additional-role diagnostic | Temporary Azure Security Admin at the exact resource-group scope | Did not change the result after a fresh login and full propagation interval; assignment removed | 2026-07-11 |
| Graph fallback canary | Manual workflow run `29180371449` | Passed: exact canary ID updated/read back, disabled, with zero response actions | 2026-07-12 |
| Graph fallback full pack | Manual workflow run `29180593038` | Passed: all six exact IDs updated/read back; canary disabled, five behavior rules enabled, and zero response actions on every rule | 2026-07-12 |
| Graph fallback scheduler inspection | Read-only workflow runs `29193356536` and `29193929962` | Observed: the post-telemetry recheck showed all five enabled rules at frequency `PT1H`, with `lastRunDateTime` `2026-07-12T13:09:25.6533333Z` and `nextRunDateTime` `2026-07-12T14:09:25.6533333Z`; last-run status and error fields were empty, the disabled canary remained disabled, and all rules had zero current `automatedActions` plus zero deprecated `responseActions` | 2026-07-12 |
| Dedicated Graph fallback identity | Entra app-role and Azure RBAC audits plus GitHub OIDC configuration | Passed: only Graph application permission `CustomDetection.ReadWrite.All`, environment-scoped federated OIDC, no stored client secret, and zero Azure role assignments | 2026-07-12 |
| Deployment-path sequencing | GitHub Actions run order and completion timestamps | Passed: canary run `29180371449` completed, native retry `29180501340` then completed in `Failed`, and full-pack run `29180593038` began afterward; native and fallback paths were never concurrent | 2026-07-12 |
| Post-audit writer serialization | Local workflow contracts plus PR validation run `29275395872` at commit `0326383` | Passed at the published PR head: both deployment workflows are manual and confirmation-gated, share the exact `nls-gigawiper-custom-detection-writer` concurrency group with `cancel-in-progress: false`, and therefore cannot execute their writer jobs concurrently | 2026-07-13 |
| Public-release active-writer posture | Repository layout plus local `Test-Lab.ps1` workflow contracts | Passed: the tenant-specific generated native files are retained outside `.github/workflows` with non-reuse notices; no active native writer remains; the manual Graph fallback is the only active custom-detection writer | 2026-07-13 |
| Graph-fallback rule retirement | Exact-ID retirement workflow runs `29368829996` and `29368996155` | Scoped result passed: the initial run preflighted all six fallback identities and received `204` for each exact delete; the follow-up run independently returned `404` for all six exact IDs. Both overall workflows failed closed because LIVE-rule GET results persisted. | 2026-07-14 |
| Portal-native deletion/convergence | Exact Graph requests, exact Defender detail-page deletion confirmations, direct portal-service read-back, a hard-refreshed rule-list search, and exact MDE alert reads | Passed after contradictory intermediate states: Graph returned `204` while the same three rows remained visible, and rule `153` still completed a scheduled run at `2026-07-14T21:53:08Z`. A Disable attempt and the final Delete confirmation produced client-error dialogs, so neither was treated as proof. Direct portal-service reads then returned `404` for rules `153`, `152`, and `151` at `22:00:33Z`, `22:01:39Z`, and `22:01:52Z`; an exact `NLS-GW` search returned **0 items** / **No data available** at `22:02:39Z`. Exact MDE API reads still returned all three historical custom alerts in incident `628`. No cause is assigned to the delayed or contradictory responses. | 2026-07-14 |
| Fallback identity retirement | Exact Entra app/service-principal audit, Azure role audit, and GitHub environment read-back | Passed after fallback-rule read-back: app and service principal absent; federated credential and `CustomDetection.ReadWrite.All` grant removed with the app; zero Azure RBAC remained; environment retained with zero variables and zero secrets | 2026-07-14 |
| Deployment ownership | Native failure state plus exact-ID Graph read-back | Observed: the six validation-time rules were created or updated by the Graph fallback; the failed Repository connection does not own them | 2026-07-12 |
| Defender portal rule-list visibility | Unified custom-detection page searched by exact `NLS-GW` prefix before and after the separate portal-native validation rules were created | Observed, cause unassigned: the historical pre-portal check returned **0 items** / **No data available**; the follow-up filter returned exactly three rows, all of them `NLS-GW-LIVE-001`, `NLS-GW-LIVE-003`, and `NLS-GW-LIVE-004`. None of the six Graph-fallback objects appeared. The later cleanup convergence is recorded separately above. | 2026-07-12 |
| Disposable endpoint onboarded | MDE extension, guest verification, machine API, and `DeviceInfo` | Passed: endpoint `Onboarded` and `Active`, SENSE running, default inbound deny with no custom inbound NSG rules | 2026-07-11 |
| Safe endpoint jobs executed | Azure managed Run Command instance views | Passed: task/registry, custom-log clear, filename-only `mc.exe`, and eight decoy renames all exited 0 | 2026-07-11 |
| Live KQL validation | Defender XDR Advanced Hunting using the exact checked-in queries | Passed for NLS-GW-001, NLS-GW-003, NLS-GW-004, and NLS-GW-005 against real benign events; a July 12 12-hour `DeviceProcessEvents` recheck returned two real `mc.exe` rows on `nls-gw-lab`, including the safe marker text, from a harness that performed no network transfer | 2026-07-12 |
| `.candy` rename collection | Three bounded decoy runs on Windows Server 2022 | Passed after ingestion delay: seven `FileRenamed` rows surfaced from the Public Documents copy-plus-move variant and satisfied the five-in-five-minutes threshold | 2026-07-11 |
| Synthetic query fixtures | Live Advanced Hunting execution of `tests/synthetic-unit-tests.kql` | Passed after audit hardening: ten named result rows, five positive and five negative, using normalized exact copies of the current compiled queries; exercises all five recovery/boot branches, both event-log branches, all four MinIO branches, a multi-process persistence regression, and a clock-boundary `.candy` burst | 2026-07-12 |
| Pre-canary custom-alert check | Defender XDR Incidents and Advanced Hunting `AlertInfo` | Observed before the portal-native canary was created: an exact `NLS-GW` incident search returned zero incidents, and a 24-hour query for `Title startswith "NLS-GW"` or `DetectionSource contains "Custom"` returned no results | 2026-07-12 |
| Portal-native scheduled NLS-GW-001 rule | Defender unified custom-detection page, rule `152` | Passed: created July 12 at `09:39:42` in the portal's UTC-5 display with the then-checked-in scheduled query; High severity, Persistence, all devices, zero automated response actions; last run `10:39:42` **Completed**, next run `11:39:42` | 2026-07-12 |
| Portal-native NLS-GW-001 alert | Defender XDR alert page | Passed: initial scheduled evaluation over previously generated benign telemetry produced **Custom detection** / **Microsoft Defender for Endpoint** alert `ede0f56adf-2532-41c2-98a8-ac08a2481201_aml`, linked to incident `628` at `09:46:42` in the portal's UTC-5 display | 2026-07-12 |
| Portal-native scheduled NLS-GW-003 rule | Defender unified custom-detection page, rule `153` | Passed: created July 12 at `09:53:08` in the portal's UTC-5 display with the exact checked-in scheduled query; High severity, Defense Evasion, all devices, zero automated response actions; last run `10:53:08` **Completed**, next run `11:53:08` | 2026-07-12 |
| Portal-native NLS-GW-003 alert | Defender XDR alert page | Passed: initial scheduled evaluation over previously generated benign telemetry produced **Custom detection** / **Microsoft Defender for Endpoint** alert `ed1f17e8f7-3600-4c97-867e-b6bd1c987c37_aml`, linked to incident `628` at `10:00:38` in the portal's UTC-5 display | 2026-07-12 |
| Portal-native NRT canary | Defender unified custom-detection page | Passed: alert-only Continuous (NRT) canary `NLS-GW-LIVE-004` was created at `12:30:02Z` with the exact NLS-GW-004 query; status **Enabled** / **Running**, all devices, and zero response actions | 2026-07-12 |
| Post-creation safe marker | Azure managed Run Command and Defender endpoint telemetry | Passed: marker completed at `12:30:45Z` with `NetworkTransfer=False` | 2026-07-12 |
| Portal-native NLS-GW-004 alert | Defender XDR alert page | Passed: at `12:33Z`, after the safe post-creation marker, Defender produced medium-severity Exfiltration **Custom detection** / **Microsoft Defender for Endpoint** alert `eda016b9bd-4631-44d3-baa6-314b4f7ed032_aml` and linked it to incident `628`; the alert's first activity predated rule creation and its last activity `2026-07-12 07:30:45` matched the marker | 2026-07-12 |
| Portal-native incident correlation | Defender XDR incident and all three alert-detail pages | Passed: incident `628` is High severity with **Active alerts 3/3**; all three alerts are **Custom detection** / **Microsoft Defender for Endpoint** and have zero automated response actions | 2026-07-12 |
| Portal-native NLS-GW-005 boundary | Advanced Hunting plus repeated fresh unified custom-detection wizards | Observed: the exact checked-in aggregation and a raw-row adapter both returned live `DeviceFileEvents` data, but the wizards repeatedly displayed `Supported entities could not be loaded` with **Add assets** disabled; no 005 portal rule or alert exists or is claimed | 2026-07-12 |
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

### ATT&CK taxonomy compatibility note

During this validation, Microsoft custom-detection validation accepted the
legacy `T1070.001` mapping used by NLS-GW-003. The current MITRE ATT&CK catalog
lists **Clear Windows Event Logs** as
[`T1685.005`](https://attack.mitre.org/techniques/T1685/005/). The checked-in
Bicep retains the provider-validated legacy value until `T1685.005` is tested
against the preview provider. This records a provider-compatibility boundary;
it does not describe `T1070.001` as the current canonical ATT&CK identifier.

## Native Repository deployment observations

The Repository connection targeted `main` and selected `CustomDetection`. Its
setup created the expected OIDC deployment workflow and provisioned an identity
with Microsoft Sentinel Contributor plus the documented Graph application
permission `CustomDetection.ReadWrite.All`. A token-safe diagnostic confirmed
that the exact identity could call the custom-detection Graph API.

Native workflow run `29178665606` failed all six resources during three
provider-validation attempts, and the later run `29180501340` returned the same
result for all six with `InvalidTemplateDeployment` and an inner `ProviderError:
Encountered internal server error`. The Repository connection now visibly
reports **Failed**. Delegated direct deployment of the same compiled Bicep also
reached the provider and returned an internal error, while a separate direct
Graph GET retrieved the disabled canary by stable ID. Reproducing with Bicep
CLI `v0.45.6` excluded the runner's older compiler as the cause.

A temporary Azure Security Admin assignment was used to test whether an
additional Azure role changed the outcome. It did not change the result after
propagation and was removed. The referenced prerequisites did not identify an
additional Azure role for this app-only path. These observations locate the
unsuccessful result at the native deployment stage after the documented
prerequisites were met; the root cause remains unconfirmed. Preserve the
Repository run and tracking IDs for Microsoft Support.

The bounded fallback uses a separate Graph-only application with no Azure role
assignments. Its workflow is manual, restricted to `main`, compiles the same
Bicep source, creates or updates only the six stable IDs, performs no deletion,
and verifies each rule by exact ID. During validation, the hardened native and
Graph revisions shared a GitHub concurrency group and did not run concurrently.
For public release, the connection-specific native files are retained outside
the active workflow directory, leaving the Graph fallback as the only active
writer. It retains the stable concurrency name so a new connection-generated
native workflow can be deliberately hardened to share it before an ownership
transition. Serialization prevents overlapping writers; it does not choose an
owner or make a queued ownership transition safe by itself.

Canary workflow run `29180371449` succeeded first. Full-pack workflow run
`29180593038` then updated and read back all six exact IDs: the canary remained
disabled, all five behavior rules were enabled, and every rule had zero response
actions. The dedicated identity used only the Microsoft Graph application
permission `CustomDetection.ReadWrite.All` through environment-scoped GitHub
OIDC and had zero Azure RBAC assignments. Because the Repository path failed,
it does not own these Graph-created or Graph-updated rules.

Read-only inspection workflow run `29193356536` later retrieved all six
validation-time Graph objects without changing them. Post-telemetry recheck run
`29193929962`
showed the five enabled behavior rules at frequency `PT1H`, with
`lastRunDateTime` `2026-07-12T13:09:25.6533333Z` and `nextRunDateTime`
`2026-07-12T14:09:25.6533333Z`; the disabled canary remained disabled. The
last-run status and error fields were empty. Both the current
`automatedActions` collection and deprecated `responseActions` collection were
empty for every rule. This establishes scheduler metadata and execution timing
for the enabled Graph-fallback rules, but it does not attribute any alert or
incident to them.

The historical exact `NLS-GW` portal filter returned zero rows before the
separate portal-native validation objects were created. A follow-up filter
returned exactly three rows: `NLS-GW-LIVE-001`, `NLS-GW-LIVE-003`, and
`NLS-GW-LIVE-004`. None of the six Graph-fallback display names or stable IDs
appeared. This keeps Graph-object portal visibility unresolved and does not
change alert attribution.

Successful deployment is not evidence of a custom alert. The safe telemetry
produced live query matches for four behavior rules. On July 12, a 12-hour
`DeviceProcessEvents` recheck returned two real `mc.exe` rows on `nls-gw-lab`,
including the safe marker text; the bounded harness performed no network
transfer. Before a separate portal-native canary was created, the exact
`NLS-GW` incident search returned zero incidents and the 24-hour `AlertInfo`
check for an `NLS-GW` title or `Custom` detection source returned no results.

## Portal-native scheduler and alert finding

Three separate alert-only rules were created manually in the Defender portal
with the then-current checked-in queries, all devices in scope, and zero
automated response actions. Scheduled rule `NLS-GW-LIVE-001` (portal rule `152`) was created July 12
at `09:39:42` in the portal's UTC-5 display. Its High-severity Persistence alert
`ede0f56adf-2532-41c2-98a8-ac08a2481201_aml` linked to incident `628` at
`09:46:42`; its last run at `10:39:42` was **Completed**, with the next run at
`11:39:42`. Scheduled rule `NLS-GW-LIVE-003` (portal rule `153`) was created at
`09:53:08`. Its High-severity Defense Evasion alert
`ed1f17e8f7-3600-4c97-867e-b6bd1c987c37_aml` linked to the same incident at
`10:00:38`; its last run at `10:53:08` was **Completed**, with the next run at
`11:53:08`.

Those two alerts resulted from the documented initial scheduled evaluations over
previously generated benign endpoint telemetry; no harmful behavior was newly
executed. Separately, the Continuous (NRT) rule `NLS-GW-LIVE-004` was
created at `12:30:02Z`. A safe post-creation marker completed at `12:30:45Z`
with `NetworkTransfer=False`; at `12:33Z`, Defender generated medium-severity
Exfiltration alert `eda016b9bd-4631-44d3-baa6-314b4f7ed032_aml`. The tenant-local
display showed first activity `2026-07-11 19:47:54`, which predated rule
creation, and last activity `2026-07-12 07:30:45`, which matched the safe
marker. This establishes that the NRT alert incorporated a post-rule event; it
does not establish that the marker was the alert's sole cause.

All three are **Custom detection** / **Microsoft Defender for Endpoint** alerts,
and all three alert detail pages now show incident `628` at High severity with
**Active alerts 3/3**. This proves the validation-time query revisions, real
endpoint telemetry, scheduled and Continuous (NRT) evaluation, alert creation,
and incident correlation for the separate portal-native rules. It does not
attribute an alert or incident to the native Repository path or a Graph-fallback
object.
Read-only Graph inspection independently established hourly scheduler execution
timing for the five enabled fallback rules, but Graph-rule alert attribution
remains unestablished.

NLS-GW-005 remains an explicit boundary. Its exact checked-in aggregation and a
raw-row adapter both returned live `DeviceFileEvents` data, but repeated fresh
unified custom-detection wizards displayed `Supported entities could not be
loaded` and left **Add assets** disabled. No 005 portal rule was created, and no
005 alert exists or is claimed. This is recorded as an observed wizard outcome
with no assigned root cause, not as evidence that aggregate custom detections or
NLS-GW-005 are unsupported. Screenshots of the live portal evidence are
published with the companion case study linked above.

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

## Post-validation cleanup

Read-only inventory on July 14, 2026 confirmed zero Sentinel Repository
connections, zero matching connection-created identities or service principals,
zero matching role assignments, zero connection secrets, and zero active
generated runs. The credential-less `nls-gigawiper-validation-20260711`
diagnostic application and service principal were then deleted, and the exact
24-resource disposable endpoint resource group was deleted after evidence
capture. Generated PR #6 was closed, only its generated side branch was deleted,
and the two stale generated workflow registrations were disabled after their
exact bot commits were recorded in the local native-retest support package.

Later on July 14, the six Graph-fallback objects were deleted by exact ID and
independently returned `404`. The three portal-native rules were separately
submitted for deletion through their exact Defender detail pages. Graph's
earlier `204` responses were not accepted as portal proof because the rows
remained visible and rule `153` completed another scheduled run at
`2026-07-14T21:53:08Z`. A Disable attempt returned `Client Error` / `Error
enabling rules`, and the final Delete confirmation returned `Client Error` /
`Error deleting detection rules`; neither error was treated as evidence of
success or failure. Direct portal-service reads subsequently returned `404` for
rules `153`, `152`, and `151`, and a hard-refreshed exact `NLS-GW` search returned
**0 items** / **No data available**. Exact MDE API reads confirmed that all three
historical custom alerts and incident `628` remained retained evidence. The
fallback application, service principal, OIDC credential, Graph grant, and
GitHub environment variables were removed only after fallback-rule read-back.

The protected three-file canary evidence branch remains. This cleanup does not
change any evidence level or attribute alerts to the Graph or native paths.
The one-time `Retire` workflow input and retirement script were removed after
use; the reusable fallback workflow again exposes only `Inspect` and `Apply`.

## Evidence levels

- **Passed:** directly validated with the named tool or live platform.
- **Observed:** platform behavior captured, including a recorded failure state.
- **Synthetic:** query logic tested with constructed rows only.
- **Pending:** no public claim should be made until evidence is captured.
- **Not claimed:** deliberately outside the safety or access boundary.
