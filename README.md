# GigaWiper Detection as Code Lab

Turn Microsoft's GigaWiper threat research into reviewable Microsoft Defender
XDR custom detections, validate them without malware, and exercise the new
Microsoft Sentinel Repositories custom-detection path with an honest preview
fallback when the provider fails.

> **Safety boundary:** This lab never downloads or executes GigaWiper. It does
> not wipe disks, encrypt files, delete boot files, disable recovery, or clear
> Windows Security/System/Application logs. Destructive stages are validated
> with synthetic rows only.

For the complete live-result narrative, exact alert IDs, claim boundaries, and
editorial notes, see the dated
[validation handoff](docs/HANDOFF-2026-07-12.md).

## What this proves

| Layer | Evidence |
|---|---|
| Source control | Stable rule IDs, CODEOWNERS, pull-request validation, and Git history |
| Bicep | Six templates compile with the Microsoft Security extension `v1.0.1` |
| Deployment | Native Repository sync was exercised and failed in the preview provider; the manual Graph upsert succeeded as a bounded fallback |
| Detection | Five enabled behavior-oriented rules plus one disabled deployment canary over Defender XDR endpoint tables |
| Safe testing | Benign task/registry activity, a custom lab log clear, a filename-only MinIO simulation, and decoy `.candy` renames |
| Destructive testing | Synthetic KQL fixtures only |

## Architecture

```text
Pull request
    |
    v
GitHub Actions: Bicep compile + ID/query/safety checks
    |
    v
Merge to main (validation only)
    |
    +--> Manual native Sentinel Repository retry (Preview; exact confirmation)
    |        |
    |        +--> FAILED: provider error before Repository ownership
    |
    +--> Manual Graph fallback (shared cross-workflow writer lock)
             |
             v
         GitHub OIDC --> exact-ID create/update + read-back
             |
             v
         Defender XDR: five enabled rules + disabled canary
             |
             +--> safe endpoint telemetry
             +--> hourly scheduler runs observed
             +--> Graph-rule alert attribution not established
```

The ordinary pull-request and `main` workflows validate content but do not
deploy it. The generated native workflow has been safety-overridden to require
a manual dispatch and the exact confirmation `DEPLOY_NATIVE_SENTINEL_CONTENT`.
Native Sentinel Repository synchronization is the preferred path to retest
after the unresolved preview-path failure is understood and addressed, but it
failed here and does not own the six rules created or updated by the Graph
fallback. The Graph workflow is also manual-only, restricted to `main`, requires
its own exact confirmation
string, and exists solely because the native preview path returned a failed
deployment in this tenant.
The native and Graph workflows now share the
`nls-gigawiper-custom-detection-writer` concurrency group, so GitHub cannot run
the two writer jobs simultaneously. The validated runs were also serialized:
the canary fallback completed, the latest native retry then completed in
**Failed**, and the full-pack fallback began only
after that retry ended. The paths were never concurrent. Keep that separation
when retesting; the lock prevents overlap, but it does not decide which path
should own the rules.

## Detection pack

| ID | Rule | Design | Stage | Validated status |
|---|---|---|---|---|
| `nls-gw-000-canary` | Impossible-match deployment canary | Single-table scheduled rule | Deployment validation | Disabled |
| `nls-gw-001-onedrive-persistence` | OneDrive-lookalike task plus registry activity | Multi-table scheduled correlation | Persistence | Enabled |
| `nls-gw-002-recovery-boot-tampering` | Recovery and boot command patterns | Single-table scheduled rule | Destructive preparation | Enabled |
| `nls-gw-003-event-log-destruction` | `wevtutil` log clearing | Single-table scheduled rule | Defense evasion | Enabled |
| `nls-gw-004-minio-transfer-staging` | Unusual `mc.exe` transfer arguments | Single-table scheduled rule | Exfiltration staging | Enabled |
| `nls-gw-005-candy-rename-burst` | Five `.candy` renames within any five-minute window | Optimized time-key window join | Impact-stage signal | Enabled |

All six exact IDs were read back after the successful fallback deployment.
Every rule had zero automated response actions; the canary remained disabled.

## Prerequisites

- Microsoft 365 E5 or an equivalent license that includes Defender XDR.
- Microsoft Sentinel workspace onboarded to the Microsoft Defender portal and
  selected as the primary workspace. Custom detections are a primary-workspace
  capability in the current Defender portal model.
- Owner on the resource group containing the connected Sentinel workspace.
- GitHub Actions enabled for Repository smart deployments.
- Azure CLI and Bicep for local validation or the direct deployment path.
- `Az.Accounts` and `Az.Resources` if you use the endpoint deployment helper.
- A disposable Windows endpoint onboarded to Microsoft Defender for Endpoint
  for live benign telemetry validation.

Before endpoint testing, confirm the Defender for Endpoint tenant is active,
not merely licensed. A sensor can report local onboarding success while the API
still returns `Account mode is inactive`; Microsoft documents that first-time
Defender for Cloud integration can take up to 12 hours.

The capability is preview. This repository was built against:

| Component | Version/date |
|---|---|
| Documentation and live validation dates | 2026-07-11 through 2026-07-12 |
| Resource API | `2026-06-01-preview` |
| Microsoft Security Bicep extension | `v1.0.1` |
| Portal | Microsoft Defender portal |

## Validate locally

```powershell
./scripts/Test-Lab.ps1
```

The test compiles every Bicep file and verifies:

- stable IDs begin with a letter and stay within the provider's character rules;
- IDs and display names are unique;
- every compiled query's final projection returns `Timestamp`, `DeviceId`, and `ReportId`;
- each preview rule declares no more than one MITRE tactic;
- compiled `detectionAction` objects contain neither current
  `automatedActions` nor deprecated `responseActions` keys;
- all five behavior rules are copied exactly into positive and negative
  synthetic fixture contracts, including every recovery, log-clear, and MinIO
  command branch;
- NLS-GW-005 retains an exact five-minute sliding window through bounded
  `range()` / `mv-expand` time keys instead of a device-wide cross join;
- safe telemetry generation refuses collisions, validates ownership before
  cleanup, removes only its registry marker value, and checks native exit codes;
- native and fallback writers are manual, mutually serialized, version-pinned,
  and refuse to update an existing Graph rule that has response actions; and
- no destructive commands appear in the safe telemetry script.

To execute all ten fabricated positive/negative cases through Defender's
read-only Advanced Hunting API using the current Azure CLI session:

```powershell
./scripts/Invoke-SyntheticKqlTests.ps1
```

This command submits only `datatable()` rows. It creates no endpoint activity,
rule, alert, incident, or tenant object.

The disposable endpoint template obtains the MDE onboarding payload at deploy
time from `Microsoft.Security/mdeOnboardings/Windows`. The protected payload is
never written to the repository, test output, or deployment outputs.

## Test the native Sentinel Repositories path

1. Fork or clone this repository into a GitHub repository you control.
2. In the Microsoft Defender portal, open **Microsoft Sentinel** > **Content
   management** > **Repositories**.
3. Create or edit the Repository connection.
4. Select **Custom Detection Rules** as a content type.
5. Disable the Graph fallback, then manually dispatch the generated native
   workflow from `main` with `DEPLOY_NATIVE_SENTINEL_CONTENT`.
6. Inspect the synchronization result before confirming rules under **Hunting**
   > **Custom detection rules**.

In this validation, the native path stopped at provider validation and the
Repository status became visibly **Failed**. It did not create or take ownership
of the six rules later created or updated through Microsoft Graph. If a future
native synchronization succeeds, treat only content actually deployed by that
connection as Repository-managed; portal changes to such managed content can be
overwritten by a later synchronization.

### Preview provider finding — validated July 11-12, 2026

The connection-created identity held Microsoft Sentinel Contributor and the
documented Microsoft Graph application permission
`CustomDetection.ReadWrite.All`. Its app-only Graph token could read a rule by
stable ID, but native Repository validation returned
`InvalidTemplateDeployment` with an inner `ProviderError` for all six
templates. Delegated direct deployment of the same Bicep and extension reached
the provider but also returned an internal error; the separate Microsoft Graph
path accepted and read back the corrected rules. Installing current Bicep CLI
`v0.45.6` did not change the native result.

The latest native workflow run, `29180501340`, again failed all six resources,
and the Repository connection surfaced the final **Failed** state. This is the
native-path evidence; it is separate from the successful manual fallback runs.

Adding Azure **Security Admin** did not fix the provider after a fresh login
and a full propagation interval, so that diagnostic assignment was removed.
Do not grant Owner or Security Admin as a workaround. Preserve the Repository
run and tracking IDs for Microsoft support, then choose one bounded alternative
while the preview-path root cause remains unresolved.

## Manual Graph preview fallback

The fallback compiles the same six Bicep files, extracts only the custom-rule
properties, and performs an exact-ID GET followed by POST or PATCH through the
official Microsoft Graph beta custom-detection API. It then reads each stable
ID back and verifies the desired status, schedule, KQL, alert metadata, MITRE
mapping, host mapping, and absence of response actions.

Live validation completed in two manual runs: canary run `29180371449` passed,
then full-pack run `29180593038` updated and read back all six exact IDs. The
canary was disabled, the five behavior rules were enabled, and all six rules
had zero automated response actions. These are Graph-created or Graph-updated
rules; the failed Repository connection does not own them. No custom alert is
attributed to those Graph-fallback objects.

Read-only inspection workflow run `29193356536` then retrieved the six stable
Graph IDs without changing them. A post-telemetry recheck in run `29193929962`
showed the five enabled behavior rules at frequency `PT1H`, with
`lastRunDateTime` `2026-07-12T13:09:25.6533333Z` and `nextRunDateTime`
`2026-07-12T14:09:25.6533333Z`; the disabled canary remained disabled. The current
`automatedActions` collection and the deprecated `responseActions` collection
were both empty for every rule. The last-run status and error fields were also
empty. This establishes Graph scheduler metadata and execution timing, but it
does not attribute a particular alert or incident to a Graph-fallback rule.

Before the separate portal-native validation rules existed, the unified
Defender custom-detection page did not surface the six Graph-fallback objects
even though exact-ID Graph read-back succeeded. An exact `NLS-GW` search
returned **0 items** and **No data available**; a screenshot of that historical
result is captured in the companion site draft. A follow-up exact-prefix filter
after portal-native validation returned exactly three rows, all of them the
separate `NLS-GW-LIVE-001`, `NLS-GW-LIVE-003`, and `NLS-GW-LIVE-004` objects.
None of the six Graph-fallback rules appeared. Their portal-list visibility
therefore remains pending, and the evidence does not yet distinguish preview
replication behavior from portal authorization or UI filtering.

Before the separate portal-native canary was created on July 12, an exact
`NLS-GW` incident search found zero incidents and a 24-hour Advanced Hunting
`AlertInfo` query for titles beginning with `NLS-GW` or a detection source
containing `Custom` returned no results. Separately, a
12-hour `DeviceProcessEvents` query returned two real `mc.exe` rows from
`nls-gw-lab`, including the safe marker text. The bounded harness performed no
network transfer. Those rows prove endpoint telemetry and query matching only;
at that point they were not evidence of a custom alert.

The included GitHub workflow uses:

- a dedicated Entra application with only the application permission
  `CustomDetection.ReadWrite.All`;
- GitHub OIDC instead of a client secret;
- no Azure subscription role;
- the `custom-detection-fallback` environment, restricted to `main`;
- manual dispatch plus the exact confirmation `DEPLOY_PREVIEW_FALLBACK`;
- no delete, prune, or adoption of a conflicting rule with another stable ID.

Plan locally without obtaining a token or changing the tenant:

```powershell
./scripts/Deploy-CustomDetectionsGraph.ps1 -Mode Plan -Scope All
```

To apply, manually run **Deploy custom detections - preview fallback** from the
default branch. Start with `Canary`, confirm its disabled state, and then run
`All`. Disable this fallback when native Repository synchronization succeeds.

The Graph endpoint is tenant-scoped and beta. This fallback is suitable for
this Defender XDR `Device*`-table pack; it is not presented as a general
replacement for workspace-scoped Sentinel content.

See [the fallback identity and environment setup](docs/GRAPH-FALLBACK.md) when
forking the lab into another tenant.

## Portal-native alert validation

To validate the live rule engine independently of both preview deployment
paths, three separate alert-only rules were created manually in the Defender
portal with the exact repository queries current at validation time. All three
targeted all devices, had zero automated response actions, and produced genuine
**Custom detection** / **Microsoft Defender for Endpoint** alerts:

| Portal rule | Validation query and schedule | Live result |
|---|---|---|
| `NLS-GW-LIVE-001` (rule `152`) | Validation-revision NLS-GW-001 scheduled query; created July 12 at `09:39:42` in the portal's UTC-5 display | High-severity Persistence alert `ede0f56adf-2532-41c2-98a8-ac08a2481201_aml`, linked to incident `628` at `09:46:42`; last run `10:39:42` **Completed**, next run `11:39:42` |
| `NLS-GW-LIVE-003` (rule `153`) | Then-current exact NLS-GW-003 scheduled query; created July 12 at `09:53:08` in the portal's UTC-5 display | High-severity Defense Evasion alert `ed1f17e8f7-3600-4c97-867e-b6bd1c987c37_aml`, linked to incident `628` at `10:00:38`; last run `10:53:08` **Completed**, next run `11:53:08` |
| `NLS-GW-LIVE-004` | Then-current exact NLS-GW-004 Continuous (NRT) query; created July 12 at `12:30:02Z` | Medium-severity Exfiltration alert `eda016b9bd-4631-44d3-baa6-314b4f7ed032_aml`, linked to incident `628` at `12:33Z` |

The 001 and 003 alerts came from genuine initial scheduled evaluations over the
previously generated benign endpoint telemetry. They were not fabricated
alerts and no new harmful behavior was executed to produce them. For 004, a
safe post-creation marker completed at `12:30:45Z` with
`NetworkTransfer=False`; Defender displayed first activity as
`2026-07-11 19:47:54` and last activity as `2026-07-12 07:30:45` in the tenant's
local-time display, with the last activity matching that safe marker.

The three alert detail pages now show incident `628` at High severity with
**Active alerts 3/3**. This proves the validation-time query revisions, real
endpoint telemetry, scheduled and Continuous (NRT) evaluation, alert creation,
and incident correlation for the separate portal-native rules. The current
hardened NLS-GW-001 and NLS-GW-005 queries were separately re-run against the
retained telemetry and each returned the expected single row; no new alert is
attributed to those revisions, and the six live Graph-fallback objects were not
mutated during remediation. This evidence does **not**
attribute any alert or incident to the native Repository path or a
Graph-fallback object. The later read-only Graph inspection independently
established hourly scheduler execution timing for the five enabled fallback
rules, but Graph-rule alert attribution remains unestablished.

NLS-GW-005 has an explicit boundary. Its exact checked-in aggregation and a
raw-row adapter both returned live `DeviceFileEvents` data, but fresh unified
custom-detection wizards repeatedly displayed **Supported entities could not be
loaded** and left **Add assets** disabled. No portal-native 005 rule was created,
and no 005 alert is claimed. This is an observed portal/session failure with no
assigned root cause, not proof that aggregate custom detections or NLS-GW-005
are unsupported. The live portal screenshots are stored with the companion blog
draft.

## Direct Bicep alternative

Use this only when Repository synchronization is not the desired owner:

```powershell
./scripts/Deploy-Lab.ps1 -ResourceGroup sentinel-lab-rg -IncludeCanary
```

Do not run direct Bicep deployment and Repository synchronization against the
same rule IDs at the same time.

## Generate safe telemetry

Create the isolated endpoint if you do not already have a disposable,
MDE-onboarded Windows test device:

```powershell
Connect-AzAccount
./scripts/New-LabEndpoint.ps1 `
  -ResourceGroup nls-gigawiper-dac-lab-rg `
  -VmName nls-gw-win-lab
```

The template creates no custom inbound NSG rules. Use Azure Run Command instead
of opening RDP if you want to invoke the harness remotely:

```powershell
$safeScript = Get-Content -Raw ./scripts/Invoke-SafeGigaWiperTelemetry.ps1
az vm run-command invoke `
  --resource-group nls-gigawiper-dac-lab-rg `
  --name nls-gw-win-lab `
  --command-id RunPowerShellScript `
  --scripts $safeScript
```

Wait until the Defender machine API reports the endpoint `Onboarded` and
`Active`, and confirm `DeviceInfo` exists in Advanced Hunting, before running
the bounded telemetry.

```powershell
./scripts/Invoke-SafeGigaWiperTelemetry.ps1
```

The script creates only bounded lab artifacts:

- `HKCU\SOFTWARE\OneDrive\Environment` with an explicit lab marker (the
  equivalent `HKU\S-1-5-18` hive when a managed run executes as SYSTEM);
- a harmless scheduled task named `OneDrive Update` whose action exits;
- a custom `NLS-GigaWiper-Lab` event log, then clears only that custom log;
- a copy of `cmd.exe` named `mc.exe` that only prints a simulation marker;
- eight harmless copies of the signed Windows `cmd.exe` renamed from `.tmp` to
  `.candy` without execution or encryption; this path produced observable
  `FileRenamed` telemetry on the validated Server 2022 endpoint.

Cleanup is exact-scope:

```powershell
./scripts/Invoke-SafeGigaWiperTelemetry.ps1 -CleanupOnly
```

Cleanup first validates every task, event-log, directory, and marker ownership
signal, then removes only the exact registry marker value and owned lab
artifacts. It refuses same-name objects with unrecognized content.

## Validation levels

| Level | Meaning |
|---|---|
| Live deployment | Rule compiled, was deployed by the explicitly named path, and its exact state was read back from Defender XDR |
| Real benign telemetry | The endpoint performed the bounded action and Defender collected it |
| Synthetic query test | `datatable()` fixtures validate logic without performing the action |
| Query guidance only | Useful hunt not claimed as a deployed alert |

Synthetic query output is never presented as a genuine Defender alert. Built-in
Microsoft GigaWiper detections are not claimed as reproduced without a real
Microsoft-generated alert.

## Cleanup

1. Run the telemetry cleanup command above.
2. Remove the Repository connection or deselect Custom Detection Rules if it
   should no longer attempt native synchronization. This does not remove or
   transfer ownership of rules created through the Graph fallback.
3. Delete the six stable Graph-fallback IDs declared in `detections/*.bicep`
   from Defender XDR, or use an appropriately authorized Microsoft Graph
   cleanup workflow with `CustomDetection.ReadWrite.All`.
4. Separately delete the portal-native `NLS-GW-LIVE-001`,
   `NLS-GW-LIVE-003`, and `NLS-GW-LIVE-004` rules. They are not among the six
   Graph-fallback IDs.
5. Delete the dedicated `nls-gigawiper-custom-detection-fallback` app
   registration and remove its GitHub environment variables after the rules no
   longer require fallback management.
6. Delete the dormant `nls-gigawiper-validation-20260711` diagnostic app
   registration. It has no credential, but its tenant-wide Graph grants should
   not remain after validation.
7. Delete only the disposable Azure resource group created for endpoint testing.

Never use complete-mode resource-group deployment as a cleanup shortcut.

## Sources

- [Microsoft GigaWiper research](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
- [Deploy custom detection rules as code](https://learn.microsoft.com/en-us/azure/sentinel/ci-cd-custom-content#deploy-custom-detection-rules-as-code-preview)
- [Create a custom detection through Microsoft Graph beta](https://learn.microsoft.com/en-us/graph/api/security-rulesroot-post-detectionrules?view=graph-rest-beta)
- [Update a custom detection through Microsoft Graph beta](https://learn.microsoft.com/en-us/graph/api/security-detectionrule-update?view=graph-rest-beta)
- [Primary and secondary Sentinel workspaces in the Defender portal](https://learn.microsoft.com/en-us/azure/sentinel/workspaces-defender-portal)
- [Create custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)

## License

MIT. Defensive use only; validate and tune every rule for your own environment.
