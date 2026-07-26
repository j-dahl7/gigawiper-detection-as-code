# GigaWiper Detection as Code Lab

Turn Microsoft's GigaWiper threat research into reviewable Microsoft Defender
XDR custom detections, validate them without malware, and exercise the Microsoft
Sentinel Repositories custom-detection preview with a bounded Graph fallback for
the native-path result observed in this validation.

> **Safety boundary:** This lab never downloads or executes GigaWiper. It does
> not wipe disks, encrypt files, delete boot files, disable recovery, or clear
> Windows Security/System/Application logs. Destructive stages are validated
> with synthetic rows only.

For the complete live-result narrative, see the published
[case study](https://nineliveszerotrust.com/blog/gigawiper-detections-as-code/)
and its shorter [lab guide](https://nineliveszerotrust.com/labs/gigawiper-detection-as-code/).
Exact alert IDs, claim boundaries, and editorial provenance remain in the dated
[validation handoff](docs/HANDOFF-2026-07-12.md).

> **Retirement status:** Confirmed tenant-side validation artifacts were
> retired on July 14, 2026, after evidence capture. The three separately created
> LIVE rules converged to zero portal rows and direct `404` read-back while their
> historical alerts and incident were preserved. The reusable workflow remains
> checked in without authorization to the original tenant.

> **Current source-audit boundary (July 25, 2026):** the offline
> `./scripts/Test-Lab.ps1 -Json` suite passed against the current repository.
> A new read-only `Invoke-SyntheticKqlTests.ps1` attempt stopped before query
> execution because Defender returned `Account mode is inactive`. No fresh live
> rule deployment, scheduler run, endpoint telemetry run, alert, or cleanup is
> claimed by this audit. All live outcomes below remain explicitly dated
> historical evidence from July 11–14.

## What this proves

| Layer | Evidence |
|---|---|
| Source control | Stable rule IDs, exact ownership markers, CODEOWNERS, pull-request validation, and Git history |
| Bicep | Six templates compile with the Microsoft Security extension `v1.0.1` |
| Deployment | Native Repository synchronization was exercised and ended in `Failed` after provider validation returned the recorded errors; the manual Graph upsert succeeded as a bounded fallback |
| Detection | Five enabled behavior-oriented rules plus one disabled deployment canary over Defender XDR endpoint tables |
| Safe testing | Benign task/registry activity, a custom lab log clear, a filename-only MinIO simulation, and decoy `.candy` renames |
| Destructive testing | Synthetic KQL fixtures only |

## Validation-time architecture

```text
Pull request
    |
    v
GitHub Actions: Bicep compile + ID/query/safety checks
    |
    v
Merge to main (validation only)
    |
    +--> Native Sentinel Repository path (fresh connection required to retest)
    |        |
    |        +--> Fresh connection-generated workflow (review before use)
    |        |
    |        +--> July validation: FAILED before Repository ownership
    |
    +--> Manual Graph fallback (only active writer in this repository)
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
deploy it. The only active custom-detection writer checked into
`.github/workflows` is the manual Graph fallback. It is restricted to `main`,
requires an exact confirmation, and retains the stable
`nls-gigawiper-custom-detection-writer` concurrency lock.

After the July 14 retirement, the original fallback app, service principal,
federated credential, Graph grant, and GitHub environment variables were
removed. The checked-in workflow therefore has no authorization to the
validation tenant; another operator must supply a separately reviewed identity
in their own protected environment before reuse.

The connection-specific native workflow and helper used during validation are
retained under [`evidence/generated/sentinel-repository/`](evidence/generated/sentinel-repository/)
for provenance only. They contain non-secret identifiers for the original lab
and are intentionally not active or reusable. Native Sentinel Repository
synchronization remains the preferred path to retest, but a new connection in
your environment must generate a fresh workflow and helper. Review and harden
those generated files before use, and never run a native writer concurrently
with the Graph fallback. In this validation, the native path ended in
**Failed** and did not own the six rules later created or updated through the
Graph fallback. The validated runs were serialized: the canary fallback
completed, the latest native retry completed in **Failed**, and the full-pack
fallback began only after that retry ended. Serialization prevents overlap; it
does not decide which path should own the rules.

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

> **ATT&CK taxonomy compatibility:** During this validation, Microsoft custom-
> detection validation accepted the legacy `T1070.001` mapping on NLS-GW-003.
> The current MITRE ATT&CK catalog lists **Clear Windows Event Logs** as
> [`T1685.005`](https://attack.mitre.org/techniques/T1685/005/). The checked-in
> Bicep retains the provider-validated legacy value until the current mapping is
> tested against the preview provider; this is compatibility evidence, not a
> claim that `T1070.001` is the current canonical ATT&CK identifier.

## Prerequisites

- Microsoft 365 E5 or an equivalent license that includes Defender XDR.
- Microsoft Sentinel workspace onboarded to the Microsoft Defender portal and
  selected as the primary workspace. Custom detections are a primary-workspace
  capability in the current Defender portal model.
- Owner on the resource group containing the connected Sentinel workspace.
- GitHub Actions enabled for Repository smart deployments.
- Azure CLI and Bicep for local compilation and the validation-only ARM helper.
- `Az.Accounts` `5.3.3` and `Az.Resources` `9.0.3` if you use either endpoint
  lifecycle helper. The scripts explicitly import those required versions.
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
| Current source-only audit | 2026-07-25; offline suite passed, fresh Advanced Hunting attempt blocked before execution by inactive Defender account mode |
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
  cleanup (including exact custom-log source inventory), removes only its
  registry marker value, avoids recursive directory deletion, and checks native
  exit codes;
- endpoint creation composes the exact marketplace image from three numeric
  version segments, binds every deployment to a local manifest plus unique
  Azure ownership tags, and provides manifest-verified cleanup;
- the direct ARM helper performs validation only and contains no deployment
  create operation;
- the tenant-specific native files are retained outside the active workflow
  directory, no native writer remains active, and the sole active Graph writer
  remains manual, confirmation-gated, version-pinned, and refuses to update an
  existing exact ID without the repository marker or with response actions; and
- no destructive commands appear in the safe telemetry script.

To execute all ten constructed positive/negative cases through Defender's
read-only Advanced Hunting API using the current Azure CLI session:

```powershell
./scripts/Invoke-SyntheticKqlTests.ps1
```

This command submits only `datatable()` rows. It creates no endpoint activity,
rule, alert, incident, or tenant object.

This is a live, read-only API check, not part of the offline suite. On the July
25 source-audit attempt, Defender returned `Account mode is inactive` before any
query executed, so the historical July 12 ten-result pass was not refreshed.

The disposable endpoint template obtains the MDE onboarding payload at deploy
time from `Microsoft.Security/mdeOnboardings/Windows`. The protected payload is
never written to the repository, test output, or deployment outputs.

## Test the native Sentinel Repositories path

1. Fork or clone this repository into a GitHub repository you control.
2. In the Microsoft Defender portal, open **Microsoft Sentinel** > **Content
   management** > **Repositories**.
3. Create a new Repository connection for your repository and environment.
4. Select **Custom Detection Rules** as a content type.
5. Review the freshly generated workflow and helper. Before allowing a native
   write, make it manual-only, add an exact confirmation and a `main` guard, pin
   third-party actions, and serialize it with
   `nls-gigawiper-custom-detection-writer`.
6. Ensure the Graph fallback is disabled and has no active or queued writer
   run, then explicitly authorize the fresh native workflow.
7. Inspect the synchronization result before confirming rules under **Hunting**
   > **Custom detection rules**.

Do not copy or dispatch the files under
`evidence/generated/sentinel-repository/`. They were generated for the original
connection, include its environment-specific identifiers, and are retained
only to support the recorded validation result.

In this validation, the native path stopped at provider validation and the
Repository status became visibly **Failed**. It did not create or take ownership
of the six rules later created or updated through Microsoft Graph. If a future
native synchronization succeeds, treat only content actually deployed by that
connection as Repository-managed; portal changes to such managed content can be
overwritten by a later synchronization.

### Observed native Repository result — validated July 11-12, 2026

The connection-created identity held Microsoft Sentinel Contributor and the
documented Microsoft Graph application permission
`CustomDetection.ReadWrite.All`. Its app-only Graph token could read a rule by
stable ID, but native Repository validation returned
`InvalidTemplateDeployment` with an inner `ProviderError` for all six
templates. Delegated direct deployment of the same Bicep and extension reached
the provider but also returned an internal error; the separate Microsoft Graph
path accepted and read back the corrected rules. Installing current Bicep CLI
`v0.45.6` did not change the native result.

The latest native workflow run, `29180501340`, returned the same recorded errors
for all six resources, and the Repository connection ended in **Failed**. This
native-path evidence is separate from the successful manual fallback runs.

A temporary Azure **Security Admin** assignment did not change the native
deployment result after a fresh login and full propagation interval, so it was
removed. Do not add or retain Owner or Security Admin solely to troubleshoot
this result. Preserve the Repository run and tracking IDs for Microsoft Support
while the preview-path root cause remains unconfirmed.

## Manual Graph preview fallback

The fallback compiles the same six Bicep files, extracts only the custom-rule
properties, and performs an exact-ID GET followed by POST or PATCH through the
official Microsoft Graph beta custom-detection API. It then reads each stable
ID back and verifies the desired status, schedule, KQL, alert metadata, MITRE
mapping, host mapping, exact root description marker, and absence of response
actions. Before any tenant write, every desired rule must carry
`nlzt-owner:gigawiper-detection-as-code:v1` and contain no response actions. An
existing exact ID is updated only if it already carries that same marker and is
also alert-only; otherwise the script treats it as a collision and stops. Older
unmarked deployments are intentionally not auto-adopted.

This is the repository's only active custom-detection writer. Public reuse
requires your own dedicated single-tenant Entra application, federated GitHub
OIDC credential, `custom-detection-fallback` environment, and environment
variables; no identity or authorization from the original lab is reusable.
`Plan` is local and non-mutating. `Inspect` performs exact-ID reads. `Apply`
changes custom-detection objects in the tenant named by your environment and
therefore remains restricted to `main`, the protected environment, and the
exact `DEPLOY_PREVIEW_FALLBACK` confirmation.

`Inspect` requests the ownership description but does not print it; an exact ID
without the repository marker is rejected rather than reported as this lab's
rule.

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

Before the separate portal-native validation rules existed, an exact `NLS-GW`
search in the unified Defender custom-detection page returned **0 items** and
**No data available**, while exact-ID Graph read-back succeeded. A screenshot of
that historical result is captured in the published companion article. A follow-up
exact-prefix filter after portal-native validation returned exactly three rows,
all of them the separate `NLS-GW-LIVE-001`, `NLS-GW-LIVE-003`, and
`NLS-GW-LIVE-004` objects. None of the six Graph-fallback rules appeared. That
historical visibility difference remains unexplained; the evidence does not
distinguish preview replication behavior from portal authorization or UI
filtering.

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
targeted all devices and had zero automated response actions. Defender generated
the following **Custom detection** / **Microsoft Defender for Endpoint** alerts:

| Portal rule | Validation query and schedule | Live result |
|---|---|---|
| `NLS-GW-LIVE-001` (rule `152`) | Validation-revision NLS-GW-001 scheduled query; created July 12 at `09:39:42` in the portal's UTC-5 display | High-severity Persistence alert `ede0f56adf-2532-41c2-98a8-ac08a2481201_aml`, linked to incident `628` at `09:46:42`; last run `10:39:42` **Completed**, next run `11:39:42` |
| `NLS-GW-LIVE-003` (rule `153`) | Then-current exact NLS-GW-003 scheduled query; created July 12 at `09:53:08` in the portal's UTC-5 display | High-severity Defense Evasion alert `ed1f17e8f7-3600-4c97-867e-b6bd1c987c37_aml`, linked to incident `628` at `10:00:38`; last run `10:53:08` **Completed**, next run `11:53:08` |
| `NLS-GW-LIVE-004` | Then-current exact NLS-GW-004 Continuous (NRT) query; created July 12 at `12:30:02Z` | Medium-severity Exfiltration alert `eda016b9bd-4631-44d3-baa6-314b4f7ed032_aml`, linked to incident `628` at `12:33Z` |

The 001 and 003 alerts came from the documented initial scheduled evaluations
over previously generated benign endpoint telemetry; no harmful behavior was
executed to obtain them. For 004, a safe post-creation marker completed at
`12:30:45Z` with
`NetworkTransfer=False`; Defender displayed first activity as
`2026-07-11 19:47:54` and last activity as `2026-07-12 07:30:45` in the tenant's
local-time display, with the last activity matching that safe marker.

The three alert detail pages now show incident `628` at High severity with
**Active alerts 3/3**. This proves the validation-time query revisions, real
endpoint telemetry, scheduled and Continuous (NRT) evaluation, alert creation,
and incident correlation for the separate portal-native rules. The current
hardened NLS-GW-001 and NLS-GW-005 queries were separately re-run against the
retained telemetry and each returned the expected single row; no new alert is
attributed to those revisions, and the six then-live Graph-fallback objects were not
mutated during remediation. This evidence does **not**
attribute any alert or incident to the native Repository path or a
Graph-fallback object. The later read-only Graph inspection independently
established hourly scheduler execution timing for the five enabled fallback
rules, but Graph-rule alert attribution remains unestablished.

NLS-GW-005 has an explicit boundary. Its exact checked-in aggregation and a
raw-row adapter both returned live `DeviceFileEvents` data, but fresh unified
custom-detection wizards repeatedly displayed **Supported entities could not be
loaded** and left **Add assets** disabled. No portal-native 005 rule was created,
and no 005 alert is claimed. This is recorded as an observed wizard outcome with
no assigned root cause, not as evidence that aggregate custom detections or
NLS-GW-005 are unsupported. The live portal screenshots are published with the
companion [case study](https://nineliveszerotrust.com/blog/gigawiper-detections-as-code/).

## Direct Bicep validation (non-mutating)

Use this to compile the same templates and ask Azure Resource Manager to
validate them against an existing resource group:

```powershell
./scripts/Deploy-Lab.ps1 -ResourceGroup sentinel-lab-rg -IncludeCanary
```

This helper does not call `az deployment group create` and creates or updates no
custom-detection object. Raw ARM deployment is not a supported writer here
because it cannot prove ownership of an existing tenant-scoped stable ID. Use a
freshly generated and reviewed Repository workflow or the marker-verified Graph
fallback for an explicitly authorized mutation.

## Generate safe telemetry

Create the isolated endpoint if you do not already have a disposable,
MDE-onboarded Windows test device:

```powershell
Install-Module Az.Accounts -RequiredVersion 5.3.3 -Scope CurrentUser
Install-Module Az.Resources -RequiredVersion 9.0.3 -Scope CurrentUser
Import-Module Az.Accounts -RequiredVersion 5.3.3
Import-Module Az.Resources -RequiredVersion 9.0.3
Connect-AzAccount

# Inventory available exact versions, review one, and copy its full value.
az vm image list `
  --location centralus `
  --publisher MicrosoftWindowsServer `
  --offer WindowsServer `
  --sku 2022-datacenter-azure-edition `
  --all `
  --query "[].version" `
  --output tsv

$imageVersion = '<reviewed-exact-version>'

# Preview performs context, manifest, collision, and ownership reads only.
./scripts/New-LabEndpoint.ps1 `
  -ResourceGroup nls-gigawiper-dac-lab-rg `
  -VmName nls-gw-win-lab `
  -ImageVersion $imageVersion `
  -WhatIf

./scripts/New-LabEndpoint.ps1 `
  -ResourceGroup nls-gigawiper-dac-lab-rg `
  -VmName nls-gw-win-lab `
  -ImageVersion $imageVersion
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

The helper writes `.gigawiper-endpoint.json` immediately before its first Azure
creation, applies a unique deployment UUID plus exact owner tag to the resource
group and resources, and records the pinned image and returned VM identity only
after successful read-back. The raw template accepts only the exact owner marker
and constructs the image version from three nonnegative integer parameters; the
helper validates the canonical dotted form before supplying them. It will not
adopt a same-name resource group. `-ReuseOwnedLabResourceGroup` is accepted only
for an exact-owned, empty group whose manifest remains `planned`; any child
resource, completed manifest, missing or mismatched manifest, Azure ID, tag,
location, VM name, or image version stops the run. Preview cleanup and create a
fresh group after a partial or completed deployment.

Wait until the Defender machine API reports the endpoint `Onboarded` and
`Active`, and confirm `DeviceInfo` exists in Advanced Hunting, before running
the bounded telemetry.

```powershell
./scripts/Invoke-SafeGigaWiperTelemetry.ps1
```

The script creates only bounded lab artifacts:

- `HKCU\SOFTWARE\OneDrive\Environment` with an explicit lab marker (the
  equivalent `HKU\S-1-5-18` hive when a managed run executes as SYSTEM);
- a harmless scheduled task named `OneDrive Update` whose `cmd.exe /c rem`
  action performs no operation;
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
artifacts. `-WhatIf` performs those same read-only checks. Cleanup refuses a
custom log with any unexpected source and removes allowlisted files before a
non-recursive directory removal, so a newly introduced file fails closed.

## Validation levels

| Level | Meaning |
|---|---|
| Live deployment | Rule compiled, was deployed by the explicitly named path, and its exact state was read back from Defender XDR |
| Real benign telemetry | The endpoint performed the bounded action and Defender collected it |
| Synthetic query test | `datatable()` fixtures validate logic without performing the action |
| Query guidance only | Useful hunt not claimed as a deployed alert |

Synthetic query output is never presented as a Defender-generated alert. Built-in
Microsoft GigaWiper detections are not claimed as reproduced without a real
Microsoft-generated alert.

## Cleanup

1. Run the telemetry cleanup command above.
2. Remove the Repository connection when native synchronization is no longer
   required, then verify that the connection-created managed identity and its
   Microsoft Sentinel Contributor, Logic App Contributor,
   `CustomDetection.ReadWrite.All`, and branch-scoped GitHub OIDC grants are
   retired. Deselecting Custom Detection Rules only stops that content type; it
   is not identity cleanup and does not remove or transfer ownership of rules
   created through the Graph fallback.
3. Delete the six stable Graph-fallback IDs declared in `detections/*.bicep`
   from Defender XDR, or use an appropriately authorized Microsoft Graph
   cleanup workflow with `CustomDetection.ReadWrite.All`.
4. Separately delete the portal-native `NLS-GW-LIVE-001`,
   `NLS-GW-LIVE-003`, and `NLS-GW-LIVE-004` rules. They are not among the six
   Graph-fallback IDs.
5. Delete the dedicated `nls-gigawiper-custom-detection-fallback` app
   registration and remove its GitHub environment variables after the rules no
   longer require fallback management.
6. Delete the credential-less residual `nls-gigawiper-validation-20260711`
   diagnostic app registration. It has no password, certificate, or federated
   credential, but its tenant-wide Graph grants should not remain after
   validation.
7. Preview and then run manifest-verified endpoint cleanup. The helper requires
   the exact group name, the local deployment manifest, matching tenant and
   subscription, matching Azure resource-group ID, and both unique ownership
   tags before it can delete the group:

   ```powershell
   ./scripts/Remove-LabEndpoint.ps1 `
     -ConfirmResourceGroup nls-gigawiper-dac-lab-rg `
     -WhatIf

   ./scripts/Remove-LabEndpoint.ps1 `
     -ConfirmResourceGroup nls-gigawiper-dac-lab-rg
   ```

   The manifest is removed only after Azure reports the group absent. If the
   manifest is missing or any identity check differs, investigate manually;
   never replace the manifest or ownership tags merely to make cleanup proceed.

**Cleanup status (July 14, 2026):** the Repository connections and their scoped
identities/secrets were removed, the residual validation app in step 6 was
deleted, and the exact disposable endpoint resource group in step 7 was deleted
after evidence capture. The six Graph-fallback objects were then deleted by
exact ID and returned `404` on independent read-back. The three portal-native
LIVE-rule deletion dialogs were each completed through their exact Defender
detail pages. A final hard-refreshed `NLS-GW` search then returned **0 items** /
**No data available**, and direct portal-service reads for rules `151`, `152`,
and `153` each returned `404`. Exact MDE API reads confirmed that all three
historical custom alerts remained in incident `628`. The fallback app, service
principal, federated credential, Graph grant, and both GitHub environment
variables were removed only after the fallback-rule read-back.

During retirement, Graph initially returned `204` for the three numeric LIVE
rule IDs while Defender still rendered the rows, and rule `153` completed
another scheduled run at `2026-07-14T21:53:08Z`. A Disable attempt and the final
Delete confirmation also produced client-error dialogs that did not establish
the final state. None of those intermediate responses was treated as proof.
Convergence was recorded only after the zero-row portal search and three exact
`404` reads; no root cause is assigned to the delayed or contradictory
responses.
The one-time `Retire` input and retirement script were removed after use; the
reusable fallback workflow again exposes only `Inspect` and `Apply`.

Never use complete-mode resource-group deployment as a cleanup shortcut.

## Sources

- [Microsoft GigaWiper research](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
- [Deploy custom detection rules as code](https://learn.microsoft.com/en-us/azure/sentinel/ci-cd-custom-content#deploy-custom-detection-rules-as-code-preview)
- [Create a custom detection through Microsoft Graph beta](https://learn.microsoft.com/en-us/graph/api/security-rulesroot-post-detectionrules?view=graph-rest-beta)
- [Update a custom detection through Microsoft Graph beta](https://learn.microsoft.com/en-us/graph/api/security-detectionrule-update?view=graph-rest-beta)
- [Delete a custom detection through Microsoft Graph beta](https://learn.microsoft.com/en-us/graph/api/security-rulesroot-delete-detectionrules?view=graph-rest-beta)
- [Primary and secondary Sentinel workspaces in the Defender portal](https://learn.microsoft.com/en-us/azure/sentinel/workspaces-defender-portal)
- [Create custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)
- [MITRE ATT&CK: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/)

## License

MIT. Defensive use only; validate and tune every rule for your own environment.
