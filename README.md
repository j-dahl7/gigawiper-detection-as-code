# GigaWiper Detection as Code Lab

Turn Microsoft's GigaWiper threat research into reviewable Microsoft Defender
XDR custom detections, validate them without malware, and deploy them through
the new Microsoft Sentinel Repositories custom-detection path.

> **Safety boundary:** This lab never downloads or executes GigaWiper. It does
> not wipe disks, encrypt files, delete boot files, disable recovery, or clear
> Windows Security/System/Application logs. Destructive stages are validated
> with synthetic rows only.

## What this proves

| Layer | Evidence |
|---|---|
| Source control | Stable rule IDs, CODEOWNERS, pull-request validation, and Git history |
| Bicep | Six templates compile with the Microsoft Security extension `v1.0.1` |
| Deployment | Native Repository sync is the production path; direct Bicep is an explicit alternative |
| Detection | Five behavior-oriented rules over Defender XDR endpoint tables |
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
Merge to main
    |
    v
Microsoft Sentinel Repository synchronization (Preview)
    |
    v
Microsoft Defender XDR custom detection rules
    |
    +--> safe endpoint telemetry
    +--> alerts and incident correlation
```

GitHub Actions validates content but does not deploy it. Microsoft Sentinel
Repositories remains the single production deployment path after merge. This
avoids competing deployment systems and duplicate ownership.

## Detection pack

| ID | Rule | Design | Stage |
|---|---|---|---|
| `nls-gw-001-onedrive-persistence` | OneDrive-lookalike task plus registry activity | Multi-table scheduled correlation | Persistence |
| `nls-gw-002-recovery-boot-tampering` | Recovery and boot command patterns | Single-table scheduled rule | Destructive preparation |
| `nls-gw-003-event-log-destruction` | `wevtutil` log clearing | Single-table scheduled rule | Defense evasion |
| `nls-gw-004-minio-transfer-staging` | Unusual `mc.exe` transfer arguments | Single-table scheduled rule | Exfiltration staging |
| `nls-gw-005-candy-rename-burst` | Burst of `.candy` file renames | Single-table aggregation | Impact confirmation |

`NLS-GW-000` is a disabled deployment canary. It cannot match ordinary tenant
activity and is excluded from production screenshots unless explicitly needed.

## Prerequisites

- Microsoft 365 E5 or an equivalent license that includes Defender XDR.
- Microsoft Sentinel workspace onboarded to the Microsoft Defender portal and
  selected as the primary workspace. Custom detections are a primary-workspace
  capability in the current Defender portal model.
- Owner on the resource group containing the connected Sentinel workspace.
- GitHub Actions enabled for Repository smart deployments.
- Azure CLI and Bicep for local validation or the direct deployment path.
- A disposable Windows endpoint onboarded to Microsoft Defender for Endpoint
  for live benign telemetry validation.

Before endpoint testing, confirm the Defender for Endpoint tenant is active,
not merely licensed. A sensor can report local onboarding success while the API
still returns `Account mode is inactive`; Microsoft documents that first-time
Defender for Cloud integration can take up to 12 hours.

The capability is preview. This repository was built against:

| Component | Version/date |
|---|---|
| Documentation validation date | 2026-07-11 |
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
- every query returns `Timestamp`, `DeviceId`, and `ReportId`;
- each preview rule declares no more than one MITRE tactic;
- automated response actions are absent;
- no destructive commands appear in the safe telemetry script.

The disposable endpoint template obtains the MDE onboarding payload at deploy
time from `Microsoft.Security/mdeOnboardings/Windows`. The protected payload is
never written to the repository, test output, or deployment outputs.

## Deploy with Sentinel Repositories

1. Fork or clone this repository into a GitHub repository you control.
2. In the Microsoft Defender portal, open **Microsoft Sentinel** > **Content
   management** > **Repositories**.
3. Create or edit the Repository connection.
4. Select **Custom Detection Rules** as a content type.
5. Point the connection at this repository and merge a validated pull request.
6. Confirm the rules under **Hunting** > **Custom detection rules**.

Repository synchronization is authoritative. Portal changes to managed content
can be overwritten by the next synchronization.

## Direct Bicep alternative

Use this only when Repository synchronization is not the desired owner:

```powershell
./scripts/Deploy-Lab.ps1 -ResourceGroup sentinel-lab-rg -IncludeCanary
```

Do not run direct Bicep deployment and Repository synchronization against the
same rule IDs at the same time.

## Generate safe telemetry

```powershell
./scripts/Invoke-SafeGigaWiperTelemetry.ps1
```

The script creates only bounded lab artifacts:

- `HKCU\SOFTWARE\OneDrive\Environment` with an explicit lab marker;
- a harmless scheduled task named `OneDrive Update` whose action exits;
- a custom `NLS-GigaWiper-Lab` event log, then clears only that custom log;
- a copy of `cmd.exe` named `mc.exe` that only prints a simulation marker;
- eight text decoys renamed to `.candy` without encryption.

Cleanup is exact-scope:

```powershell
./scripts/Invoke-SafeGigaWiperTelemetry.ps1 -CleanupOnly
```

## Validation levels

| Level | Meaning |
|---|---|
| Live deployment | Rule compiled, synchronized/deployed, and appeared in Defender XDR |
| Real benign telemetry | The endpoint performed the bounded action and Defender collected it |
| Synthetic query test | `datatable()` fixtures validate logic without performing the action |
| Query guidance only | Useful hunt not claimed as a deployed alert |

Synthetic query output is never presented as a genuine Defender alert. Built-in
Microsoft GigaWiper detections are not claimed as reproduced without a real
Microsoft-generated alert.

## Cleanup

1. Run the telemetry cleanup command above.
2. Remove the Repository connection or deselect Custom Detection Rules if the
   repository should no longer own the rules.
3. Delete the five `NLS-GW-*` rules from Defender XDR, or use an appropriately
   authorized Microsoft Graph cleanup workflow with
   `CustomDetection.ReadWrite.All`.
4. Delete only the disposable Azure resource group created for endpoint testing.

Never use complete-mode resource-group deployment as a cleanup shortcut.

## Sources

- [Microsoft GigaWiper research](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
- [Deploy custom detection rules as code](https://learn.microsoft.com/en-us/azure/sentinel/ci-cd-custom-content#deploy-custom-detection-rules-as-code-preview)
- [Create custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)

## License

MIT. Defensive use only; validate and tune every rule for your own environment.
