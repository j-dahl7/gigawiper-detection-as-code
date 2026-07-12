# Validation evidence ledger

This file separates observed evidence from planned or synthetic validation.

| Claim | Evidence | Status | Date |
|---|---|---|---|
| Six templates compile with Bicep | Local `az bicep build --stdout` | Passed | 2026-07-11 |
| Provider rejects a GUID beginning with a number | Live direct-Bicep canary deployment returned `Invalid rule identifier` | Observed | 2026-07-11 |
| Stable letter-prefixed ID reaches provider | Direct-Bicep deployment reached Microsoft Security provider | Observed; provider repeatedly returned an internal error during execution | 2026-07-11 |
| Preview accepts one tactic per rule | Graph API rejected a two-tactic rule with `Only one tactic is currently supported` | Observed; CI guard added | 2026-07-11 |
| Rule engine accepts corrected pack | Graph API create/read/delete round trip, then live validation deployment | Passed: five enabled rules, one disabled canary, zero response actions | 2026-07-11 |
| Native Sentinel Repository connection | Source Controls API plus generated OIDC workflow and repository commits | Connected with `CustomDetection`; deployment remains pending | 2026-07-11 |
| Native Sentinel Repository synchronization | Generated GitHub workflow | Pending; execution still returns `InvalidTemplateDeployment` after tenant activation, and Defender portal primary-workspace state remains unresolved | 2026-07-11 |
| Five rules enabled and canary disabled | Microsoft Graph custom-detection API | Passed for validation deployment; Repository ownership remains pending | 2026-07-11 |
| Disposable endpoint onboarded | MDE extension, guest verification, machine API, and `DeviceInfo` | Passed: endpoint `Onboarded` and `Active`, SENSE running, default-deny NSG | 2026-07-11 |
| Safe endpoint jobs executed | Azure managed Run Command instance views | Passed: task/registry, custom-log clear, filename-only `mc.exe`, and eight decoy renames all exited 0 | 2026-07-11 |
| Live KQL validation | Defender XDR Advanced Hunting using the exact checked-in queries | Passed for NLS-GW-001, NLS-GW-003, and NLS-GW-004 against real benign events | 2026-07-11 |
| `.candy` rename collection | Three bounded decoy runs on Windows Server 2022 | Not observed: the sensor surfaced lab directory creation but not the individual rename events; NLS-GW-005 remains synthetic-only for this validation | 2026-07-11 |
| Synthetic query fixtures | Live Advanced Hunting execution of `tests/synthetic-unit-tests.kql` | Passed: five named test rows, including recovery tampering and `.candy` aggregation | 2026-07-11 |
| Safe activity produced an alert | Defender XDR | Pending |
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
the custom lab-log clear, and the filename-only `mc.exe` execution. Three safe
`.candy` decoy variants completed locally—PowerShell rename, native `ren`, and
copy-plus-move in Public Documents—but Advanced Hunting exposed only the lab
directory creation events, not the individual file renames. The rule remains a
valid impact-stage hypothesis and is covered by synthetic KQL fixtures, but this
ledger does not label it live-validated on this endpoint.

## Evidence levels

- **Passed:** directly validated with the named tool or live platform.
- **Observed:** platform behavior captured, including an expected failure.
- **Synthetic:** query logic tested with fabricated rows only.
- **Pending:** no public claim should be made until evidence is captured.
- **Not claimed:** deliberately outside the safety or access boundary.
