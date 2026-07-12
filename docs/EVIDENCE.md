# Validation evidence ledger

This file separates observed evidence from planned or synthetic validation.

| Claim | Evidence | Status | Date |
|---|---|---|---|
| Six templates compile with Bicep | Local `az bicep build --stdout` | Passed | 2026-07-11 |
| Provider rejects a GUID beginning with a number | Live direct-Bicep canary deployment returned `Invalid rule identifier` | Observed | 2026-07-11 |
| Stable letter-prefixed ID reaches provider | Direct-Bicep deployment reached Microsoft Security provider | Observed; provider repeatedly returned an internal error during execution | 2026-07-11 |
| Preview accepts one tactic per rule | Graph API rejected a two-tactic rule with `Only one tactic is currently supported` | Observed; CI guard added | 2026-07-11 |
| Rule engine accepts corrected pack | Graph API create/read/delete round trip | Passed: five enabled rules, one disabled canary, zero response actions; temporary copies removed | 2026-07-11 |
| Native Sentinel Repository connection | Source Controls API plus generated OIDC workflow and repository commits | Connected with `CustomDetection`; deployment remains pending | 2026-07-11 |
| Native Sentinel Repository synchronization | Generated GitHub workflow | Pending; execution returns `InvalidTemplateDeployment` while tenant endpoint account is inactive | 2026-07-11 |
| Five rules visible and enabled | Defender portal | Pending after Repository-owned deployment |
| Disposable endpoint onboarded | MDE extension instance view plus guest verification | Passed: protected package success, SENSE running, onboarding state 1, default-deny NSG | 2026-07-11 |
| Safe endpoint events collected | Disposable MDE endpoint | Pending |
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
the SENSE service reported a current cloud connection. The tenant-level machine
API still returned `Account mode is inactive`, so endpoint-table and alert
claims remain pending until the Defender for Endpoint service finishes
first-time activation.

## Evidence levels

- **Passed:** directly validated with the named tool or live platform.
- **Observed:** platform behavior captured, including an expected failure.
- **Synthetic:** query logic tested with fabricated rows only.
- **Pending:** no public claim should be made until evidence is captured.
- **Not claimed:** deliberately outside the safety or access boundary.
