# Validation evidence ledger

This file separates observed evidence from planned or synthetic validation.

| Claim | Evidence | Status | Date |
|---|---|---|---|
| Six templates compile with Bicep | Local `az bicep build --stdout` | Passed | 2026-07-11 |
| Provider rejects a GUID beginning with a number | Live direct-Bicep canary deployment returned `Invalid rule identifier` | Observed | 2026-07-11 |
| Stable letter-prefixed ID reaches provider | Direct-Bicep deployment reached Microsoft Security provider | Observed; provider returned transient internal error | 2026-07-11 |
| Native Sentinel Repository synchronization | Defender portal | Pending |
| Five rules visible and enabled | Defender portal | Pending |
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

## Evidence levels

- **Passed:** directly validated with the named tool or live platform.
- **Observed:** platform behavior captured, including an expected failure.
- **Synthetic:** query logic tested with fabricated rows only.
- **Pending:** no public claim should be made until evidence is captured.
- **Not claimed:** deliberately outside the safety or access boundary.
