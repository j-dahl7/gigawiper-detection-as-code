# Manual Graph fallback for the July 2026 preview

Use this path only when native Sentinel Repository synchronization fails in the
Microsoft Security provider after the documented prerequisites and permissions
have been verified. It is a tenant-scoped Microsoft Graph beta workaround, not
a replacement for Sentinel Repositories.

## Security model

Create a dedicated single-tenant Entra application for this workflow. Grant it
only the Microsoft Graph **application** permission:

| Permission | App role ID |
|---|---|
| `CustomDetection.ReadWrite.All` | `e0fd9c8d-a12e-4cc9-9827-20c8c3cd6fb8` |

Grant tenant admin consent. Do not give this identity an Azure subscription or
resource-group role. The Graph permission is tenant-wide, so compensate with a
dedicated identity, GitHub environment controls, branch protection, CODEOWNERS,
and manual execution.

Create one federated identity credential on the application:

| Field | Value |
|---|---|
| Issuer | `https://token.actions.githubusercontent.com` |
| Audience | `api://AzureADTokenExchange` |
| Subject | `repo:OWNER/REPOSITORY:environment:custom-detection-fallback` |

No client secret is required or expected.

## GitHub environment

Create the environment `custom-detection-fallback` and restrict its deployment
branch policy to `main`. If the repository plan supports required reviewers,
add one. Private repositories on plans without environment reviewers should
retain the `main` guard, exact confirmation input, and branch protection in the
checked-in workflow.

Add these environment variables; neither value is a credential:

| Variable | Value |
|---|---|
| `CUSTOM_DETECTION_CLIENT_ID` | Application (client) ID of the dedicated app |
| `AZURE_TENANT_ID` | Tenant ID containing Defender XDR |

## Run order

The checked-in native and Graph workflows share the
`nls-gigawiper-custom-detection-writer` concurrency group. GitHub admits only
one of those workflow runs at a time; `cancel-in-progress: false` also prevents
a new dispatch from terminating an active deployment.

1. Let any native Sentinel Repository workflow finish. The shared lock prevents
   execution overlap, but confirm the intended owner before allowing a queued
   writer to proceed.
2. Run **Deploy custom detections - preview fallback** from `main`.
3. Select `Canary` and type `DEPLOY_PREVIEW_FALLBACK`.
4. Confirm `nls-gw-000-canary` is read back as `disabled` with zero response
   actions.
5. Run the workflow again with `All`.
6. Retain the step-summary table as evidence.
7. Disable this fallback after native Repository synchronization succeeds.

The script performs exact-ID GET/POST/PATCH operations only. It never deletes
or prunes rules, and it refuses to adopt a name/title conflict when the expected
stable ID is absent.

## Retire the fallback

After the six stable IDs have been deleted or deliberately transferred to a
working native owner, delete the dedicated
`nls-gigawiper-custom-detection-fallback` app registration. Then remove the
`CUSTOM_DETECTION_CLIENT_ID` and `AZURE_TENANT_ID` variables from the
`custom-detection-fallback` GitHub environment and remove that environment if
it has no other purpose. Do not delete the identity before any separately
authorized exact-ID rule cleanup that depends on it.

## References

- [Create detectionRule](https://learn.microsoft.com/en-us/graph/api/security-rulesroot-post-detectionrules?view=graph-rest-beta)
- [Update detectionRule](https://learn.microsoft.com/en-us/graph/api/security-detectionrule-update?view=graph-rest-beta)
- [Get detectionRule](https://learn.microsoft.com/en-us/graph/api/security-detectionrule-get?view=graph-rest-beta)
- [CustomDetection.ReadWrite.All](https://learn.microsoft.com/en-us/graph/permissions-reference#customdetectionreadwriteall)
- [GitHub OIDC with Azure](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure-openid-connect)
