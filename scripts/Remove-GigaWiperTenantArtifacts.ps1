[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$graphToken = $env:GRAPH_ACCESS_TOKEN
if ([string]::IsNullOrWhiteSpace($graphToken)) {
    throw 'GRAPH_ACCESS_TOKEN is required.'
}

$graphBaseUri = 'https://graph.microsoft.com/beta/security/rules/detectionRules'
$ownedRules = @(
    [pscustomobject]@{
        Id = 'nls-gw-000-canary'
        DisplayName = 'NLS-GW-000 - Detection as Code Canary'
        Kind = 'Graph fallback'
    }
    [pscustomobject]@{
        Id = 'nls-gw-001-onedrive-persistence'
        DisplayName = 'NLS-GW-001 - OneDrive-Lookalike Task and Registry Persistence'
        Kind = 'Graph fallback'
    }
    [pscustomobject]@{
        Id = 'nls-gw-002-recovery-boot-tampering'
        DisplayName = 'NLS-GW-002 - Recovery and Boot Tampering'
        Kind = 'Graph fallback'
    }
    [pscustomobject]@{
        Id = 'nls-gw-003-event-log-destruction'
        DisplayName = 'NLS-GW-003 - Windows Event Log Destruction'
        Kind = 'Graph fallback'
    }
    [pscustomobject]@{
        Id = 'nls-gw-004-minio-transfer-staging'
        DisplayName = 'NLS-GW-004 - Unusual MinIO Client Transfer Staging'
        Kind = 'Graph fallback'
    }
    [pscustomobject]@{
        Id = 'nls-gw-005-candy-rename-burst'
        DisplayName = 'NLS-GW-005 - Candy Extension Rename Burst'
        Kind = 'Graph fallback'
    }
    [pscustomobject]@{
        Id = '152'
        DisplayName = 'NLS-GW-LIVE-001 - Safe OneDrive Persistence'
        Kind = 'Portal-native validation'
    }
    [pscustomobject]@{
        Id = '153'
        DisplayName = 'NLS-GW-LIVE-003 - Safe Custom Log Clearing'
        Kind = 'Portal-native validation'
    }
    [pscustomobject]@{
        Id = '151'
        DisplayName = 'NLS-GW-LIVE-004 - MinIO Safe Telemetry Canary'
        Kind = 'Portal-native validation'
    }
)

$headers = @{
    Authorization = "Bearer $graphToken"
    Accept        = 'application/json'
}

function Invoke-GraphRequest {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'DELETE')]
        [string] $Method,

        [Parameter(Mandatory)]
        [string] $Uri
    )

    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $requestParameters = @{
            Method             = $Method
            Uri                = $Uri
            Headers            = $headers
            SkipHttpErrorCheck = $true
        }
        $response = Invoke-WebRequest @requestParameters

        $statusCode = [int] $response.StatusCode
        if ($statusCode -eq 429 -or $statusCode -ge 500) {
            if ($attempt -eq 5) {
                throw "Microsoft Graph $Method did not recover from HTTP $statusCode."
            }

            Start-Sleep -Seconds ([Math]::Min(2 * $attempt, 8))
            continue
        }

        return [pscustomobject]@{
            StatusCode = $statusCode
            Content    = [string] $response.Content
        }
    }
}

function Get-RuleById {
    param(
        [Parameter(Mandatory)]
        [string] $Id
    )

    $escapedId = [Uri]::EscapeDataString($Id)
    $response = Invoke-GraphRequest -Method GET -Uri "$graphBaseUri/$escapedId"
    if ($response.StatusCode -eq 404) {
        return $null
    }
    if ($response.StatusCode -ne 200) {
        throw "Exact-ID read for '$Id' returned HTTP $($response.StatusCode)."
    }

    $rule = $response.Content | ConvertFrom-Json
    if ([string] $rule.id -cne $Id) {
        throw "Exact-ID read for '$Id' returned unexpected ID '$($rule.id)'."
    }

    return $rule
}

# Complete every read and allowlist check before the first DELETE.
$targets = [System.Collections.Generic.List[object]]::new()
foreach ($ownedRule in $ownedRules) {
    $rule = Get-RuleById -Id $ownedRule.Id
    if ($null -ne $rule) {
        if ([string] $rule.displayName -cne $ownedRule.DisplayName) {
            throw "Refusing cleanup because ID '$($ownedRule.Id)' has unexpected display name '$($rule.displayName)'."
        }
        $targets.Add($ownedRule)
    }
    else {
        Write-Output "Already absent: $($ownedRule.Kind): $($ownedRule.DisplayName) [$($ownedRule.Id)]."
    }
}

if ($ownedRules.Count -ne 9 -or $targets.Count -gt $ownedRules.Count) {
    throw 'Refusing cleanup because the exact nine-rule ownership boundary was violated.'
}

Write-Output "Preflight passed for $($targets.Count) owned rule(s)."
foreach ($target in $targets) {
    $escapedId = [Uri]::EscapeDataString([string] $target.Id)
    $response = Invoke-GraphRequest -Method DELETE -Uri "$graphBaseUri/$escapedId"
    if ($response.StatusCode -notin @(204, 404)) {
        throw "Delete for '$($target.DisplayName)' returned HTTP $($response.StatusCode)."
    }

    Write-Output "Retired $($target.Kind): $($target.DisplayName) [$($target.Id)] (HTTP $($response.StatusCode))."
}

for ($attempt = 1; $attempt -le 6; $attempt++) {
    $remaining = @($ownedRules | Where-Object { $null -ne (Get-RuleById -Id $_.Id) })
    if ($remaining.Count -eq 0) {
        Write-Output 'Read-back passed: all nine allowlisted rule identities are absent.'
        return
    }

    if ($attempt -lt 6) {
        Start-Sleep -Seconds 5
    }
}

throw 'Read-back failed: one or more allowlisted rules remained after bounded retries.'
