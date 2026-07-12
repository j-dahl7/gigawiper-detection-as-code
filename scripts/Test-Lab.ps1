[CmdletBinding()]
param(
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$detectionPath = Join-Path $root 'detections'
$infraFile = Join-Path $root 'infra\lab-endpoint.bicep'
$files = @(Get-ChildItem -LiteralPath $detectionPath -Filter '*.bicep' | Sort-Object Name)

if ($files.Count -ne 6) {
    throw "Expected 6 Bicep files (5 rules plus canary); found $($files.Count)."
}

$results = [System.Collections.Generic.List[object]]::new()
$ids = [System.Collections.Generic.List[string]]::new()
$displayNames = [System.Collections.Generic.List[string]]::new()

foreach ($file in $files) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    $idMatch = [regex]::Match($content, "(?m)^\s*id:\s*'([^']+)'\s*$")
    $nameMatch = [regex]::Match($content, "(?m)^\s*displayName:\s*'([^']+)'\s*$")

    if (-not $idMatch.Success) { throw "Missing id in $($file.Name)." }
    if (-not $nameMatch.Success) { throw "Missing displayName in $($file.Name)." }

    $id = $idMatch.Groups[1].Value
    $displayName = $nameMatch.Groups[1].Value
    if ($id -notmatch '^[A-Za-z][A-Za-z0-9_-]{0,99}$') {
        throw "Invalid provider rule id '$id' in $($file.Name)."
    }
    if ($content -notmatch '\bTimestamp\b' -or $content -notmatch '\bDeviceId\b' -or $content -notmatch '\bReportId\b') {
        throw "Query contract missing Timestamp, DeviceId, or ReportId in $($file.Name)."
    }
    if ($content -match '(?i)isolateDevice|disableUser|deleteEmail|runAntivirusScan') {
        throw "Automated response action found in $($file.Name); lab rules must alert only by default."
    }
    if (([regex]::Matches($content, '(?m)^\s*tactic:\s*')).Count -gt 1) {
        throw "Preview custom detections currently accept one MITRE tactic per rule: $($file.Name)."
    }

    $compileOutput = & az bicep build --file $file.FullName --stdout 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Bicep compilation failed for $($file.Name):`n$($compileOutput -join "`n")"
    }

    $ids.Add($id)
    $displayNames.Add($displayName)
    $results.Add([pscustomobject]@{
        File = $file.Name
        Id = $id
        DisplayName = $displayName
        BicepCompiled = $true
        QueryContract = $true
        ResponseActions = 'none'
    })
}

if (($ids | Sort-Object -Unique).Count -ne $ids.Count) {
    throw 'Duplicate custom detection rule IDs found.'
}
if (($displayNames | Sort-Object -Unique).Count -ne $displayNames.Count) {
    throw 'Duplicate custom detection display names found.'
}

$infraOutput = & az bicep build --file $infraFile --stdout 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Infrastructure Bicep compilation failed:`n$($infraOutput -join "`n")"
}
$infraContent = Get-Content -LiteralPath $infraFile -Raw
if ($infraContent -notmatch 'securityRules:\s*\[\]') {
    throw 'Disposable endpoint NSG must not contain inbound rules.'
}
if ($infraContent -notmatch 'Microsoft\.Security/mdeOnboardings@2021-10-01-preview' -or
    $infraContent -notmatch 'defenderForEndpointOnboardingScript:\s*mdeOnboarding\.properties\.onboardingPackageWindows') {
    throw 'MDE must use the subscription onboarding resource instead of a checked-in onboarding package.'
}
if ($infraContent -notmatch 'azureResourceId:\s*vm\.id') {
    throw 'MDE extension settings must bind onboarding to the disposable VM resource ID.'
}

$telemetryScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Invoke-SafeGigaWiperTelemetry.ps1') -Raw
$forbidden = @(
    'Clear-EventLog -LogName Security',
    'wevtutil cl Security',
    'wevtutil cl System',
    'wevtutil cl Application',
    'reagentc /disable',
    'bcdedit /set recoveryenabled no',
    'Remove-Item C:\\Windows\\System32',
    'Format-Volume',
    'Clear-Disk'
)
foreach ($value in $forbidden) {
    if ($telemetryScript.Contains($value, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Forbidden destructive string found in safe telemetry script: $value"
    }
}

$syntheticFile = Join-Path $root 'tests\synthetic-unit-tests.kql'
$syntheticContent = Get-Content -LiteralPath $syntheticFile -Raw
$expectedSyntheticTests = @(
    'PersistenceCorrelation',
    'RecoveryTampering',
    'EventLogDestruction',
    'MinIOStaging',
    'CandyRenameBurst'
)
foreach ($testName in $expectedSyntheticTests) {
    if ($syntheticContent -notmatch ('Test="{0}"' -f [regex]::Escape($testName))) {
        throw "Synthetic fixture coverage missing for $testName."
    }
}

$summary = [pscustomobject]@{
    Passed = $true
    DetectionFiles = $files.Count
    UniqueIds = $ids.Count
    SafetyChecks = $forbidden.Count
    InfrastructureCompiled = $true
    InboundSecurityRules = 0
    MdeOnboardingPackage = 'ARM reference; not stored'
    SyntheticTests = $expectedSyntheticTests.Count
    Results = $results
}

if ($Json) {
    $summary | ConvertTo-Json -Depth 5
} else {
    $results | Format-Table -AutoSize
    Write-Host "Validated $($files.Count) detection templates, the zero-inbound endpoint template, $($ids.Count) unique IDs, $($expectedSyntheticTests.Count) synthetic fixtures, and $($forbidden.Count) safety boundaries."
}
