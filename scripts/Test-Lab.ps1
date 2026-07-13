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
$queriesById = [ordered]@{}

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
    if (([regex]::Matches($content, '(?m)^\s*tactic:\s*')).Count -gt 1) {
        throw "Preview custom detections currently accept one MITRE tactic per rule: $($file.Name)."
    }

    $compileOutput = & az bicep build --file $file.FullName --stdout 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Bicep compilation failed for $($file.Name):`n$($compileOutput -join "`n")"
    }

    $template = ($compileOutput -join "`n") | ConvertFrom-Json -Depth 100
    $resources = @(
        $template.resources.PSObject.Properties.Value |
            Where-Object type -EQ 'Microsoft.Security/detectionRules@2026-06-01-preview'
    )
    if ($resources.Count -ne 1) {
        throw "Expected one compiled custom detection resource in $($file.Name); found $($resources.Count)."
    }
    $properties = $resources[0].properties
    $queryText = [string]$properties.queryCondition.queryText
    if (-not $queryText) {
        throw "Compiled custom detection query is empty in $($file.Name)."
    }

    $projectMatches = [regex]::Matches($queryText, '(?im)^\s*\|\s*project\s+([^\r\n]+)$')
    if ($projectMatches.Count -eq 0) {
        throw "Compiled query has no final project clause in $($file.Name)."
    }
    $finalProjection = $projectMatches[$projectMatches.Count - 1].Groups[1].Value
    foreach ($requiredColumn in @('Timestamp', 'DeviceId', 'ReportId')) {
        if ($finalProjection -notmatch ("(?i)(^|,\s*){0}(?:\s*=|(?=\s*,|\s*$))" -f [regex]::Escape($requiredColumn))) {
            throw "Compiled query final projection is missing $requiredColumn in $($file.Name)."
        }
    }

    $actionPropertyNames = @($properties.detectionAction.PSObject.Properties.Name)
    $forbiddenActionModels = @($actionPropertyNames | Where-Object { $_ -in @('automatedActions', 'responseActions') })
    if ($forbiddenActionModels.Count -gt 0) {
        throw "Compiled rule $($file.Name) declares response-action model(s): $($forbiddenActionModels -join ', ')."
    }
    if ('alertTemplate' -notin $actionPropertyNames) {
        throw "Compiled rule $($file.Name) is missing its alert template."
    }

    $ids.Add($id)
    $displayNames.Add($displayName)
    $queriesById[$id] = $queryText.Trim()
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

$cleanupStart = $telemetryScript.IndexOf('function Remove-LabArtifacts', [StringComparison]::Ordinal)
$cleanupEnd = if ($cleanupStart -ge 0) {
    $telemetryScript.IndexOf('$identity =', $cleanupStart, [StringComparison]::Ordinal)
} else {
    -1
}
$cleanupBlock = if ($cleanupStart -ge 0 -and $cleanupEnd -gt $cleanupStart) {
    $telemetryScript.Substring($cleanupStart, $cleanupEnd - $cleanupStart)
} else {
    ''
}
$cleanupMutationMarker = $cleanupBlock.IndexOf(
    '# Phase 2: all ownership checks passed; remove only the validated artifacts.',
    [StringComparison]::Ordinal
)
$cleanupDeletionOffsets = @(
    '& schtasks.exe /Delete',
    'Remove-EventLog -LogName $eventLogName',
    'Remove-Item -LiteralPath $directory.Path -Recurse -Force',
    '& reg.exe DELETE $registryNativePath /V $registryValueName /F'
) | ForEach-Object { $cleanupBlock.IndexOf($_, [StringComparison]::Ordinal) }
$firstCleanupDeletion = @($cleanupDeletionOffsets | Where-Object { $_ -ge 0 } | Sort-Object | Select-Object -First 1)
$generationPreflight = $telemetryScript.IndexOf(
    '    Assert-GenerationNamesAvailable',
    [StringComparison]::Ordinal
)
$generationFirstWrite = $telemetryScript.IndexOf(
    '    New-Item -ItemType Directory -Path $labRoot',
    [StringComparison]::Ordinal
)
$telemetryContracts = [ordered]@{
    'custom event-log cleanup is exact' = $telemetryScript -match 'Remove-EventLog\s+-LogName\s+\$eventLogName'
    'generation preflights every reserved name before writing' = $generationPreflight -ge 0 -and
        $generationFirstWrite -gt $generationPreflight -and
        $telemetryScript -match 'function\s+Assert-GenerationNamesAvailable'
    'generation refuses forced overwrite' = $telemetryScript -notmatch '(?m)^\s*New-Item[^\r\n]*\$labRoot[^\r\n]*-Force' -and
        $telemetryScript -notmatch '(?m)^\s*&\s*schtasks\.exe\s+/Create[^\r\n]*/F' -and
        $telemetryScript -notmatch '(?m)^\s*(Copy-Item|Move-Item)[^\r\n]*-Force'
    'cleanup validates every artifact before deleting' = $cleanupMutationMarker -ge 0 -and
        $firstCleanupDeletion.Count -eq 1 -and
        $firstCleanupDeletion[0] -gt $cleanupMutationMarker -and
        $cleanupBlock -match 'Test-LabTaskOwned' -and
        $cleanupBlock -match 'LogNameFromSourceName' -and
        $cleanupBlock -match 'Test-DirectoryOwned' -and
        $telemetryScript -match 'Get-ScheduledTask' -and
        $telemetryScript -match [regex]::Escape("Refusing to treat '`$taskName' as absent.")
    'legacy task ownership requires the registry marker' = $telemetryScript -match [regex]::Escape(
        "return (`$arguments -ceq '/c exit 0' -and `$LegacyRegistryMarkerPresent)"
    )
    'registry cleanup removes only the exact marker value' = $cleanupBlock -match [regex]::Escape(
        '& reg.exe DELETE $registryNativePath /V $registryValueName /F'
    )
    'native command failures are enforced' = $telemetryScript -match 'function\s+Assert-NativeCommandSucceeded' -and
        $telemetryScript -match 'if\s*\(\$LASTEXITCODE\s+-ne\s+0\)' -and
        ([regex]::Matches($telemetryScript, 'Assert-NativeCommandSucceeded\s+-Operation')).Count -ge 6
    'directory cleanup requires ownership markers and allowlisted contents' = $telemetryScript -match 'ownershipMarkerName' -and
        $telemetryScript -match 'Test-DirectoryContentsAreLabOnly' -and
        $telemetryScript -match 'LegacyRegistryMarkerPresent'
}
foreach ($contract in $telemetryContracts.GetEnumerator()) {
    if (-not $contract.Value) {
        throw "Safe telemetry contract failed: $($contract.Key)."
    }
}

$syntheticFile = Join-Path $root 'tests\synthetic-unit-tests.kql'
$syntheticContent = Get-Content -LiteralPath $syntheticFile -Raw
$expectedSyntheticTests = @(
    'PersistencePositive',
    'PersistenceNegative',
    'RecoveryPositive',
    'RecoveryNegative',
    'EventLogPositive',
    'EventLogNegative',
    'MinIOPositive',
    'MinIONegative',
    'CandyPositive',
    'CandyNegative'
)
foreach ($testName in $expectedSyntheticTests) {
    if (([regex]::Matches($syntheticContent, ('"{0}"' -f [regex]::Escape($testName)))).Count -ne 1) {
        throw "Synthetic fixture must declare exactly one expectation for $testName."
    }
}
$fixtureAliases = [ordered]@{
    'nls-gw-001-onedrive-persistence' = 'PersistenceMatches'
    'nls-gw-002-recovery-boot-tampering' = 'RecoveryMatches'
    'nls-gw-003-event-log-destruction' = 'LogClearMatches'
    'nls-gw-004-minio-transfer-staging' = 'MinioMatches'
    'nls-gw-005-candy-rename-burst' = 'CandyMatches'
}
foreach ($entry in $fixtureAliases.GetEnumerator()) {
    $id = $entry.Key
    $markerPattern = "(?ms)^// BEGIN EXACT QUERY {0}\s*\r?\n(?<query>.*?)\r?\n// END EXACT QUERY {0}\s*$" -f [regex]::Escape($id)
    $fixtureMatch = [regex]::Match($syntheticContent, $markerPattern)
    if (-not $fixtureMatch.Success) {
        throw "Synthetic fixture is missing the exact-query block for $id."
    }
    $fixtureQuery = $fixtureMatch.Groups['query'].Value
    $fixtureQuery = [regex]::Replace(
        $fixtureQuery,
        ("(?m)^let\s+{0}\s*=\s*" -f [regex]::Escape($entry.Value)),
        ''
    ).Trim()
    if ($fixtureQuery.EndsWith(';', [StringComparison]::Ordinal)) {
        $fixtureQuery = $fixtureQuery.Substring(0, $fixtureQuery.Length - 1)
    }
    $normalizedFixtureQuery = ($fixtureQuery -replace "`r`n", "`n").Trim()
    $normalizedDetectionQuery = ([string]$queriesById[$id] -replace "`r`n", "`n").Trim()
    if ($normalizedFixtureQuery -cne $normalizedDetectionQuery) {
        throw "Synthetic fixture query diverges from the compiled query for $id."
    }
}
$requiredFixtureBranches = @(
    'reagentc.exe /disable',
    'bcdedit.exe /set {default} recoveryenabled no',
    'bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures',
    'takeown.exe /f C:\Windows\Boot\EFI\bootmgfw.efi',
    'icacls.exe C:\Windows\System32\ntoskrnl.exe /grant Users:F',
    'wevtutil.exe cl NLS-GigaWiper-Lab',
    'wevtutil.exe clear-log NLS-GigaWiper-Lab',
    'mc.exe mirror C:\Sensitive alias/bucket',
    'mc.exe cp C:\Sensitive\decoy.txt alias/bucket',
    'mc.exe pipe alias/bucket/decoy.txt',
    'mc.exe alias set fixture https://127.0.0.1.invalid ACCESS SECRET'
)
foreach ($branchCommand in $requiredFixtureBranches) {
    if (-not $syntheticContent.Contains($branchCommand, [StringComparison]::Ordinal)) {
        throw "Synthetic fixtures do not exercise required command branch: $branchCommand"
    }
}
foreach ($expectation in @(
    '"RecoveryPositive", "recovery-positive", "Recovery", 5',
    '"EventLogPositive", "log-positive", "EventLog", 2',
    '"MinIOPositive", "minio-positive", "MinIO", 4'
)) {
    if (-not $syntheticContent.Contains($expectation, [StringComparison]::Ordinal)) {
        throw "Synthetic fixtures do not enforce expanded branch count: $expectation"
    }
}
$candyQuery = [string]$queriesById['nls-gw-005-candy-rename-burst']
$candyWindowContracts = [ordered]@{
    'five-minute lookup window' = $candyQuery -match '(?m)^let\s+LookupWindow\s*=\s*5m;\s*$'
    'half-window lookup bins' = $candyQuery -match '(?m)^let\s+LookupBin\s*=\s*LookupWindow\s*/\s*2\.0;\s*$'
    'range-based time-key expansion' = $candyQuery -match 'TimeKey\s*=\s*range\(bin\(Timestamp\s*-\s*LookupWindow,\s*LookupBin\),\s*bin\(Timestamp,\s*LookupBin\),\s*LookupBin\)'
    'expanded typed time keys' = $candyQuery -match '\|\s*mv-expand\s+TimeKey\s+to\s+typeof\(datetime\)'
    'device and time-key equality join' = $candyQuery -match '\)\s+on\s+DeviceId,\s*TimeKey'
    'exact post-join window bound' = $candyQuery -match 'Timestamp\s+between\s+\(WindowStart\s*\.\.\s*WindowStart\s*\+\s*LookupWindow\)'
}
foreach ($contract in $candyWindowContracts.GetEnumerator()) {
    if (-not $contract.Value) {
        throw "Candy time-window contract failed: $($contract.Key)."
    }
}
if ($syntheticContent -notmatch 'Passed=\(Actual == Expected\)' -or
    $syntheticContent -notmatch 'coalesce\(Actual, tolong\(0\)\)') {
    throw 'Synthetic fixtures must emit explicit positive and negative pass/fail results.'
}
$syntheticRunner = Join-Path $PSScriptRoot 'Invoke-SyntheticKqlTests.ps1'
if (-not (Test-Path -LiteralPath $syntheticRunner)) {
    throw 'The read-only live synthetic KQL runner is missing.'
}
$syntheticRunnerContent = Get-Content -LiteralPath $syntheticRunner -Raw
foreach ($testName in $expectedSyntheticTests) {
    if ($syntheticRunnerContent -notmatch ("'{0}'" -f [regex]::Escape($testName))) {
        throw "The live synthetic KQL runner does not assert $testName."
    }
}
if ($syntheticRunnerContent -notmatch 'advancedqueries/run' -or
    $syntheticRunnerContent -notmatch 'Invoke-RestMethod\s+-Method\s+Post' -or
    $syntheticRunnerContent -notmatch '\$row\[0\]\.Passed') {
    throw 'The live synthetic KQL runner is missing its read-only execution or result assertions.'
}
if ($syntheticRunnerContent -match '\[uri\]\$ApiUri' -or
    $syntheticRunnerContent -notmatch [regex]::Escape(
        "`$apiUri = [uri]'https://api.securitycenter.microsoft.com/api/advancedqueries/run'"
    )) {
    throw 'The live synthetic KQL runner must send its bearer token only to the fixed Defender API endpoint.'
}

$graphFallbackFile = Join-Path $PSScriptRoot 'Deploy-CustomDetectionsGraph.ps1'
$graphFallback = Get-Content -LiteralPath $graphFallbackFile -Raw
$fallbackWorkflowFile = Join-Path $root '.github\workflows\graph-preview-fallback.yml'
$fallbackWorkflow = Get-Content -LiteralPath $fallbackWorkflowFile -Raw
$inspectStart = $graphFallback.IndexOf("if (`$Mode -eq 'Inspect')", [StringComparison]::Ordinal)
$inspectEnd = if ($inspectStart -ge 0) {
    $graphFallback.IndexOf('$compiledRules =', $inspectStart, [StringComparison]::Ordinal)
} else {
    -1
}
$inspectBlock = if ($inspectStart -ge 0 -and $inspectEnd -gt $inspectStart) {
    $graphFallback.Substring($inspectStart, $inspectEnd - $inspectStart)
} else {
    ''
}
$applyStart = $graphFallback.IndexOf('$results = foreach ($rule in $compiledRules)', [StringComparison]::Ordinal)
$applyEnd = if ($applyStart -ge 0) {
    $graphFallback.IndexOf('$results | Format-Table', $applyStart, [StringComparison]::Ordinal)
} else {
    -1
}
$applyBlock = if ($applyStart -ge 0 -and $applyEnd -gt $applyStart) {
    $graphFallback.Substring($applyStart, $applyEnd - $applyStart)
} else {
    ''
}
$armedGuardStart = $graphFallback.IndexOf(
    'function Assert-ExistingDetectionIsAlertOnly',
    [StringComparison]::Ordinal
)
$armedGuardEnd = if ($armedGuardStart -ge 0) {
    $graphFallback.IndexOf('function ConvertTo-UtcIsoTimestamp', $armedGuardStart, [StringComparison]::Ordinal)
} else {
    -1
}
$armedGuardBlock = if ($armedGuardStart -ge 0 -and $armedGuardEnd -gt $armedGuardStart) {
    $graphFallback.Substring($armedGuardStart, $armedGuardEnd - $armedGuardStart)
} else {
    ''
}
$existingGetOffset = $applyBlock.IndexOf('$existing = Invoke-DetectionGraphRequest', [StringComparison]::Ordinal)
$existingGuardOffset = $applyBlock.IndexOf(
    'Assert-ExistingDetectionIsAlertOnly -RuleId $rule.id -Rule $existing.Body',
    [StringComparison]::Ordinal
)
$raceGetOffset = $applyBlock.IndexOf('$raceCheck = Invoke-DetectionGraphRequest', [StringComparison]::Ordinal)
$raceGuardOffset = $applyBlock.IndexOf(
    'Assert-ExistingDetectionIsAlertOnly -RuleId $rule.id -Rule $raceCheck.Body',
    [StringComparison]::Ordinal
)
$firstPatchOffset = $applyBlock.IndexOf('-Method PATCH', [StringComparison]::Ordinal)
$fallbackContracts = [ordered]@{
    'manual-only workflow' = $fallbackWorkflow -match '(?m)^\s*workflow_dispatch:' -and $fallbackWorkflow -notmatch '(?m)^\s*(push|pull_request):'
    'apply-only main-branch guard' = $fallbackWorkflow -match "github\.ref == 'refs/heads/main'" -and
        $fallbackWorkflow -match "inputs\.operation == 'Apply'"
    'protected environment' = $fallbackWorkflow -match '(?m)^\s*environment:\s*custom-detection-fallback\s*$'
    'OIDC without subscription RBAC' = $fallbackWorkflow -match '(?m)^\s*allow-no-subscriptions:\s*true\s*$' -and $fallbackWorkflow -notmatch '(?m)^\s*subscription-id:'
    'pinned actions' = $fallbackWorkflow -match 'actions/checkout@[0-9a-f]{40}' -and $fallbackWorkflow -match 'azure/login@[0-9a-f]{40}'
    'exact-ID upsert' = $graphFallback -match 'detectionRules' -and $graphFallback -match 'EscapeDataString' -and $graphFallback -match "ValidateSet\('GET', 'POST', 'PATCH'\)"
    'MITRE sub-technique normalization' = $graphFallback -match 'subTechniques' -and $graphFallback -match 'GetMitreFingerprints'
    'no delete or pruning' = $graphFallback -notmatch "ValidateSet\([^\r\n]*'DELETE'" -and $graphFallback -notmatch '(?i)prune'
    'app-only permission guidance' = $graphFallback -match 'CustomDetection\.ReadWrite\.All'
    'manual read-only inspection' = $graphFallback -match "ValidateSet\('Plan', 'Apply', 'Inspect'\)" -and $fallbackWorkflow -match 'INSPECT_PREVIEW_FALLBACK'
    'inspection uses exact-ID GET only' = $inspectBlock -match 'EscapeDataString' -and $inspectBlock -match '(?m)-Method GET' -and $inspectBlock -notmatch '(?m)-Method (POST|PATCH)'
    'inspection requests metadata only' = $inspectBlock -match '\?\$select=id,status,schedule,lastRunDetails,detectionAction'
    'inspection output is allowlisted' = @(
        'Id',
        'Status',
        'Frequency',
        'NextRunDateTime',
        'LastRunStatus',
        'LastRunDateTime',
        'LastRunErrorCode',
        'LastRunFailureReason',
        'ResponseActionCount'
    ).Where({ $graphFallback -match ("(?m)^\s*{0}\s*=" -f $_) }).Count -eq 9 -and
        $inspectBlock -notmatch '(?i)queryText|displayName|createdBy|lastModifiedBy|requestId|tenant'
    'all modes enforce both response-action models' = $graphFallback -match 'responseActions' -and
        $graphFallback -match 'automatedActions\.PSObject\.Properties' -and
        $graphFallback -match "property\.Name -notlike '@\*'" -and
        $graphFallback -match '\$responseActionCount\s*=\s*Get-DetectionResponseActionCount' -and
        $graphFallback -match 'ResponseActions\s*=\s*Get-DetectionResponseActionCount'
    'apply refuses armed exact-ID rules before update' = $graphFallback -match 'function\s+Assert-ExistingDetectionIsAlertOnly' -and
        ([regex]::Matches($graphFallback, 'Assert-ExistingDetectionIsAlertOnly\s+-RuleId')).Count -eq 2 -and
        $armedGuardBlock -match 'Get-DetectionResponseActionCount\s+-DetectionAction\s+\$Rule\.detectionAction' -and
        $armedGuardBlock -match 'if\s*\(\$responseActionCount\s+-gt\s+0\)' -and
        $armedGuardBlock -match "Refusing to modify an armed rule" -and
        $existingGetOffset -ge 0 -and
        $existingGuardOffset -gt $existingGetOffset -and
        $raceGetOffset -gt $existingGuardOffset -and
        $raceGuardOffset -gt $raceGetOffset -and
        $firstPatchOffset -gt $raceGuardOffset
    'inspection timestamps are UTC ISO 8601' = $graphFallback -match 'ConvertTo-UtcIsoTimestamp' -and
        $graphFallback -match "ToUniversalTime\(\)\.ToString\(" -and
        $graphFallback -match "'o'"
    'transport failures retry before throwing' = $graphFallback -match 'catch\s*\{\s*if\s*\(\$attempt -lt 4\)' -and
        $graphFallback -match 'Start-Sleep -Seconds' -and
        $graphFallback -match 'continue'
}
foreach ($contract in $fallbackContracts.GetEnumerator()) {
    if (-not $contract.Value) {
        throw "Graph fallback contract failed: $($contract.Key)."
    }
}

$nativeWorkflowFile = Join-Path $root '.github\workflows\sentinel-deploy-51af5a44-e148-40f0-b250-6457efb89a6c.yml'
$nativeWorkflow = Get-Content -LiteralPath $nativeWorkflowFile -Raw
$nativeHelperFile = Join-Path $root '.github\workflows\azure-sentinel-deploy-51af5a44-e148-40f0-b250-6457efb89a6c.ps1'
$nativeHelper = Get-Content -LiteralPath $nativeHelperFile -Raw
$validateWorkflow = Get-Content -LiteralPath (Join-Path $root '.github\workflows\validate.yml') -Raw
$nativeUses = @([regex]::Matches($nativeWorkflow, '(?m)^\s*uses:\s*([^\s#]+)') | ForEach-Object { $_.Groups[1].Value })
$nativeConcurrency = [regex]::Match($nativeWorkflow, '(?m)^\s*group:\s*([^\s#]+)\s*$').Groups[1].Value
$fallbackConcurrency = [regex]::Match($fallbackWorkflow, '(?m)^\s*group:\s*([^\s#]+)\s*$').Groups[1].Value
$workflowContracts = [ordered]@{
    'native workflow is manual-only' = $nativeWorkflow -match '(?m)^\s*workflow_dispatch:' -and
        $nativeWorkflow -notmatch '(?m)^\s*(push|pull_request):'
    'native workflow requires exact confirmation' = $nativeWorkflow -match "inputs\.confirmation == 'DEPLOY_NATIVE_SENTINEL_CONTENT'"
    'native workflow restricts deployment to main' = $nativeWorkflow -match "github\.ref == 'refs/heads/main'"
    'native workflow actions are SHA-pinned' = $nativeUses.Count -gt 0 -and
        @($nativeUses | Where-Object { $_ -notmatch '@[0-9a-f]{40}$' }).Count -eq 0 -and
        ([regex]::Matches($nativeWorkflow, 'azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5')).Count -eq 3 -and
        ([regex]::Matches($nativeWorkflow, 'azure/powershell@53dd145408794f7e80f97cfcca04155c85234709')).Count -eq 1
    'native workflow uses a fixed Az version' = $nativeWorkflow -match "(?m)^\s*azPSVersion:\s*'[0-9]+\.[0-9]+\.[0-9]+'\s*$"
    'native workflow installs the validated Bicep CLI' = $nativeWorkflow -match '(?m)^\s*run:\s*az bicep install --version v0\.45\.6\s*$'
    'native helper builds through Azure CLI Bicep' = $nativeHelper -match 'az bicep build --file \$path --stdout --only-show-errors' -and
        $nativeHelper -notmatch '(?m)^\s*\$templateObject\s*=\s*bicep build\s'
    'validation checkout is SHA-pinned' = $validateWorkflow -match 'actions/checkout@[0-9a-f]{40}'
    'validation Bicep CLI is version-pinned' = $validateWorkflow -match 'az bicep install --version v[0-9]+\.[0-9]+\.[0-9]+'
    'native and Graph writers share a concurrency lock' = $nativeConcurrency -eq 'nls-gigawiper-custom-detection-writer' -and
        $fallbackConcurrency -eq $nativeConcurrency -and
        $nativeWorkflow -match '(?m)^\s*cancel-in-progress:\s*false\s*$' -and
        $fallbackWorkflow -match '(?m)^\s*cancel-in-progress:\s*false\s*$'
}
foreach ($contract in $workflowContracts.GetEnumerator()) {
    if (-not $contract.Value) {
        throw "Workflow safety contract failed: $($contract.Key)."
    }
}

$summary = [pscustomobject]@{
    Passed = $true
    DetectionFiles = $files.Count
    UniqueIds = $ids.Count
    SafetyChecks = $forbidden.Count
    TelemetryContracts = $telemetryContracts.Count
    InfrastructureCompiled = $true
    InboundSecurityRules = 0
    MdeOnboardingPackage = 'ARM reference; not stored'
    SyntheticTests = $expectedSyntheticTests.Count
    SyntheticPositiveTests = @($expectedSyntheticTests | Where-Object { $_ -like '*Positive' }).Count
    SyntheticNegativeTests = @($expectedSyntheticTests | Where-Object { $_ -like '*Negative' }).Count
    SyntheticBranchContracts = $requiredFixtureBranches.Count
    CandyWindowContracts = $candyWindowContracts.Count
    LiveSyntheticRunnerPresent = $true
    FallbackContracts = $fallbackContracts.Count
    WorkflowContracts = $workflowContracts.Count
    Results = $results
}

if ($Json) {
    $summary | ConvertTo-Json -Depth 5
} else {
    $results | Format-Table -AutoSize
    Write-Host "Validated $($files.Count) detection templates, the zero-inbound endpoint template, $($ids.Count) unique IDs, $($expectedSyntheticTests.Count) positive/negative synthetic contracts, $($forbidden.Count) destructive-string boundaries, $($telemetryContracts.Count) telemetry ownership controls, $($fallbackContracts.Count) fallback controls, and $($workflowContracts.Count) workflow controls."
}
