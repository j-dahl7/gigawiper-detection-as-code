[CmdletBinding()]
param(
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$detectionPath = Join-Path $root 'detections'
$infraFile = Join-Path $root 'infra\lab-endpoint.bicep'
$detectionOwnershipMarker = 'nlzt-owner:gigawiper-detection-as-code:v1'
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

    $compileOutput = & az bicep build --file $file.FullName --stdout --only-show-errors 2>&1
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
    if ([string]$properties.description -cne $detectionOwnershipMarker) {
        throw "Compiled rule $($file.Name) is missing the exact repository ownership marker."
    }
    $queryText = [string]$properties.queryCondition.queryText
    if (-not $queryText) {
        throw "Compiled custom detection query is empty in $($file.Name)."
    }

    $projectMatches = [regex]::Matches($queryText, '(?im)^\s*\|\s*project\s+([^\r\n]+)\r?$')
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

$infraOutput = & az bicep build --file $infraFile --stdout --only-show-errors 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Infrastructure Bicep compilation failed:`n$($infraOutput -join "`n")"
}
$infraTemplate = ($infraOutput -join "`n") | ConvertFrom-Json -Depth 100
$testLabContent = Get-Content -LiteralPath $PSCommandPath -Raw
if ($testLabContent -notmatch [regex]::Escape('& az bicep build --file $file.FullName --stdout --only-show-errors') -or
    $testLabContent -notmatch [regex]::Escape('& az bicep build --file $infraFile --stdout --only-show-errors')) {
    throw 'Lab validation must suppress non-error Azure CLI output before parsing compiled Bicep JSON.'
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

$infraContracts = [ordered]@{
    'marketplace image is composed from three nonnegative numeric segments' =
        $infraTemplate.parameters.imageVersionMajor.type -ceq 'int' -and
        [int]$infraTemplate.parameters.imageVersionMajor.minValue -eq 0 -and
        $infraTemplate.parameters.imageVersionMinor.type -ceq 'int' -and
        [int]$infraTemplate.parameters.imageVersionMinor.minValue -eq 0 -and
        $infraTemplate.parameters.imageVersionBuild.type -ceq 'int' -and
        [int]$infraTemplate.parameters.imageVersionBuild.minValue -eq 0 -and
        $infraContent -match "(?m)^var imageVersion = '\$\{imageVersionMajor\}\.\$\{imageVersionMinor\}\.\$\{imageVersionBuild\}'\s*$" -and
        $infraContent -match '(?m)^\s*version:\s*imageVersion\s*$' -and
        $infraContent -notmatch "(?m)^\s*version:\s*'latest'\s*$"
    'endpoint ownership uses an exact marker and bounded deployment token' =
        $infraContent -match '(?m)^param ownerMarker string\s*$' -and
        $infraContent -match '(?m)^param deploymentId string\s*$' -and
        @($infraTemplate.parameters.ownerMarker.allowedValues).Count -eq 1 -and
        [string]$infraTemplate.parameters.ownerMarker.allowedValues[0] -ceq 'nine-lives-gigawiper:endpoint:v1' -and
        [int]$infraTemplate.parameters.deploymentId.minLength -eq 36 -and
        [int]$infraTemplate.parameters.deploymentId.maxLength -eq 36 -and
        $infraContent -match "'nlzt-owner':\s*ownerMarker" -and
        $infraContent -match "'nlzt-deployment':\s*deploymentId" -and
        ([regex]::Matches($infraContent, '(?m)^\s*tags:\s*safeTelemetryTags\s*$')).Count -eq 4 -and
        $infraContent -match '(?ms)resource publicIp .*?tags:\s*union\(.*?ownershipTags\)'
    'MDE extension upgrades are not mutable' =
        $infraContent -match '(?m)^\s*autoUpgradeMinorVersion:\s*false\s*$' -and
        $infraContent -match '(?m)^\s*enableAutomaticUpgrade:\s*false\s*$'
    'deployment identity is returned for manifest verification' =
        $infraContent -match '(?m)^output resourceGroupId string = resourceGroup\(\)\.id\s*$' -and
        $infraContent -match '(?m)^output deploymentId string = deploymentId\s*$' -and
        $infraContent -match '(?m)^output imageVersion string = imageVersion\s*$'
}
foreach ($contract in $infraContracts.GetEnumerator()) {
    if (-not $contract.Value) {
        throw "Endpoint infrastructure contract failed: $($contract.Key)."
    }
}

$directDeploymentScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Deploy-Lab.ps1') -Raw
$directDeploymentContracts = [ordered]@{
    'direct helper is validation-only' =
        $directDeploymentScript -match 'az deployment group validate' -and
        $directDeploymentScript -notmatch 'az deployment group create' -and
        $directDeploymentScript -match "Operation = 'validate-only'"
    'direct helper explains the ownership boundary' =
        $directDeploymentScript -match 'raw ARM deployment cannot\s*\r?\n?#?\s*prove ownership' -and
        $directDeploymentScript -match 'marker-verified exact-ID mutation'
}
foreach ($contract in $directDeploymentContracts.GetEnumerator()) {
    if (-not $contract.Value) {
        throw "Direct deployment contract failed: $($contract.Key)."
    }
}

$endpointCreateFile = Join-Path $PSScriptRoot 'New-LabEndpoint.ps1'
$endpointRemoveFile = Join-Path $PSScriptRoot 'Remove-LabEndpoint.ps1'
$endpointCreateScript = Get-Content -LiteralPath $endpointCreateFile -Raw
$endpointRemoveScript = Get-Content -LiteralPath $endpointRemoveFile -Raw
$endpointIgnore = Get-Content -LiteralPath (Join-Path $root '.gitignore') -Raw
$plannedManifestOffset = $endpointCreateScript.IndexOf(
    'Write-EndpointManifest -Status planned -DeploymentId $deploymentId',
    [StringComparison]::Ordinal
)
$resourceGroupCreateOffset = $endpointCreateScript.IndexOf(
    '$group = New-AzResourceGroup -Name $ResourceGroup',
    [StringComparison]::Ordinal
)
$reuseOwnershipOffset = $endpointCreateScript.IndexOf(
    'Assert-OwnedResourceGroup -Group $group -DeploymentId ([string]$manifest.deployment_id)',
    [StringComparison]::Ordinal
)
$endpointDeploymentOffset = $endpointCreateScript.IndexOf(
    '$deployment = New-AzResourceGroupDeployment',
    [StringComparison]::Ordinal
)
$lastEmptyGroupGuardOffset = $endpointCreateScript.LastIndexOf(
    'Assert-EndpointResourceGroupEmpty',
    $endpointDeploymentOffset,
    [StringComparison]::Ordinal
)
$cleanupTagGuardOffset = $endpointRemoveScript.IndexOf(
    '[string]$Group.Tags[$OwnerTag] -cne $OwnerMarker',
    [StringComparison]::Ordinal
)
$cleanupDeleteOffset = $endpointRemoveScript.IndexOf(
    'Remove-AzResourceGroup -Name $ConfirmResourceGroup',
    [StringComparison]::Ordinal
)
$cleanupPostApprovalGuardOffset = $endpointRemoveScript.LastIndexOf(
    'Assert-OwnedResourceGroup -Group $group',
    $cleanupDeleteOffset,
    [StringComparison]::Ordinal
)
$cleanupConvergenceOffset = $endpointRemoveScript.IndexOf(
    'Azure resource-group deletion did not converge',
    $cleanupDeleteOffset,
    [StringComparison]::Ordinal
)
$cleanupManifestDeleteOffset = $endpointRemoveScript.IndexOf(
    'Remove-Item -LiteralPath $ManifestPath -Force',
    [StringComparison]::Ordinal
)
$endpointContracts = [ordered]@{
    'endpoint creation requires a pinned image version' =
        $endpointCreateScript -match [regex]::Escape('[ValidatePattern(''^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$'')]') -and
        $endpointCreateScript -match '\$imageVersionParts = \$ImageVersion\.Split' -and
        $endpointCreateScript -match '-imageVersionMajor\s+\$imageVersionMajor' -and
        $endpointCreateScript -match '-imageVersionMinor\s+\$imageVersionMinor' -and
        $endpointCreateScript -match '-imageVersionBuild\s+\$imageVersionBuild'
    'planned manifest precedes the first Azure creation' =
        $plannedManifestOffset -ge 0 -and
        $resourceGroupCreateOffset -gt $plannedManifestOffset
    'approval is followed by fresh manifest and Azure ownership reads' =
        $endpointCreateScript -match 'Endpoint manifest disappeared after approval' -and
        $endpointCreateScript -match '\$currentGroup = Get-ExactResourceGroup' -and
        $endpointCreateScript -match 'appeared after approval\. Refusing adoption or update' -and
        $endpointCreateScript -match 'appeared immediately before creation\. Refusing the name collision'
    'first manifest creation cannot overwrite a concurrent owner' =
        $endpointCreateScript -match 'Write-EndpointManifest -Status planned -DeploymentId \$deploymentId -CreateOnly' -and
        $endpointCreateScript -match '\[IO\.File\]::Move\(\$temporaryPath, \$ManifestPath\)' -and
        $endpointCreateScript -match 'Endpoint manifest appeared after approval\. Refusing overwrite'
    'endpoint outputs are verified before the deployed manifest' =
        $endpointCreateScript -match '\$outputEndpointName -cne \$VmName' -and
        $endpointCreateScript -match '\$outputImageVersion -cne \$ImageVersion' -and
        $endpointCreateScript -match 'Normalize-ResourceId \$virtualMachineId' -and
        $endpointCreateScript -match '\$deployment\.Outputs\.inboundSecurityRules\.Value -ne 0' -and
        $endpointCreateScript.IndexOf('Write-EndpointManifest -Status deployed', [StringComparison]::Ordinal) -gt
            $endpointCreateScript.IndexOf('$expectedVirtualMachineId =', [StringComparison]::Ordinal)
    'reuse requires an exact-owned empty planned resource group' =
        $endpointCreateScript -match 'ReuseOwnedLabResourceGroup' -and
        $endpointCreateScript -match "exists but endpoint manifest .* is missing\. Refusing adoption" -and
        $endpointCreateScript -match '\$manifest\.status -cne ''planned''' -and
        $endpointCreateScript -match 'function\s+Assert-EndpointResourceGroupEmpty' -and
        $endpointCreateScript -match 'Get-AzResource -ResourceGroupName \$ResourceGroup' -and
        ([regex]::Matches($endpointCreateScript, '(?m)^\s*Assert-EndpointResourceGroupEmpty\s*$')).Count -eq 4 -and
        $reuseOwnershipOffset -ge 0 -and
        $reuseOwnershipOffset -lt $resourceGroupCreateOffset -and
        $lastEmptyGroupGuardOffset -gt $resourceGroupCreateOffset -and
        $endpointDeploymentOffset -gt $lastEmptyGroupGuardOffset
    'supported endpoint deployment identity is a validated UUID' =
        $endpointCreateScript -match '\[guid\]::NewGuid\(\)\.ToString\(\)' -and
        $endpointCreateScript -match '\[guid\]::TryParse\(\[string\]\$Manifest\.deployment_id' -and
        $endpointRemoveScript -match '\[guid\]::TryParse\(\[string\]\$manifest\.deployment_id'
    'endpoint preview changes no manifest' =
        $endpointCreateScript -match 'Operation = if \(\$WhatIfPreference\) \{ ''preview'' \} else \{ ''declined'' \}' -and
        $endpointCreateScript -match 'ManifestChanged = \$false' -and
        $endpointCreateScript.IndexOf('$PSCmdlet.ShouldProcess', [StringComparison]::Ordinal) -lt $plannedManifestOffset
    'endpoint cleanup requires exact confirmation, manifest, and live tags' =
        $endpointRemoveScript -match 'Endpoint cleanup manifest not found: .*Refusing name-based cleanup' -and
        $endpointRemoveScript -match '\$ConfirmResourceGroup -cne \[string\]\$manifest\.resource_group_name' -and
        $cleanupTagGuardOffset -ge 0 -and
        $cleanupDeleteOffset -gt $cleanupTagGuardOffset
    'endpoint cleanup retains its manifest until Azure deletion converges' =
        $cleanupConvergenceOffset -gt $cleanupDeleteOffset -and
        $cleanupManifestDeleteOffset -gt $cleanupConvergenceOffset -and
        ([regex]::Matches($endpointRemoveScript, '(?m)^\s*Remove-AzResourceGroup\s')).Count -eq 1
    'endpoint cleanup revalidates after confirmation and before manifest removal' =
        $cleanupPostApprovalGuardOffset -gt $cleanupTagGuardOffset -and
        $cleanupPostApprovalGuardOffset -lt $cleanupDeleteOffset -and
        $endpointRemoveScript -match 'A same-name resource group appeared before manifest removal' -and
        $endpointRemoveScript -match '\(Get-Content -LiteralPath \$ManifestPath -Raw\) -cne \$manifestRaw'
    'endpoint manifests are excluded from version control' =
        $endpointIgnore -match '(?m)^\.gigawiper-endpoint\.json\s*$' -and
        $endpointIgnore -match '(?m)^\.gigawiper-endpoint\.json\.tmp\.\*\s*$'
    'endpoint PowerShell modules are exact-version pinned' =
        $endpointCreateScript -match [regex]::Escape("`$AzAccountsVersion = '5.3.3'") -and
        $endpointCreateScript -match [regex]::Escape("`$AzResourcesVersion = '9.0.3'") -and
        $endpointRemoveScript -match [regex]::Escape("`$AzAccountsVersion = '5.3.3'") -and
        $endpointRemoveScript -match [regex]::Escape("`$AzResourcesVersion = '9.0.3'") -and
        ([regex]::Matches(
            "$endpointCreateScript`n$endpointRemoveScript",
            'Import-Module -Name Az\.(?:Accounts|Resources) -RequiredVersion \$Az\w+Version -ErrorAction Stop'
        )).Count -eq 4
}
foreach ($contract in $endpointContracts.GetEnumerator()) {
    if (-not $contract.Value) {
        throw "Endpoint lifecycle contract failed: $($contract.Key)."
    }
}

$endpointTokens = $null
$endpointParseErrors = $null
$endpointAst = [System.Management.Automation.Language.Parser]::ParseInput(
    $endpointCreateScript,
    [ref]$endpointTokens,
    [ref]$endpointParseErrors
)
if ($endpointParseErrors.Count -gt 0) {
    throw 'Unable to parse the endpoint lifecycle helper for inventory behavior tests.'
}
$endpointInventoryFunction = @(
    $endpointAst.FindAll(
        {
            param($Ast)
            $Ast -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $Ast.Name -ceq 'Assert-EndpointResourceGroupEmpty'
        },
        $true
    )
)
if ($endpointInventoryFunction.Count -ne 1) {
    throw 'Expected exactly one Assert-EndpointResourceGroupEmpty function in the endpoint helper.'
}
Invoke-Expression $endpointInventoryFunction[0].Extent.Text
$ResourceGroup = 'nls-endpoint-inventory-fixture'
$endpointInventoryFixture = @()
function Get-AzResource {
    [CmdletBinding()]
    param([string]$ResourceGroupName)
    return @($endpointInventoryFixture)
}
try {
    Assert-EndpointResourceGroupEmpty
    $endpointInventoryFixture = @([pscustomobject]@{ ResourceId = '/fixture/resource' })
    $nonemptyInventoryRejected = $false
    try {
        Assert-EndpointResourceGroupEmpty
    }
    catch {
        $nonemptyInventoryRejected = $_.Exception.Message -match 'Refusing incremental child-resource adoption or update'
    }
}
finally {
    Remove-Item Function:\Get-AzResource -ErrorAction SilentlyContinue
}
$endpointInventoryCases = [ordered]@{
    'empty resource group is accepted' = $true
    'nonempty resource group is rejected' = $nonemptyInventoryRejected
}
foreach ($case in $endpointInventoryCases.GetEnumerator()) {
    if (-not $case.Value) {
        throw "Endpoint inventory behavior failed: $($case.Key)."
    }
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
    'Remove-OwnedDirectory `',
    'Remove-ItemProperty `'
) | ForEach-Object { $cleanupBlock.IndexOf($_, [StringComparison]::Ordinal) }
$firstCleanupDeletion = @($cleanupDeletionOffsets | Where-Object { $_ -ge 0 } | Sort-Object | Select-Object -First 1)
$generationPreflight = $telemetryScript.LastIndexOf(
    'Assert-GenerationNamesAvailable',
    [StringComparison]::Ordinal
)
$generationShouldProcess = $telemetryScript.IndexOf(
    '$PSCmdlet.ShouldProcess($labRoot',
    $generationPreflight,
    [StringComparison]::Ordinal
)
$generationFirstWrite = $telemetryScript.IndexOf(
    '    New-Item -ItemType Directory -Path $labRoot',
    [StringComparison]::Ordinal
)
$ownedDirectoryStart = $telemetryScript.IndexOf('function Remove-OwnedDirectory', [StringComparison]::Ordinal)
$ownedDirectoryEnd = if ($ownedDirectoryStart -ge 0) {
    $telemetryScript.IndexOf('function Assert-GenerationNamesAvailable', $ownedDirectoryStart, [StringComparison]::Ordinal)
} else {
    -1
}
$ownedDirectoryBlock = if ($ownedDirectoryStart -ge 0 -and $ownedDirectoryEnd -gt $ownedDirectoryStart) {
    $telemetryScript.Substring($ownedDirectoryStart, $ownedDirectoryEnd - $ownedDirectoryStart)
} else {
    ''
}
$freshDirectoryInventoryOffset = $ownedDirectoryBlock.IndexOf(
    '$items = @(Get-ChildItem -LiteralPath $Path -Force)',
    [StringComparison]::Ordinal
)
$freshDirectoryValidationOffset = $ownedDirectoryBlock.IndexOf(
    'Test-LabDirectoryItemAllowed -Item $item -Kind $Kind',
    $freshDirectoryInventoryOffset,
    [StringComparison]::Ordinal
)
$freshDirectoryDeleteOffset = $ownedDirectoryBlock.IndexOf(
    'Remove-Item -LiteralPath $item.FullName -Force',
    [StringComparison]::Ordinal
)
$telemetryContracts = [ordered]@{
    'custom event-log cleanup is exact' = $telemetryScript -match 'Remove-EventLog\s+-LogName\s+\$eventLogName'
    'generation preflights every reserved name before writing' = $generationPreflight -ge 0 -and
        $generationShouldProcess -gt $generationPreflight -and
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
        $cleanupBlock -match 'Get-CustomEventLogSources' -and
        $cleanupBlock -match 'Test-DirectoryOwned' -and
        $telemetryScript -match 'Get-ScheduledTask' -and
        $telemetryScript -match [regex]::Escape("Refusing to treat '`$taskName' as absent.")
    'legacy task ownership requires the registry marker' = $telemetryScript -match [regex]::Escape(
        "return (`$arguments -ceq '/c exit 0' -and `$LegacyRegistryMarkerPresent)"
    )
    'task ownership rejects additional or non-Exec actions' =
        $telemetryScript -match '\$actionNodes = @\(\$TaskXml\.SelectNodes' -and
        $telemetryScript -match '\$execNodes = @\(\$TaskXml\.SelectNodes' -and
        $telemetryScript -match '\$actionNodes\.Count -ne 1 -or \$execNodes\.Count -ne 1'
    'registry cleanup removes only the exact marker value' =
        $cleanupBlock -match 'Remove-ItemProperty' -and
        $cleanupBlock -match '\(Get-RegistryMarkerValue\) -cne \$registryValueData' -and
        $cleanupBlock -match '-Name \$registryValueName'
    'native command failures are enforced' = $telemetryScript -match 'function\s+Assert-NativeCommandSucceeded' -and
        $telemetryScript -match 'if\s*\(\$LASTEXITCODE\s+-ne\s+0\)' -and
        ([regex]::Matches($telemetryScript, 'Assert-NativeCommandSucceeded\s+-Operation')).Count -ge 4
    'directory cleanup requires ownership markers and allowlisted contents' = $telemetryScript -match 'ownershipMarkerName' -and
        $telemetryScript -match 'Test-DirectoryContentsAreLabOnly' -and
        $telemetryScript -match 'LegacyRegistryMarkerPresent' -and
        $telemetryScript -match 'Remove-Item -LiteralPath \$Path -ErrorAction Stop' -and
        $telemetryScript -notmatch '(?m)^\s*Remove-Item[^\r\n]*\$(?:directory\.Path|Path)[^\r\n]*-Recurse'
    'fresh directory inventory is revalidated before exact leaf deletion' =
        $freshDirectoryInventoryOffset -ge 0 -and
        $freshDirectoryValidationOffset -gt $freshDirectoryInventoryOffset -and
        $freshDirectoryDeleteOffset -gt $freshDirectoryValidationOffset -and
        $ownedDirectoryBlock -match 'gained an unrecognized item after preflight\. Refusing cleanup'
    'event-log cleanup refuses any unexpected source' =
        $cleanupBlock -match '\$eventSources\.Count -ne 1' -and
        $cleanupBlock -match '\$eventSources\[0\] -cne \$eventSource' -and
        $cleanupBlock -match '\$currentEventSources\.Count -ne 1'
    'WhatIf performs read-only ownership and collision preflights' =
        $telemetryScript -match '(?s)if\s*\(\$WhatIfPreference\)\s*\{\s*Remove-LabArtifacts -Preview' -and
        $generationPreflight -lt $generationShouldProcess
    'declined operations are not reported as completed' =
        $telemetryScript -match "'cleanup-declined'" -and
        $telemetryScript -match "'generate-declined'" -and
        ([regex]::Matches($telemetryScript, 'Completed = if \(\$\w+Completed\)')).Count -eq 2
    'generation rechecks collision-prone names before writes' =
        $telemetryScript -match 'appeared after preflight\. Refusing overwrite' -and
        $telemetryScript -match 'appeared after preflight\. Refusing reuse'
}
foreach ($contract in $telemetryContracts.GetEnumerator()) {
    if (-not $contract.Value) {
        throw "Safe telemetry contract failed: $($contract.Key)."
    }
}

$telemetryTokens = $null
$telemetryParseErrors = $null
$telemetryAst = [System.Management.Automation.Language.Parser]::ParseInput(
    $telemetryScript,
    [ref]$telemetryTokens,
    [ref]$telemetryParseErrors
)
if ($telemetryParseErrors.Count -gt 0) {
    throw 'Unable to parse the safe telemetry harness for task-ownership behavior tests.'
}
$taskOwnershipFunction = @(
    $telemetryAst.FindAll(
        {
            param($Ast)
            $Ast -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $Ast.Name -ceq 'Test-LabTaskOwned'
        },
        $true
    )
)
if ($taskOwnershipFunction.Count -ne 1) {
    throw 'Expected exactly one Test-LabTaskOwned function in the safe telemetry harness.'
}
Invoke-Expression $taskOwnershipFunction[0].Extent.Text

[xml]$currentOwnedTask = '<Task><Actions><Exec><Command>cmd.exe</Command><Arguments>/c rem NLS-GigaWiper-SafeTelemetry</Arguments></Exec></Actions></Task>'
[xml]$legacyOwnedTask = '<Task><Actions><Exec><Command>cmd.exe</Command><Arguments>/c exit 0</Arguments></Exec></Actions></Task>'
[xml]$additionalActionTask = '<Task><Actions><Exec><Command>cmd.exe</Command><Arguments>/c rem NLS-GigaWiper-SafeTelemetry</Arguments></Exec><Exec><Command>cmd.exe</Command><Arguments>/c exit 0</Arguments></Exec></Actions></Task>'
[xml]$nonExecTask = '<Task><Actions><ComHandler><ClassId>00000000-0000-0000-0000-000000000000</ClassId></ComHandler></Actions></Task>'
$taskOwnershipCases = [ordered]@{
    'current exact task is owned' = (Test-LabTaskOwned -TaskXml $currentOwnedTask -LegacyRegistryMarkerPresent $false)
    'legacy exact task requires marker' =
        -not (Test-LabTaskOwned -TaskXml $legacyOwnedTask -LegacyRegistryMarkerPresent $false) -and
        (Test-LabTaskOwned -TaskXml $legacyOwnedTask -LegacyRegistryMarkerPresent $true)
    'additional action is rejected' = -not (Test-LabTaskOwned -TaskXml $additionalActionTask -LegacyRegistryMarkerPresent $true)
    'non-Exec action is rejected' = -not (Test-LabTaskOwned -TaskXml $nonExecTask -LegacyRegistryMarkerPresent $true)
}
foreach ($case in $taskOwnershipCases.GetEnumerator()) {
    if (-not $case.Value) {
        throw "Safe telemetry task-ownership behavior failed: $($case.Key)."
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
$actionCounterStart = $graphFallback.IndexOf(
    'function Get-DetectionResponseActionCount',
    [StringComparison]::Ordinal
)
$actionCounterEnd = if ($actionCounterStart -ge 0) {
    $graphFallback.IndexOf(
        'function Assert-DesiredDetectionIsOwnedAndAlertOnly',
        $actionCounterStart,
        [StringComparison]::Ordinal
    )
} else {
    -1
}
if ($actionCounterStart -lt 0 -or $actionCounterEnd -le $actionCounterStart) {
    throw 'Unable to isolate the Graph response-action counter for behavioral regression tests.'
}
. ([scriptblock]::Create($graphFallback.Substring(
    $actionCounterStart,
    $actionCounterEnd - $actionCounterStart
)))
$actionModelCases = @(
    [pscustomobject]@{
        Name = 'alert-only hashtable'
        Action = [ordered]@{ alertTemplate = @{} }
        Expected = 0
    },
    [pscustomobject]@{
        Name = 'deprecated response action'
        Action = [ordered]@{ alertTemplate = @{}; responseActions = @(@{ type = 'isolate' }) }
        Expected = 1
    },
    [pscustomobject]@{
        Name = 'current hashtable action'
        Action = [ordered]@{
            alertTemplate = @{}
            automatedActions = [ordered]@{ isolateDevice = @(@{ mode = 'test' }) }
        }
        Expected = 1
    },
    [pscustomobject]@{
        Name = 'current PSCustomObject actions'
        Action = [pscustomobject]@{
            alertTemplate = @{}
            automatedActions = [pscustomobject]@{
                isolateDevice = @(@{ mode = 'one' }, @{ mode = 'two' })
            }
        }
        Expected = 2
    },
    [pscustomobject]@{
        Name = 'metadata-only current action model'
        Action = [ordered]@{
            alertTemplate = @{}
            automatedActions = [ordered]@{ '@odata.type' = '#microsoft.graph.security.automatedActions' }
        }
        Expected = 0
    }
)
foreach ($case in $actionModelCases) {
    $actualActionCount = Get-DetectionResponseActionCount -DetectionAction $case.Action
    if ($actualActionCount -ne $case.Expected) {
        throw "Graph response-action regression '$($case.Name)' expected $($case.Expected), got $actualActionCount."
    }
}
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
$ownershipGuardStart = $graphFallback.IndexOf(
    'function Assert-DesiredDetectionIsOwnedAndAlertOnly',
    [StringComparison]::Ordinal
)
$ownershipGuardEnd = if ($ownershipGuardStart -ge 0) {
    $graphFallback.IndexOf('function ConvertTo-UtcIsoTimestamp', $ownershipGuardStart, [StringComparison]::Ordinal)
} else {
    -1
}
$ownershipGuardBlock = if ($ownershipGuardStart -ge 0 -and $ownershipGuardEnd -gt $ownershipGuardStart) {
    $graphFallback.Substring($ownershipGuardStart, $ownershipGuardEnd - $ownershipGuardStart)
} else {
    ''
}
$latestGuardStart = $graphFallback.IndexOf(
    'function Get-LatestOwnedAlertOnlyDetection',
    [StringComparison]::Ordinal
)
$latestGuardEnd = if ($latestGuardStart -ge 0) {
    $graphFallback.IndexOf('$results = foreach ($rule in $compiledRules)', $latestGuardStart, [StringComparison]::Ordinal)
} else {
    -1
}
$latestGuardBlock = if ($latestGuardStart -ge 0 -and $latestGuardEnd -gt $latestGuardStart) {
    $graphFallback.Substring($latestGuardStart, $latestGuardEnd - $latestGuardStart)
} else {
    ''
}
$existingGetOffset = $applyBlock.IndexOf('$existing = Invoke-DetectionGraphRequest', [StringComparison]::Ordinal)
$existingGuardOffset = $applyBlock.IndexOf(
    'Assert-ExistingDetectionIsOwnedAndAlertOnly `',
    [StringComparison]::Ordinal
)
$raceGetOffset = $applyBlock.IndexOf('$raceCheck = Invoke-DetectionGraphRequest', [StringComparison]::Ordinal)
$raceGuardOffset = $applyBlock.IndexOf(
    'Assert-ExistingDetectionIsOwnedAndAlertOnly `',
    $existingGuardOffset + 1,
    [StringComparison]::Ordinal
)
$firstPatchOffset = $applyBlock.IndexOf('-Method PATCH', [StringComparison]::Ordinal)
$lastPatchOffset = $applyBlock.LastIndexOf('-Method PATCH', [StringComparison]::Ordinal)
$firstLatestOwnershipCheckOffset = $applyBlock.IndexOf(
    'Get-LatestOwnedAlertOnlyDetection `',
    [StringComparison]::Ordinal
)
$secondLatestOwnershipCheckOffset = $applyBlock.IndexOf(
    'Get-LatestOwnedAlertOnlyDetection `',
    $firstLatestOwnershipCheckOffset + 1,
    [StringComparison]::Ordinal
)
$desiredPreflightOffset = $graphFallback.IndexOf(
    'Assert-DesiredDetectionIsOwnedAndAlertOnly -Rule $rule',
    [StringComparison]::Ordinal
)
$planOffset = $graphFallback.IndexOf("if (`$Mode -eq 'Plan')", [StringComparison]::Ordinal)
$fallbackContracts = [ordered]@{
    'manual-only workflow' = $fallbackWorkflow -match '(?m)^\s*workflow_dispatch:' -and $fallbackWorkflow -notmatch '(?m)^\s*(push|pull_request):'
    'all token-bearing modes require the main branch' =
        $fallbackWorkflow -match "(?s)github\.ref == 'refs/heads/main'\s*&&\s*\(\(inputs\.operation == 'Inspect'.*inputs\.operation == 'Apply'" -and
        $fallbackWorkflow -notmatch "(?s)\(inputs\.operation == 'Inspect'.*\|\|\s*\(github\.ref == 'refs/heads/main'"
    'protected environment' = $fallbackWorkflow -match '(?m)^\s*environment:\s*custom-detection-fallback\s*$'
    'OIDC without subscription RBAC' = $fallbackWorkflow -match '(?m)^\s*allow-no-subscriptions:\s*true\s*$' -and $fallbackWorkflow -notmatch '(?m)^\s*subscription-id:'
    'pinned actions' = $fallbackWorkflow -match 'actions/checkout@[0-9a-f]{40}' -and $fallbackWorkflow -match 'azure/login@[0-9a-f]{40}'
    'exact-ID upsert' = $graphFallback -match 'detectionRules' -and $graphFallback -match 'EscapeDataString' -and $graphFallback -match "ValidateSet\('GET', 'POST', 'PATCH'\)"
    'MITRE sub-technique normalization' = $graphFallback -match 'subTechniques' -and $graphFallback -match 'GetMitreFingerprints'
    'no delete or pruning' = $graphFallback -notmatch "ValidateSet\([^\r\n]*'DELETE'" -and $graphFallback -notmatch '(?i)prune'
    'app-only permission guidance' = $graphFallback -match 'CustomDetection\.ReadWrite\.All'
    'manual read-only inspection' = $graphFallback -match "ValidateSet\('Plan', 'Apply', 'Inspect'\)" -and $fallbackWorkflow -match 'INSPECT_PREVIEW_FALLBACK'
    'inspection uses exact-ID GET only' = $inspectBlock -match 'EscapeDataString' -and $inspectBlock -match '(?m)-Method GET' -and $inspectBlock -notmatch '(?m)-Method (POST|PATCH)'
    'inspection requests only allowlisted metadata and tolerates deprecated removal' =
        $inspectBlock -match '\?\$select=id,description,status,schedule,lastRunDetails,detectionAction' -and
        $inspectBlock -match '\?\$select=id,description,status,schedule,detectionAction' -and
        $inspectBlock -match '-AllowedStatus @\(200, 400, 404\)' -and
        $inspectBlock -match 'if\s*\(\$response\.StatusCode\s*-eq\s*400\)' -and
        $graphFallback -match 'function\s+Get-OptionalObjectProperty' -and
        $graphFallback -match 'Get-OptionalObjectProperty\s+-InputObject\s+\$Rule\s+-Name\s+''lastRunDetails'''
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
    'inspection verifies ownership without exposing the marker' =
        $graphFallback -match 'function\s+Assert-DetectionHasOwnershipMarker' -and
        $inspectBlock -match 'Assert-DetectionHasOwnershipMarker\s+-RuleId\s+\$ruleId\s+-Rule\s+\$response\.Body' -and
        $inspectBlock -notmatch '(?m)^\s*Description\s*='
    'all modes enforce both response-action models' = $graphFallback -match 'responseActions' -and
        $graphFallback -match 'automatedActions\.PSObject\.Properties' -and
        $graphFallback -match '\$automatedActions -is \[System\.Collections\.IDictionary\]' -and
        $graphFallback -match '\$automatedActions\.Keys' -and
        $graphFallback -match "property\.Name -notlike '@\*'" -and
        $graphFallback -match '\$responseActionCount\s*=\s*Get-DetectionResponseActionCount' -and
        $graphFallback -match 'ResponseActions\s*=\s*Get-DetectionResponseActionCount'
    'desired rules are marker-owned and alert-only before every mode' =
        $ownershipGuardBlock -match 'function\s+Assert-DesiredDetectionIsOwnedAndAlertOnly' -and
        $ownershipGuardBlock -match '\[string\]\$Rule\.description -cne \$ownershipMarker' -and
        $ownershipGuardBlock -match 'Refusing any tenant mutation' -and
        $desiredPreflightOffset -ge 0 -and
        $desiredPreflightOffset -lt $planOffset
    'apply refuses unowned or armed exact-ID rules before update' =
        $graphFallback -match 'function\s+Assert-ExistingDetectionIsOwnedAndAlertOnly' -and
        ([regex]::Matches($graphFallback, 'Assert-ExistingDetectionIsOwnedAndAlertOnly\s+`')).Count -eq 3 -and
        $ownershipGuardBlock -match 'Assert-DetectionHasOwnershipMarker -RuleId \$RuleId -Rule \$Rule' -and
        $ownershipGuardBlock -match 'Existing rule ''\$RuleId'' has' -and
        $ownershipGuardBlock -match 'Get-DetectionResponseActionCount\s+-DetectionAction\s+\$Rule\.detectionAction' -and
        $ownershipGuardBlock -match 'if\s*\(\$responseActionCount\s+-gt\s+0\)' -and
        $ownershipGuardBlock -match "Refusing to modify an armed rule" -and
        $existingGetOffset -ge 0 -and
        $existingGuardOffset -gt $existingGetOffset -and
        $raceGetOffset -gt $existingGuardOffset -and
        $raceGuardOffset -gt $raceGetOffset -and
        $firstPatchOffset -gt $raceGuardOffset
    'both PATCH paths immediately re-read ownership and action state' =
        $graphFallback -match 'function\s+Get-LatestOwnedAlertOnlyDetection' -and
        ([regex]::Matches($applyBlock, 'Get-LatestOwnedAlertOnlyDetection\s+`')).Count -eq 2 -and
        $firstLatestOwnershipCheckOffset -gt $raceGuardOffset -and
        $firstPatchOffset -gt $firstLatestOwnershipCheckOffset -and
        $secondLatestOwnershipCheckOffset -gt $firstPatchOffset -and
        $lastPatchOffset -gt $secondLatestOwnershipCheckOffset -and
        $latestGuardBlock -match '\$latest = Invoke-DetectionGraphRequest -Method GET' -and
        $latestGuardBlock -match 'Assert-ExistingDetectionIsOwnedAndAlertOnly\s+`' -and
        $latestGuardBlock -match 'Rule .* disappeared immediately before update'
    'ownership marker is included in update and post-write verification' =
        $graphFallback -match [regex]::Escape("`$ownershipMarker = '$detectionOwnershipMarker'") -and
        $graphFallback -match 'foreach \(\$key in @\(''displayName'', ''description'', ''status''' -and
        $graphFallback -match 'description = \[string\]\$Actual\.description' -and
        $graphFallback -match 'description = \[string\]\$Expected\.description'
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

$retainedNativeRoot = Join-Path $root 'evidence\generated\sentinel-repository'
$nativeWorkflowFile = Join-Path $retainedNativeRoot 'sentinel-deploy-51af5a44-e148-40f0-b250-6457efb89a6c.yml'
$nativeWorkflow = Get-Content -LiteralPath $nativeWorkflowFile -Raw
$nativeHelperFile = Join-Path $retainedNativeRoot 'azure-sentinel-deploy-51af5a44-e148-40f0-b250-6457efb89a6c.ps1'
$nativeHelper = Get-Content -LiteralPath $nativeHelperFile -Raw
$activeWorkflowRoot = Join-Path $root '.github\workflows'
$activeWorkflowFiles = @(Get-ChildItem -LiteralPath $activeWorkflowRoot -File | Where-Object {
    $_.Extension -in @('.yml', '.yaml', '.ps1')
})
$activeWorkflowContent = ($activeWorkflowFiles | ForEach-Object {
    Get-Content -LiteralPath $_.FullName -Raw
}) -join "`n"
$activeWriterFiles = @($activeWorkflowFiles | Where-Object {
    (Get-Content -LiteralPath $_.FullName -Raw) -match 'Deploy-CustomDetectionsGraph\.ps1|DEPLOY_NATIVE_SENTINEL_CONTENT'
})
$legacyNativeWorkflowFile = Join-Path $activeWorkflowRoot 'sentinel-deploy-51af5a44-e148-40f0-b250-6457efb89a6c.yml'
$legacyNativeHelperFile = Join-Path $activeWorkflowRoot 'azure-sentinel-deploy-51af5a44-e148-40f0-b250-6457efb89a6c.ps1'
$validateWorkflow = Get-Content -LiteralPath (Join-Path $root '.github\workflows\validate.yml') -Raw
$nativeUses = @([regex]::Matches($nativeWorkflow, '(?m)^\s*uses:\s*([^\s#]+)') | ForEach-Object { $_.Groups[1].Value })
$nativeConcurrency = [regex]::Match($nativeWorkflow, '(?m)^\s*group:\s*([^\s#]+)\s*$').Groups[1].Value
$fallbackConcurrency = [regex]::Match($fallbackWorkflow, '(?m)^\s*group:\s*([^\s#]+)\s*$').Groups[1].Value
$workflowContracts = [ordered]@{
    'native files are retained outside the active workflow directory' =
        $nativeWorkflowFile.StartsWith($retainedNativeRoot, [StringComparison]::OrdinalIgnoreCase) -and
        $nativeHelperFile.StartsWith($retainedNativeRoot, [StringComparison]::OrdinalIgnoreCase)
    'retained native files carry non-reuse provenance notices' =
        $nativeWorkflow -match 'RETAINED VALIDATION ARTIFACT - NOT AN ACTIVE OR REUSABLE WORKFLOW' -and
        $nativeHelper -match 'RETAINED VALIDATION ARTIFACT - NOT AN ACTIVE OR REUSABLE HELPER' -and
        $nativeWorkflow -match 'Create a new Repository connection in your own environment' -and
        $nativeHelper -match 'must\s*\r?\n?#?\s*generate its own workflow and helper'
    'no native writer remains active' = -not (Test-Path -LiteralPath $legacyNativeWorkflowFile) -and
        -not (Test-Path -LiteralPath $legacyNativeHelperFile) -and
        $activeWorkflowContent -notmatch 'DEPLOY_NATIVE_SENTINEL_CONTENT' -and
        $activeWorkflowContent -notmatch 'azure-sentinel-deploy-51af5a44-e148-40f0-b250-6457efb89a6c'
    'Graph fallback is the only active custom-detection writer' = $activeWriterFiles.Count -eq 1 -and
        $activeWriterFiles[0].FullName -eq $fallbackWorkflowFile
    'retained native workflow was manual-only' = $nativeWorkflow -match '(?m)^\s*workflow_dispatch:' -and
        $nativeWorkflow -notmatch '(?m)^\s*(push|pull_request):'
    'retained native workflow required exact confirmation and main' =
        $nativeWorkflow -match "inputs\.confirmation == 'DEPLOY_NATIVE_SENTINEL_CONTENT'" -and
        $nativeWorkflow -match "github\.ref == 'refs/heads/main'"
    'retained native workflow actions are SHA-pinned' = $nativeUses.Count -gt 0 -and
        @($nativeUses | Where-Object { $_ -notmatch '@[0-9a-f]{40}$' }).Count -eq 0 -and
        ([regex]::Matches($nativeWorkflow, 'azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5')).Count -eq 3 -and
        ([regex]::Matches($nativeWorkflow, 'azure/powershell@53dd145408794f7e80f97cfcca04155c85234709')).Count -eq 1
    'retained native workflow uses fixed tool versions' =
        $nativeWorkflow -match "(?m)^\s*azPSVersion:\s*'[0-9]+\.[0-9]+\.[0-9]+'\s*$" -and
        $nativeWorkflow -match '(?m)^\s*run:\s*az bicep install --version v0\.45\.6\s*$'
    'retained native helper builds through Azure CLI Bicep' = $nativeHelper -match 'az bicep build --file \$path --stdout --only-show-errors' -and
        $nativeHelper -notmatch '(?m)^\s*\$templateObject\s*=\s*bicep build\s'
    'validation dependencies and runner are pinned' =
        $validateWorkflow -match 'actions/checkout@[0-9a-f]{40}' -and
        $validateWorkflow -match 'az bicep install --version v[0-9]+\.[0-9]+\.[0-9]+' -and
        $validateWorkflow -match '(?m)^\s*runs-on:\s*ubuntu-24\.04\s*$' -and
        $validateWorkflow -match '(?m)^\s*persist-credentials:\s*false\s*$'
    'active Graph writer retains the validated serialization lock' =
        $fallbackConcurrency -eq 'nls-gigawiper-custom-detection-writer' -and
        $fallbackWorkflow -match '(?m)^\s*cancel-in-progress:\s*false\s*$'
    'retained native artifact records the historical shared lock' =
        $nativeConcurrency -eq 'nls-gigawiper-custom-detection-writer' -and
        $fallbackConcurrency -eq $nativeConcurrency -and
        $nativeWorkflow -match '(?m)^\s*cancel-in-progress:\s*false\s*$'
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
    TelemetryTaskModelCases = $taskOwnershipCases.Count
    InfrastructureCompiled = $true
    InfrastructureContracts = $infraContracts.Count
    DirectDeploymentContracts = $directDeploymentContracts.Count
    EndpointLifecycleContracts = $endpointContracts.Count
    EndpointInventoryModelCases = $endpointInventoryCases.Count
    InboundSecurityRules = 0
    MdeOnboardingPackage = 'ARM reference; not stored'
    SyntheticTests = $expectedSyntheticTests.Count
    SyntheticPositiveTests = @($expectedSyntheticTests | Where-Object { $_ -like '*Positive' }).Count
    SyntheticNegativeTests = @($expectedSyntheticTests | Where-Object { $_ -like '*Negative' }).Count
    SyntheticBranchContracts = $requiredFixtureBranches.Count
    CandyWindowContracts = $candyWindowContracts.Count
    LiveSyntheticRunnerPresent = $true
    GraphActionModelCases = $actionModelCases.Count
    FallbackContracts = $fallbackContracts.Count
    WorkflowContracts = $workflowContracts.Count
    Results = $results
}

if ($Json) {
    $summary | ConvertTo-Json -Depth 5
} else {
    $results | Format-Table -AutoSize
    Write-Host "Validated $($files.Count) detection templates, the zero-inbound endpoint template, $($ids.Count) unique IDs, $($expectedSyntheticTests.Count) positive/negative synthetic contracts, $($forbidden.Count) destructive-string boundaries, $($infraContracts.Count) infrastructure controls, $($directDeploymentContracts.Count) direct-deployment controls, $($endpointContracts.Count) endpoint lifecycle controls, $($telemetryContracts.Count) telemetry ownership controls, $($fallbackContracts.Count) fallback controls, and $($workflowContracts.Count) workflow controls."
}
