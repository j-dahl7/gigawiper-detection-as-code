[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidatePattern('^[A-Za-z0-9._()-]{1,90}$')]
    [string]$ResourceGroup = 'nls-gigawiper-dac-lab-rg',

    [ValidatePattern('^[a-z0-9]+$')]
    [string]$Location = 'centralus',

    [ValidatePattern('^[A-Za-z0-9-]{1,15}$')]
    [string]$VmName = 'nls-gw-win-lab',

    [string]$ExpirationDate = (Get-Date).AddDays(1).ToString('yyyy-MM-dd'),

    [Parameter(Mandatory)]
    [ValidatePattern('^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$')]
    [string]$ImageVersion,

    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.gigawiper-endpoint.json'),

    [switch]$ReuseOwnedLabResourceGroup
)

$ErrorActionPreference = 'Stop'
$OwnerMarker = 'nine-lives-gigawiper:endpoint:v1'
$OwnerTag = 'nlzt-owner'
$DeploymentTag = 'nlzt-deployment'
$ManifestPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ManifestPath)

$AzAccountsVersion = '5.3.3'
$AzResourcesVersion = '9.0.3'
Import-Module -Name Az.Accounts -RequiredVersion $AzAccountsVersion -ErrorAction Stop
Import-Module -Name Az.Resources -RequiredVersion $AzResourcesVersion -ErrorAction Stop

$context = Get-AzContext
if (-not $context -or -not $context.Subscription.Id -or -not $context.Tenant.Id) {
    throw 'An authenticated Az PowerShell context with a tenant and subscription is required.'
}
$subscriptionId = [string]$context.Subscription.Id
$tenantId = [string]$context.Tenant.Id
$expectedResourceGroupId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup"

function Normalize-ResourceId {
    param([Parameter(Mandatory)][string]$ResourceId)
    return $ResourceId.TrimEnd('/').ToLowerInvariant()
}

function Get-ExactResourceGroup {
    $resourceGroupMatches = @(
        Get-AzResourceGroup -ErrorAction Stop |
            Where-Object {
                [string]::Equals(
                    [string]$_.ResourceGroupName,
                    $ResourceGroup,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    if ($resourceGroupMatches.Count -gt 1) {
        throw "Azure returned multiple resource groups matching '$ResourceGroup'."
    }
    if ($resourceGroupMatches.Count -eq 1) {
        return $resourceGroupMatches[0]
    }
    return $null
}

function Read-EndpointManifest {
    try {
        return Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Endpoint manifest '$ManifestPath' is not valid JSON."
    }
}

function Assert-EndpointManifest {
    param([Parameter(Mandatory)][object]$Manifest)

    $required = @(
        'schema_version', 'status', 'owner_marker', 'deployment_id',
        'tenant_id', 'subscription_id', 'resource_group_name',
        'resource_group_id', 'location', 'vm_name', 'image_version'
    )
    foreach ($field in $required) {
        if ($Manifest.PSObject.Properties.Name -notcontains $field -or
            [string]::IsNullOrWhiteSpace([string]$Manifest.$field)) {
            throw "Endpoint manifest is missing required field '$field'."
        }
    }
    if ([int]$Manifest.schema_version -ne 1 -or
        [string]$Manifest.status -notin @('planned', 'deployed')) {
        throw 'Endpoint manifest has an unsupported schema or state.'
    }
    if ([string]$Manifest.owner_marker -cne $OwnerMarker) {
        throw 'Endpoint manifest owner marker is invalid.'
    }
    $parsedDeploymentId = [guid]::Empty
    if (-not [guid]::TryParse([string]$Manifest.deployment_id, [ref]$parsedDeploymentId)) {
        throw 'Endpoint manifest deployment_id is not a UUID.'
    }
    if (-not [string]::Equals([string]$Manifest.tenant_id, $tenantId, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$Manifest.subscription_id, $subscriptionId, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Endpoint manifest tenant or subscription does not match the active Az context.'
    }
    if ([string]$Manifest.resource_group_name -cne $ResourceGroup -or
        (Normalize-ResourceId ([string]$Manifest.resource_group_id)) -ne
        (Normalize-ResourceId $expectedResourceGroupId)) {
        throw 'Endpoint manifest resource-group identity is inconsistent with this request.'
    }
    if (-not [string]::Equals([string]$Manifest.location, $Location, [StringComparison]::OrdinalIgnoreCase) -or
        [string]$Manifest.vm_name -cne $VmName -or
        [string]$Manifest.image_version -cne $ImageVersion) {
        throw 'Endpoint manifest location, VM name, or pinned image version does not match this request.'
    }
}

function Write-EndpointManifest {
    param(
        [Parameter(Mandatory)][ValidateSet('planned', 'deployed')][string]$Status,
        [Parameter(Mandatory)][string]$DeploymentId,
        [string]$VirtualMachineId = '',
        [switch]$CreateOnly
    )

    $manifestDirectory = Split-Path -Parent $ManifestPath
    if (-not (Test-Path -LiteralPath $manifestDirectory -PathType Container)) {
        throw "Endpoint manifest directory does not exist: $manifestDirectory"
    }
    $data = [ordered]@{
        schema_version = 1
        status = $Status
        owner_marker = $OwnerMarker
        deployment_id = $DeploymentId
        tenant_id = $tenantId
        subscription_id = $subscriptionId
        resource_group_name = $ResourceGroup
        resource_group_id = $expectedResourceGroupId
        location = $Location
        vm_name = $VmName
        image_version = $ImageVersion
        expiration_date = $ExpirationDate
    }
    if (-not [string]::IsNullOrWhiteSpace($VirtualMachineId)) {
        $data.virtual_machine_id = $VirtualMachineId
    }

    $temporaryPath = "$ManifestPath.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            ($data | ConvertTo-Json -Depth 4),
            [Text.UTF8Encoding]::new($false)
        )
        if ($CreateOnly) {
            # File.Move without overwrite is the create-only boundary for the
            # first manifest. A concurrent run that won the name makes this
            # operation fail instead of replacing its ownership record.
            [IO.File]::Move($temporaryPath, $ManifestPath)
        }
        else {
            Move-Item -LiteralPath $temporaryPath -Destination $ManifestPath -Force
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Assert-OwnedResourceGroup {
    param(
        [Parameter(Mandatory)][object]$Group,
        [Parameter(Mandatory)][string]$DeploymentId
    )

    if ((Normalize-ResourceId ([string]$Group.ResourceId)) -ne
        (Normalize-ResourceId $expectedResourceGroupId)) {
        throw 'Live resource-group ID does not match the endpoint manifest.'
    }
    if ([string]$Group.Tags[$OwnerTag] -cne $OwnerMarker -or
        [string]$Group.Tags[$DeploymentTag] -cne $DeploymentId) {
        throw 'Live resource group does not have the exact manifest-bound ownership tags.'
    }
    if (-not [string]::Equals([string]$Group.Location, $Location, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Resource group '$ResourceGroup' is in '$($Group.Location)', not requested location '$Location'."
    }
}

function Assert-EndpointResourceGroupEmpty {
    $resources = @(Get-AzResource -ResourceGroupName $ResourceGroup -ErrorAction Stop)
    if ($resources.Count -ne 0) {
        throw "Resource group '$ResourceGroup' contains $($resources.Count) resource(s). Refusing incremental child-resource adoption or update; clean up and create a fresh endpoint group."
    }
}

$parsedExpiration = [datetime]::MinValue
if (-not [datetime]::TryParseExact(
        $ExpirationDate,
        'yyyy-MM-dd',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None,
        [ref]$parsedExpiration
    )) {
    throw "ExpirationDate must be a real calendar date in yyyy-MM-dd format; received '$ExpirationDate'."
}
if ($parsedExpiration.Date -lt (Get-Date).Date) {
    throw "ExpirationDate '$ExpirationDate' is in the past."
}

$manifest = if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
    Read-EndpointManifest
}
else {
    $null
}
if ($manifest) {
    Assert-EndpointManifest -Manifest $manifest
}

$group = Get-ExactResourceGroup

if ($group) {
    if (-not $ReuseOwnedLabResourceGroup) {
        throw "Resource group '$ResourceGroup' already exists. Refusing reuse without -ReuseOwnedLabResourceGroup."
    }
    if (-not $manifest) {
        throw "Resource group '$ResourceGroup' exists but endpoint manifest '$ManifestPath' is missing. Refusing adoption."
    }
    if ([string]$manifest.status -cne 'planned') {
        throw "Only an empty manifest-owned group in planned state can be resumed. Preview cleanup and create a fresh group instead."
    }
    Assert-OwnedResourceGroup -Group $group -DeploymentId ([string]$manifest.deployment_id)
    Assert-EndpointResourceGroupEmpty
}
elseif ($manifest -and [string]$manifest.status -eq 'deployed') {
    throw "Endpoint manifest is deployed, but its resource group is absent. Use the cleanup helper to finalize the stale manifest."
}

$deploymentId = if ($manifest) { [string]$manifest.deployment_id } else { [guid]::NewGuid().ToString() }
if (-not $PSCmdlet.ShouldProcess($expectedResourceGroupId, 'Create or resume exact manifest-owned disposable endpoint')) {
    [pscustomobject]@{
        Operation = if ($WhatIfPreference) { 'preview' } else { 'declined' }
        ResourceGroup = $ResourceGroup
        DeploymentId = $deploymentId
        ManifestChanged = $false
    }
    return
}

# Confirmation can be interactive and long-lived. Re-read both ownership
# boundaries after approval before creating or changing anything.
if ($manifest) {
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw 'Endpoint manifest disappeared after approval. Refusing Azure mutation.'
    }
    $currentManifest = Read-EndpointManifest
    Assert-EndpointManifest -Manifest $currentManifest
    if ([string]$currentManifest.deployment_id -cne $deploymentId) {
        throw 'Endpoint manifest deployment identity changed after approval. Refusing Azure mutation.'
    }
    $manifest = $currentManifest
}
elseif (Test-Path -LiteralPath $ManifestPath) {
    throw 'Endpoint manifest appeared after approval. Refusing overwrite.'
}

$currentGroup = Get-ExactResourceGroup
if ($group) {
    if (-not $currentGroup) {
        throw "Resource group '$ResourceGroup' disappeared after approval. Refusing recreation."
    }
    Assert-OwnedResourceGroup -Group $currentGroup -DeploymentId $deploymentId
    Assert-EndpointResourceGroupEmpty
    $group = $currentGroup
}
elseif ($currentGroup) {
    throw "Resource group '$ResourceGroup' appeared after approval. Refusing adoption or update."
}

if (-not $manifest) {
    Write-EndpointManifest -Status planned -DeploymentId $deploymentId -CreateOnly
    $manifest = Read-EndpointManifest
}

$lowercase = 'abcdefghijkmnopqrstuvwxyz'
$uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
$numbers = '23456789'
$symbols = '!@#$%'
$alphabet = $lowercase + $uppercase + $numbers + $symbols
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
function Get-CryptographicIndex {
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 255)]
        [int]$MaximumExclusive
    )

    $buffer = [byte[]]::new(1)
    $limit = 256 - (256 % $MaximumExclusive)
    do {
        $rng.GetBytes($buffer)
    } while ([int]$buffer[0] -ge $limit)
    return [int]$buffer[0] % $MaximumExclusive
}

try {
    $passwordCharacters = [Collections.Generic.List[char]]::new()
    foreach ($characterSet in @($lowercase, $uppercase, $numbers, $symbols)) {
        $passwordCharacters.Add($characterSet[(Get-CryptographicIndex -MaximumExclusive $characterSet.Length)])
    }
    while ($passwordCharacters.Count -lt 32) {
        $passwordCharacters.Add($alphabet[(Get-CryptographicIndex -MaximumExclusive $alphabet.Length)])
    }
    for ($index = $passwordCharacters.Count - 1; $index -gt 0; $index--) {
        $swapIndex = Get-CryptographicIndex -MaximumExclusive ($index + 1)
        $temporary = $passwordCharacters[$index]
        $passwordCharacters[$index] = $passwordCharacters[$swapIndex]
        $passwordCharacters[$swapIndex] = $temporary
    }
    $plainPassword = -join $passwordCharacters
}
finally {
    $rng.Dispose()
}
$securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
Remove-Variable plainPassword

if (-not $group) {
    if ($null -ne (Get-ExactResourceGroup)) {
        throw "Resource group '$ResourceGroup' appeared immediately before creation. Refusing the name collision."
    }
    $group = New-AzResourceGroup -Name $ResourceGroup -Location $Location -Tag @{
        Purpose = 'GigaWiperDetectionAsCode'
        Owner = 'NineLives'
        Expiration = $ExpirationDate
        $OwnerTag = $OwnerMarker
        $DeploymentTag = $deploymentId
    }
}
else {
    $group = Get-ExactResourceGroup
    if (-not $group) {
        throw "Resource group '$ResourceGroup' disappeared immediately before tag update. Refusing recreation."
    }
    Assert-OwnedResourceGroup -Group $group -DeploymentId $deploymentId
    Assert-EndpointResourceGroupEmpty
    $updatedTags = @{}
    foreach ($tag in $group.Tags.GetEnumerator()) {
        $updatedTags[[string]$tag.Key] = [string]$tag.Value
    }
    $updatedTags.Expiration = $ExpirationDate
    $group = Set-AzResourceGroup -Name $ResourceGroup -Tag $updatedTags
}
Assert-OwnedResourceGroup -Group $group -DeploymentId $deploymentId
Assert-EndpointResourceGroupEmpty

$deploymentName = "nls-gw-safe-$($deploymentId.Replace('-', '').Substring(0, 12))"
$imageVersionParts = $ImageVersion.Split('.')
$imageVersionMajor = [long]::Parse($imageVersionParts[0], [Globalization.CultureInfo]::InvariantCulture)
$imageVersionMinor = [long]::Parse($imageVersionParts[1], [Globalization.CultureInfo]::InvariantCulture)
$imageVersionBuild = [long]::Parse($imageVersionParts[2], [Globalization.CultureInfo]::InvariantCulture)
$deployment = New-AzResourceGroupDeployment `
    -Name $deploymentName `
    -ResourceGroupName $ResourceGroup `
    -TemplateFile (Join-Path (Split-Path -Parent $PSScriptRoot) 'infra\lab-endpoint.bicep') `
    -vmName $VmName `
    -location $Location `
    -expirationDate $ExpirationDate `
    -imageVersionMajor $imageVersionMajor `
    -imageVersionMinor $imageVersionMinor `
    -imageVersionBuild $imageVersionBuild `
    -ownerMarker $OwnerMarker `
    -deploymentId $deploymentId `
    -adminPassword $securePassword `
    -Verbose:$false

if ([string]$deployment.ProvisioningState -cne 'Succeeded') {
    throw "Endpoint deployment state: $($deployment.ProvisioningState). The planned manifest was retained."
}
$outputResourceGroupId = [string]$deployment.Outputs.resourceGroupId.Value
$outputDeploymentId = [string]$deployment.Outputs.deploymentId.Value
$outputEndpointName = [string]$deployment.Outputs.endpointName.Value
$outputImageVersion = [string]$deployment.Outputs.imageVersion.Value
$virtualMachineId = [string]$deployment.Outputs.virtualMachineId.Value
$expectedVirtualMachineId = "$expectedResourceGroupId/providers/Microsoft.Compute/virtualMachines/$VmName"
if ((Normalize-ResourceId $outputResourceGroupId) -ne (Normalize-ResourceId $expectedResourceGroupId) -or
    $outputDeploymentId -cne $deploymentId -or
    $outputEndpointName -cne $VmName -or
    $outputImageVersion -cne $ImageVersion -or
    (Normalize-ResourceId $virtualMachineId) -ne (Normalize-ResourceId $expectedVirtualMachineId) -or
    [int]$deployment.Outputs.inboundSecurityRules.Value -ne 0) {
    throw 'Endpoint deployment returned an unexpected ownership identity. The planned manifest was retained.'
}
$group = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction Stop
Assert-OwnedResourceGroup -Group $group -DeploymentId $deploymentId
$manifestBeforeCompletion = Read-EndpointManifest
Assert-EndpointManifest -Manifest $manifestBeforeCompletion
if ([string]$manifestBeforeCompletion.deployment_id -cne $deploymentId) {
    throw 'Endpoint manifest deployment identity changed during deployment. The planned manifest was retained.'
}
Write-EndpointManifest -Status deployed -DeploymentId $deploymentId -VirtualMachineId $virtualMachineId

[pscustomobject]@{
    Operation = 'deployed'
    ResourceGroup = $ResourceGroup
    ResourceGroupId = $expectedResourceGroupId
    VmName = $VmName
    VirtualMachineId = $virtualMachineId
    Location = $Location
    ImageVersion = $ImageVersion
    DeploymentId = $deploymentId
    ProvisioningState = $deployment.ProvisioningState
    InboundSecurityRules = $deployment.Outputs.inboundSecurityRules.Value
    MdeExtension = 'requested'
    Expires = $ExpirationDate
    ManifestPath = $ManifestPath
}
