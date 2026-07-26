[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._()-]{1,90}$')]
    [string]$ConfirmResourceGroup,

    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.gigawiper-endpoint.json')
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

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Endpoint cleanup manifest not found: $ManifestPath. Refusing name-based cleanup."
}
try {
    $manifestRaw = Get-Content -LiteralPath $ManifestPath -Raw
    $manifest = $manifestRaw | ConvertFrom-Json
}
catch {
    throw "Endpoint cleanup manifest '$ManifestPath' is not valid JSON."
}

$required = @(
    'schema_version', 'status', 'owner_marker', 'deployment_id',
    'tenant_id', 'subscription_id', 'resource_group_name', 'resource_group_id'
)
foreach ($field in $required) {
    if ($manifest.PSObject.Properties.Name -notcontains $field -or
        [string]::IsNullOrWhiteSpace([string]$manifest.$field)) {
        throw "Endpoint cleanup manifest is missing required field '$field'."
    }
}
if ([int]$manifest.schema_version -ne 1 -or
    [string]$manifest.status -notin @('planned', 'deployed') -or
    [string]$manifest.owner_marker -cne $OwnerMarker) {
    throw 'Endpoint cleanup manifest has an unsupported schema, state, or owner marker.'
}
$parsedDeploymentId = [guid]::Empty
if (-not [guid]::TryParse([string]$manifest.deployment_id, [ref]$parsedDeploymentId)) {
    throw 'Endpoint cleanup manifest deployment_id is not a UUID.'
}
if ($ConfirmResourceGroup -cne [string]$manifest.resource_group_name) {
    throw "-ConfirmResourceGroup must exactly match manifest group '$($manifest.resource_group_name)'."
}

$context = Get-AzContext
if (-not $context -or -not $context.Subscription.Id -or -not $context.Tenant.Id) {
    throw 'An authenticated Az PowerShell context with a tenant and subscription is required.'
}
if (-not [string]::Equals([string]$context.Subscription.Id, [string]$manifest.subscription_id, [StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals([string]$context.Tenant.Id, [string]$manifest.tenant_id, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Active Az tenant or subscription does not match the endpoint cleanup manifest.'
}

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
                    $ConfirmResourceGroup,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    if ($resourceGroupMatches.Count -gt 1) {
        throw "Azure returned multiple resource groups matching '$ConfirmResourceGroup'."
    }
    if ($resourceGroupMatches.Count -eq 1) {
        return $resourceGroupMatches[0]
    }
    return $null
}

function Assert-OwnedResourceGroup {
    param([Parameter(Mandatory)][object]$Group)

    if ((Normalize-ResourceId ([string]$Group.ResourceId)) -ne
        (Normalize-ResourceId ([string]$manifest.resource_group_id))) {
        throw 'Live resource-group ID does not match the endpoint cleanup manifest.'
    }
    if ([string]$Group.Tags[$OwnerTag] -cne $OwnerMarker -or
        [string]$Group.Tags[$DeploymentTag] -cne [string]$manifest.deployment_id) {
        throw 'Live resource group does not have the exact manifest-bound ownership tags. Refusing deletion.'
    }
}

$expectedResourceGroupId = "/subscriptions/$($manifest.subscription_id)/resourceGroups/$ConfirmResourceGroup"
if ((Normalize-ResourceId ([string]$manifest.resource_group_id)) -ne
    (Normalize-ResourceId $expectedResourceGroupId)) {
    throw 'Endpoint cleanup manifest resource-group ID is inconsistent with its subscription and name.'
}

$group = Get-ExactResourceGroup
if ($group) {
    Assert-OwnedResourceGroup -Group $group
}

if ($WhatIfPreference) {
    if ($group) {
        $null = $PSCmdlet.ShouldProcess($expectedResourceGroupId, 'Delete exact manifest-owned disposable endpoint resource group')
    }
    $null = $PSCmdlet.ShouldProcess($ManifestPath, 'Remove endpoint manifest after Azure absence is confirmed')
    [pscustomobject]@{
        Operation = 'cleanup-preview'
        ResourceGroupExists = $null -ne $group
        ManifestChanged = $false
    }
    return
}

if ($group) {
    if (-not $PSCmdlet.ShouldProcess($expectedResourceGroupId, 'Delete exact manifest-owned disposable endpoint resource group')) {
        [pscustomobject]@{
            Operation = 'cleanup-declined'
            ResourceGroupExists = $true
            ManifestChanged = $false
        }
        return
    }
    $group = Get-ExactResourceGroup
    if (-not $group) {
        throw 'Endpoint resource group disappeared after confirmation. The manifest was retained for a fresh convergence check.'
    }
    Assert-OwnedResourceGroup -Group $group
    Remove-AzResourceGroup -Name $ConfirmResourceGroup -Force -ErrorAction Stop | Out-Null

    if ($null -ne (Get-ExactResourceGroup)) {
        throw 'Azure resource-group deletion did not converge. The endpoint manifest was retained.'
    }
}

if ($PSCmdlet.ShouldProcess($ManifestPath, 'Remove endpoint manifest after Azure absence is confirmed')) {
    if ($null -ne (Get-ExactResourceGroup)) {
        throw 'A same-name resource group appeared before manifest removal. The manifest was retained.'
    }
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf) -or
        (Get-Content -LiteralPath $ManifestPath -Raw) -cne $manifestRaw) {
        throw 'Endpoint manifest changed after preflight. Refusing to remove it.'
    }
    Remove-Item -LiteralPath $ManifestPath -Force
    [pscustomobject]@{
        Operation = 'cleanup-complete'
        ResourceGroupExists = $false
        ManifestChanged = $true
    }
}
else {
    [pscustomobject]@{
        Operation = 'manifest-removal-declined'
        ResourceGroupExists = $false
        ManifestChanged = $false
    }
}
