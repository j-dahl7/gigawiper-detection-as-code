[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroup,

    [switch]$IncludeCanary,

    [ValidateSet('Validate', 'Deploy')]
    [string]$Mode = 'Deploy'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$buildPath = Join-Path $root '.build'
$files = @(Get-ChildItem -LiteralPath (Join-Path $root 'detections') -Filter '*.bicep' | Sort-Object Name)
if (-not $IncludeCanary) {
    $files = @($files | Where-Object Name -NotLike '*canary*')
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI is required.'
}

& (Join-Path $PSScriptRoot 'Test-Lab.ps1')
New-Item -ItemType Directory -Path $buildPath -Force | Out-Null

$results = foreach ($file in $files) {
    $jsonPath = Join-Path $buildPath ($file.BaseName + '.json')
    & az bicep build --file $file.FullName --outfile $jsonPath --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "Failed to build $($file.Name)." }

    if ($Mode -eq 'Validate') {
        & az deployment group validate --resource-group $ResourceGroup --template-file $jsonPath --only-show-errors --output none
        if ($LASTEXITCODE -ne 0) { throw "Azure validation failed for $($file.Name)." }
        [pscustomobject]@{ Rule=$file.BaseName; Operation='validate'; State='Succeeded' }
        continue
    }

    $deploymentName = ($file.BaseName.ToLowerInvariant() -replace '[^a-z0-9-]', '-').Trim('-')
    if ($PSCmdlet.ShouldProcess("resource group $ResourceGroup", "Deploy $($file.Name)")) {
        $output = & az deployment group create --resource-group $ResourceGroup --template-file $jsonPath --name $deploymentName --only-show-errors --query '{state:properties.provisioningState,timestamp:properties.timestamp}' -o json
        if ($LASTEXITCODE -ne 0) { throw "Deployment failed for $($file.Name)." }
        $parsed = $output | ConvertFrom-Json
        [pscustomobject]@{ Rule=$file.BaseName; Operation='deploy'; State=$parsed.state; Timestamp=$parsed.timestamp }
    }
}

$results | Format-Table -AutoSize
