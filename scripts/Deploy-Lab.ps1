[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroup,

    [switch]$IncludeCanary
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

# This helper is intentionally validation-only. A raw ARM deployment cannot
# prove ownership of an existing tenant-scoped stable detection ID. Use the
# Graph fallback for marker-verified exact-ID mutation, or a freshly generated
# and separately reviewed Sentinel Repository workflow.
& (Join-Path $PSScriptRoot 'Test-Lab.ps1')
New-Item -ItemType Directory -Path $buildPath -Force | Out-Null

$results = foreach ($file in $files) {
    $jsonPath = Join-Path $buildPath ($file.BaseName + '.json')
    & az bicep build --file $file.FullName --outfile $jsonPath --only-show-errors
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build $($file.Name)."
    }

    & az deployment group validate `
        --resource-group $ResourceGroup `
        --template-file $jsonPath `
        --only-show-errors `
        --output none
    if ($LASTEXITCODE -ne 0) {
        throw "Azure validation failed for $($file.Name)."
    }

    [pscustomobject]@{
        Rule = $file.BaseName
        Operation = 'validate-only'
        State = 'Succeeded'
    }
}

$results | Format-Table -AutoSize
Write-Host 'Validation completed. No custom-detection object was created or updated.'
