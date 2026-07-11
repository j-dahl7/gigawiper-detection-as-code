[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ResourceGroup = 'nls-gigawiper-dac-lab-rg',
    [string]$Location = 'eastus',
    [string]$VmName = 'nls-gw-win-lab'
)

$ErrorActionPreference = 'Stop'
Import-Module Az.Accounts
Import-Module Az.Resources

if (-not (Get-AzContext)) {
    throw 'An authenticated Az PowerShell context is required.'
}

$alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%'
$plainPassword = -join (1..32 | ForEach-Object { $alphabet[(Get-Random -Maximum $alphabet.Length)] })
$securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
Remove-Variable plainPassword

if ($PSCmdlet.ShouldProcess($ResourceGroup, 'Create disposable resource group and Windows Defender endpoint')) {
    $group = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
    if (-not $group) {
        $group = New-AzResourceGroup -Name $ResourceGroup -Location $Location -Tag @{
            Purpose = 'GigaWiperDetectionAsCode'
            Owner = 'NineLives'
            Expiration = '2026-07-12'
        }
    }

    $deployment = New-AzResourceGroupDeployment `
        -Name 'nls-gw-safe-endpoint' `
        -ResourceGroupName $ResourceGroup `
        -TemplateFile (Join-Path (Split-Path -Parent $PSScriptRoot) 'infra\lab-endpoint.bicep') `
        -vmName $VmName `
        -adminPassword $securePassword `
        -Verbose:$false

    if ($deployment.ProvisioningState -ne 'Succeeded') {
        throw "Endpoint deployment state: $($deployment.ProvisioningState)"
    }

    [pscustomobject]@{
        ResourceGroup = $ResourceGroup
        VmName = $VmName
        Location = $Location
        ProvisioningState = $deployment.ProvisioningState
        InboundSecurityRules = $deployment.Outputs.inboundSecurityRules.Value
        MdeExtension = 'requested'
        Expires = '2026-07-12'
    }
}
