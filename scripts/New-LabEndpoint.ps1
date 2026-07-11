[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ResourceGroup = 'nls-gigawiper-dac-lab-rg',
    [string]$Location = 'centralus',
    [string]$VmName = 'nls-gw-win-lab',
    [string]$ExpirationDate = (Get-Date).AddDays(1).ToString('yyyy-MM-dd')
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
            Expiration = $ExpirationDate
        }
    }

    $deployment = New-AzResourceGroupDeployment `
        -Name 'nls-gw-safe-endpoint' `
        -ResourceGroupName $ResourceGroup `
        -TemplateFile (Join-Path (Split-Path -Parent $PSScriptRoot) 'infra\lab-endpoint.bicep') `
        -vmName $VmName `
        -location $Location `
        -expirationDate $ExpirationDate `
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
        Expires = $ExpirationDate
    }
}
