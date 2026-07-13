[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ResourceGroup = 'nls-gigawiper-dac-lab-rg',
    [string]$Location = 'centralus',
    [string]$VmName = 'nls-gw-win-lab',
    [string]$ExpirationDate = (Get-Date).AddDays(1).ToString('yyyy-MM-dd'),

    [switch]$ReuseOwnedLabResourceGroup
)

$ErrorActionPreference = 'Stop'
Import-Module Az.Accounts
Import-Module Az.Resources

if (-not (Get-AzContext)) {
    throw 'An authenticated Az PowerShell context is required.'
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

if ($PSCmdlet.ShouldProcess($ResourceGroup, 'Create disposable resource group and Windows Defender endpoint')) {
    $group = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
    if (-not $group) {
        $group = New-AzResourceGroup -Name $ResourceGroup -Location $Location -Tag @{
            Purpose = 'GigaWiperDetectionAsCode'
            Owner = 'NineLives'
            Expiration = $ExpirationDate
        }
    }
    else {
        if (-not $ReuseOwnedLabResourceGroup) {
            throw "Resource group '$ResourceGroup' already exists. Refusing reuse unless -ReuseOwnedLabResourceGroup is specified."
        }
        if ($group.Tags.Purpose -cne 'GigaWiperDetectionAsCode' -or
            $group.Tags.Owner -cne 'NineLives') {
            throw "Resource group '$ResourceGroup' does not have the exact lab ownership tags. Refusing deployment."
        }
        if ($group.Location -ine $Location) {
            throw "Resource group '$ResourceGroup' is in '$($group.Location)', not requested location '$Location'. Refusing cross-region reuse."
        }

        $updatedTags = @{}
        foreach ($tag in $group.Tags.GetEnumerator()) {
            $updatedTags[[string]$tag.Key] = [string]$tag.Value
        }
        $updatedTags.Expiration = $ExpirationDate
        $group = Set-AzResourceGroup -Name $ResourceGroup -Tag $updatedTags
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
