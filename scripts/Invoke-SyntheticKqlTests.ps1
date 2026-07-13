[CmdletBinding()]
param(
    [string]$AccessToken = $env:MDE_ACCESS_TOKEN,

    [ValidateNotNullOrEmpty()]
    [uri]$ApiUri = 'https://api.securitycenter.microsoft.com/api/advancedqueries/run'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$fixtureFile = Join-Path $root 'tests\synthetic-unit-tests.kql'
$expectedTests = @(
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

if (-not $AccessToken) {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw 'Provide -AccessToken, set MDE_ACCESS_TOKEN, or sign in with Azure CLI.'
    }
    $AccessToken = (& az account get-access-token --resource 'https://api.securitycenter.microsoft.com' --query accessToken -o tsv 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $AccessToken) {
        throw 'Could not obtain a Defender for Endpoint API token from Azure CLI.'
    }
}

$query = Get-Content -LiteralPath $fixtureFile -Raw
$headers = @{
    Authorization = "Bearer $AccessToken"
    Accept = 'application/json'
}
$body = @{ Query = $query } | ConvertTo-Json -Compress

try {
    $response = Invoke-RestMethod -Method Post -Uri $ApiUri -Headers $headers -ContentType 'application/json' -Body $body
}
finally {
    $AccessToken = $null
    $headers.Authorization = $null
}

$rows = @($response.Results)
if ($rows.Count -ne $expectedTests.Count) {
    throw "Expected $($expectedTests.Count) synthetic result rows; received $($rows.Count)."
}

foreach ($testName in $expectedTests) {
    $row = @($rows | Where-Object Test -CEQ $testName)
    if ($row.Count -ne 1) {
        throw "Expected exactly one result for synthetic test '$testName'; received $($row.Count)."
    }
    if ($row[0].Passed -ne $true -or [long]$row[0].Actual -ne [long]$row[0].Expected) {
        throw "Synthetic test '$testName' failed: expected $($row[0].Expected), actual $($row[0].Actual)."
    }
}

[pscustomobject]@{
    Passed = $true
    Tests = $rows.Count
    PositiveTests = @($rows | Where-Object Test -Like '*Positive').Count
    NegativeTests = @($rows | Where-Object Test -Like '*Negative').Count
    Results = $rows
}
