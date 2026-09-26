[CmdletBinding()]
param([Parameter(Mandatory)][string]$KustoAssembly)
$ErrorActionPreference = 'Stop'
Add-Type -Path $KustoAssembly
$schema = '(Timestamp:datetime,DeviceId:string,DeviceName:string,RemoteIP:string,RemotePort:int,InitiatingProcessSHA1:string,InitiatingProcessSHA256:string,InitiatingProcessFolderPath:string,InitiatingProcessFileName:string,InitiatingProcessCommandLine:string,ReportId:long)'
$table = [Kusto.Language.Symbols.TableSymbol]::new('DeviceNetworkEvents', $schema, 'Documented network-event columns')
$database = [Kusto.Language.Symbols.DatabaseSymbol]::new('OfflineValidation', [Kusto.Language.Symbols.Symbol[]]@($table))
$kustoState = [Kusto.Language.GlobalState]::Default.WithDatabase($database)
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../hunting/gigawiper-hunts.kql') -Raw
$query = [regex]::Match($source, '(?s)// Hunt 2:.*?(?=// Hunt 3:)').Value
if (-not $query) { throw 'Network hunt was not found; no validation performed.' }
$code = [Kusto.Language.KustoCode]::ParseAndAnalyze($query, $kustoState, [Kusto.Language.Utils.CancellationToken]::new())
$diagnostics = @($code.GetDiagnostics())
if ($diagnostics.Count) {
    $diagnostics | Select-Object Code, Severity, Message | Format-Table
    throw 'The actual network hunt failed offline KQL semantic analysis.'
}
Write-Host 'PASS: network hunt parses and binds against its table contract. No query executed in a tenant.'
