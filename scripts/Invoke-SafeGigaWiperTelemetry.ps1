[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$CleanupOnly
)

$ErrorActionPreference = 'Stop'
$labRoot = Join-Path $env:ProgramData 'NLS-GigaWiper-Lab'
$decoyRoot = Join-Path $env:PUBLIC 'Documents\NLS-GigaWiper-Lab'
$registryNativePath = if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
    'HKU\S-1-5-18\SOFTWARE\OneDrive\Environment'
}
else {
    'HKCU\SOFTWARE\OneDrive\Environment'
}
$taskName = 'OneDrive Update'
$eventLogName = 'NLS-GigaWiper-Lab'
$eventSource = 'NLS-GigaWiper-SafeTelemetry'

function Remove-LabArtifacts {
    schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
    reg.exe DELETE $registryNativePath /F 2>$null | Out-Null
    if ([System.Diagnostics.EventLog]::SourceExists($eventSource)) {
        Remove-EventLog -Source $eventSource
    }
    if (Test-Path -LiteralPath $labRoot) {
        Remove-Item -LiteralPath $labRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $decoyRoot) {
        Remove-Item -LiteralPath $decoyRoot -Recurse -Force
    }
}

if ($CleanupOnly) {
    if ($PSCmdlet.ShouldProcess('exact NLS GigaWiper lab artifacts', 'Remove')) {
        Remove-LabArtifacts
    }
    [pscustomobject]@{ Safe=$true; Operation='cleanup'; LabRoot=$labRoot; Completed=(Get-Date).ToUniversalTime() }
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session on a disposable lab endpoint.'
}

if ($PSCmdlet.ShouldProcess($labRoot, 'Generate bounded benign telemetry')) {
    New-Item -ItemType Directory -Path $decoyRoot -Force | Out-Null

    reg.exe ADD $registryNativePath /V 'NLSLabMarker' /T REG_SZ /D 'SAFE-TELEMETRY-ONLY' /F | Out-Null

    $startTime = (Get-Date).AddMinutes(10).ToString('HH:mm')
    schtasks.exe /Create /TN $taskName /TR 'cmd.exe /c exit 0' /SC ONCE /ST $startTime /RU SYSTEM /F | Out-Null

    if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
        New-EventLog -LogName $eventLogName -Source $eventSource
    }
    Write-EventLog -LogName $eventLogName -Source $eventSource -EventId 1001 -EntryType Information -Message 'Nine Lives safe telemetry marker. This custom lab log will be cleared.'
    wevtutil.exe cl $eventLogName

    $mcPath = Join-Path $labRoot 'mc.exe'
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $mcPath -Force
    & $mcPath /c 'echo NLS safe MinIO mirror simulation - no transfer performed' | Out-Null

    1..8 | ForEach-Object {
        $source = Join-Path $decoyRoot ("decoy-{0:D2}.tmp" -f $_)
        $target = "decoy-{0:D2}.candy" -f $_
        Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $source -Force
        Start-Sleep -Milliseconds 500
        Move-Item -LiteralPath $source -Destination (Join-Path $decoyRoot $target) -Force
        Start-Sleep -Milliseconds 500
    }
}

[pscustomobject]@{
    Safe = $true
    Operation = 'generate'
    ScheduledTask = $taskName
    RegistryPath = $registryNativePath
    ClearedLog = $eventLogName
    DecoyFiles = 8
    RealEncryption = $false
    BootOrRecoveryChanges = $false
    NetworkTransfer = $false
    Completed = (Get-Date).ToUniversalTime()
}
