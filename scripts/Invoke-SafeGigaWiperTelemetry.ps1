[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$CleanupOnly
)

$ErrorActionPreference = 'Stop'
$labRoot = Join-Path $env:ProgramData 'NLS-GigaWiper-Lab'
$decoyRoot = Join-Path $env:PUBLIC 'Documents\NLS-GigaWiper-Lab'
$ownershipMarkerName = '.nls-gigawiper-safe-telemetry'
$ownershipMarkerValue = 'NLS-GigaWiper-SafeTelemetry-v1'
$registryNativePath = if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
    'HKU\S-1-5-18\SOFTWARE\OneDrive\Environment'
}
else {
    'HKCU\SOFTWARE\OneDrive\Environment'
}
$registryPowerShellPath = if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
    'Registry::HKEY_USERS\S-1-5-18\SOFTWARE\OneDrive\Environment'
}
else {
    'Registry::HKEY_CURRENT_USER\SOFTWARE\OneDrive\Environment'
}
$registryValueName = 'NLSLabMarker'
$registryValueData = 'SAFE-TELEMETRY-ONLY'
$taskName = 'OneDrive Update'
$taskAction = 'cmd.exe /c rem NLS-GigaWiper-SafeTelemetry'
$eventLogName = 'NLS-GigaWiper-Lab'
$eventSource = 'NLS-GigaWiper-SafeTelemetry'

function Assert-NativeCommandSucceeded {
    param(
        [Parameter(Mandatory)]
        [string]$Operation
    )

    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with native exit code $LASTEXITCODE."
    }
}

function Get-RegistryMarkerValue {
    if (-not (Test-Path -LiteralPath $registryPowerShellPath)) {
        return $null
    }

    try {
        return [string](Get-ItemPropertyValue `
            -LiteralPath $registryPowerShellPath `
            -Name $registryValueName `
            -ErrorAction Stop)
    }
    catch [System.Management.Automation.PSArgumentException] {
        return $null
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return $null
    }
}

function Get-LabTaskXml {
    $taskXmlText = @(& schtasks.exe /Query /TN $taskName /XML 2>$null)
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    try {
        return [xml]($taskXmlText -join [Environment]::NewLine)
    }
    catch {
        throw "The existing '$taskName' task could not be parsed. Refusing to modify it."
    }
}

function Test-LabTaskOwned {
    param(
        [AllowNull()]
        [xml]$TaskXml,

        [Parameter(Mandatory)]
        [bool]$LegacyRegistryMarkerPresent
    )

    if ($null -eq $TaskXml) {
        return $false
    }

    $commandNode = $TaskXml.SelectSingleNode("/*[local-name()='Task']/*[local-name()='Actions']/*[local-name()='Exec']/*[local-name()='Command']")
    $argumentsNode = $TaskXml.SelectSingleNode("/*[local-name()='Task']/*[local-name()='Actions']/*[local-name()='Exec']/*[local-name()='Arguments']")
    $command = ([string]$commandNode.InnerText).Trim()
    $arguments = ([string]$argumentsNode.InnerText).Trim()
    if ($command -notmatch '(?i)(^|\\)cmd\.exe$') {
        return $false
    }

    if ($arguments -ceq '/c rem NLS-GigaWiper-SafeTelemetry') {
        return $true
    }

    # The previous checked-in harness used this generic action. Accept it only
    # when the separate exact registry marker proves this is the legacy lab task.
    return ($arguments -ceq '/c exit 0' -and $LegacyRegistryMarkerPresent)
}

function Test-DirectoryContentsAreLabOnly {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('LabRoot', 'DecoyRoot')]
        [string]$Kind
    )

    $items = @(Get-ChildItem -LiteralPath $Path -Force -Recurse)
    foreach ($item in $items) {
        if ($item.PSIsContainer) {
            return $false
        }

        $allowed = if ($Kind -eq 'LabRoot') {
            $item.Name -in @($ownershipMarkerName, 'mc.exe')
        }
        else {
            $item.Name -eq $ownershipMarkerName -or
                $item.Name -match '^(?i:(?:decoy|public)-\d{2}\.(?:tmp|candy))$'
        }
        if (-not $allowed) {
            return $false
        }
    }

    return $true
}

function Test-DirectoryOwned {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('LabRoot', 'DecoyRoot')]
        [string]$Kind,

        [Parameter(Mandatory)]
        [bool]$LegacyRegistryMarkerPresent
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return $false
    }

    $markerPath = Join-Path $Path $ownershipMarkerName
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        $marker = (Get-Content -LiteralPath $markerPath -Raw).Trim()
        if ($marker -ceq $ownershipMarkerValue) {
            return (Test-DirectoryContentsAreLabOnly -Path $Path -Kind $Kind)
        }
        return $false
    }

    # The previous checked-in harness did not create directory marker files.
    # Its exact registry marker plus an allowlisted directory shape is accepted
    # only to support safe cleanup of that legacy lab revision.
    return ($LegacyRegistryMarkerPresent -and
        (Test-DirectoryContentsAreLabOnly -Path $Path -Kind $Kind))
}

function Assert-GenerationNamesAvailable {
    foreach ($path in @($labRoot, $decoyRoot)) {
        if (Test-Path -LiteralPath $path) {
            throw "Reserved lab path '$path' already exists. Run -CleanupOnly after verifying ownership; generation will not overwrite it."
        }
    }

    $registryMarker = Get-RegistryMarkerValue
    if ($null -ne $registryMarker) {
        throw "Registry marker '$registryValueName' already exists. Generation will not overwrite it."
    }

    if ($null -ne (Get-LabTaskXml)) {
        throw "Scheduled task '$taskName' already exists. Generation will not overwrite it."
    }

    $sourceExists = [System.Diagnostics.EventLog]::SourceExists($eventSource)
    $logExists = [System.Diagnostics.EventLog]::Exists($eventLogName)
    if ($sourceExists -or $logExists) {
        throw "Event log '$eventLogName' or source '$eventSource' already exists. Generation will not reuse it."
    }
}

function Remove-LabArtifacts {
    # Phase 1: validate ownership of every artifact before deleting anything.
    $registryMarker = Get-RegistryMarkerValue
    if ($null -ne $registryMarker -and $registryMarker -cne $registryValueData) {
        throw "Registry value '$registryValueName' has unexpected data. Refusing cleanup."
    }
    $registryMarkerOwned = $registryMarker -ceq $registryValueData

    $taskXml = Get-LabTaskXml
    if ($null -ne $taskXml) {
        if (-not (Test-LabTaskOwned `
            -TaskXml $taskXml `
            -LegacyRegistryMarkerPresent $registryMarkerOwned)) {
            throw "Scheduled task '$taskName' does not have the lab action. Refusing cleanup."
        }
    }

    $sourceExists = [System.Diagnostics.EventLog]::SourceExists($eventSource)
    $logExists = [System.Diagnostics.EventLog]::Exists($eventLogName)
    if ($sourceExists) {
        $sourceLog = [System.Diagnostics.EventLog]::LogNameFromSourceName($eventSource, '.')
        if ($sourceLog -cne $eventLogName) {
            throw "Event source '$eventSource' belongs to '$sourceLog', not the lab log. Refusing cleanup."
        }
    }
    elseif ($logExists) {
        throw "Event log '$eventLogName' exists without the expected lab source. Refusing cleanup."
    }

    $directories = @(
        @{ Path = $labRoot; Kind = 'LabRoot' },
        @{ Path = $decoyRoot; Kind = 'DecoyRoot' }
    )
    foreach ($directory in $directories) {
        if (Test-Path -LiteralPath $directory.Path) {
            if (-not (Test-DirectoryOwned `
                -Path $directory.Path `
                -Kind $directory.Kind `
                -LegacyRegistryMarkerPresent $registryMarkerOwned)) {
                throw "Reserved path '$($directory.Path)' contains unrecognized content or lacks an ownership marker. Refusing recursive cleanup."
            }
        }
    }

    # Phase 2: all ownership checks passed; remove only the validated artifacts.
    if ($null -ne $taskXml) {
        & schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
        Assert-NativeCommandSucceeded -Operation "Deleting scheduled task '$taskName'"
    }
    if ($sourceExists) {
        Remove-EventLog -LogName $eventLogName
    }
    foreach ($directory in $directories) {
        if (Test-Path -LiteralPath $directory.Path) {
            Remove-Item -LiteralPath $directory.Path -Recurse -Force
        }
    }
    if ($registryMarkerOwned) {
        & reg.exe DELETE $registryNativePath /V $registryValueName /F 2>$null | Out-Null
        Assert-NativeCommandSucceeded -Operation "Deleting registry marker '$registryValueName'"
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session on a disposable lab endpoint.'
}

if ($CleanupOnly) {
    if ($PSCmdlet.ShouldProcess('exact owned NLS GigaWiper lab artifacts', 'Remove')) {
        Remove-LabArtifacts
    }
    [pscustomobject]@{
        Safe = $true
        Operation = if ($WhatIfPreference) { 'cleanup-what-if' } else { 'cleanup' }
        LabRoot = $labRoot
        Completed = (Get-Date).ToUniversalTime()
    }
    return
}

if ($PSCmdlet.ShouldProcess($labRoot, 'Generate bounded benign telemetry')) {
    # Complete every collision check before the first write so a failed
    # preflight cannot leave a partial telemetry run behind.
    Assert-GenerationNamesAvailable

    New-Item -ItemType Directory -Path $labRoot | Out-Null
    New-Item -ItemType Directory -Path $decoyRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $labRoot $ownershipMarkerName) -Value $ownershipMarkerValue -NoNewline
    Set-Content -LiteralPath (Join-Path $decoyRoot $ownershipMarkerName) -Value $ownershipMarkerValue -NoNewline

    & reg.exe ADD $registryNativePath /V $registryValueName /T REG_SZ /D $registryValueData /F | Out-Null
    Assert-NativeCommandSucceeded -Operation "Creating registry marker '$registryValueName'"

    $startTime = (Get-Date).AddMinutes(10).ToString('HH:mm')
    & schtasks.exe /Create /TN $taskName /TR $taskAction /SC ONCE /ST $startTime /RU SYSTEM | Out-Null
    Assert-NativeCommandSucceeded -Operation "Creating scheduled task '$taskName'"

    New-EventLog -LogName $eventLogName -Source $eventSource
    Write-EventLog -LogName $eventLogName -Source $eventSource -EventId 1001 -EntryType Information -Message 'Nine Lives safe telemetry marker. This custom lab log will be cleared.'
    & wevtutil.exe cl $eventLogName
    Assert-NativeCommandSucceeded -Operation "Clearing custom event log '$eventLogName'"

    $mcPath = Join-Path $labRoot 'mc.exe'
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $mcPath
    & $mcPath /c 'echo NLS safe MinIO mirror simulation - no transfer performed' | Out-Null
    Assert-NativeCommandSucceeded -Operation 'Executing the filename-only mc.exe marker'

    1..8 | ForEach-Object {
        $source = Join-Path $decoyRoot ("decoy-{0:D2}.tmp" -f $_)
        $target = "decoy-{0:D2}.candy" -f $_
        Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Destination $source
        Start-Sleep -Milliseconds 500
        Move-Item -LiteralPath $source -Destination (Join-Path $decoyRoot $target)
        Start-Sleep -Milliseconds 500
    }
}

[pscustomobject]@{
    Safe = $true
    Operation = if ($WhatIfPreference) { 'generate-what-if' } else { 'generate' }
    ScheduledTask = $taskName
    RegistryPath = $registryNativePath
    RegistryValue = $registryValueName
    ClearedLog = $eventLogName
    DecoyFiles = 8
    RealEncryption = $false
    BootOrRecoveryChanges = $false
    NetworkTransfer = $false
    Completed = (Get-Date).ToUniversalTime()
}
