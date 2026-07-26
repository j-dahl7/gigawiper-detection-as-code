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
$eventLogRegistryPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\$eventLogName"

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

function Get-CustomEventLogSources {
    if (-not (Test-Path -LiteralPath $eventLogRegistryPath -PathType Container)) {
        return @()
    }

    try {
        return @(
            Get-ChildItem -LiteralPath $eventLogRegistryPath -ErrorAction Stop |
                ForEach-Object { [string]$_.PSChildName }
        )
    }
    catch {
        throw "Custom event-log source inventory could not be read for '$eventLogName'. Refusing cleanup."
    }
}

function Get-LabTaskXml {
    try {
        $taskMatches = @(
            Get-ScheduledTask -TaskPath '\' -ErrorAction Stop |
                Where-Object TaskName -CEQ $taskName
        )
    }
    catch {
        throw "Scheduled task inventory could not be queried. Refusing to treat '$taskName' as absent."
    }

    if ($taskMatches.Count -eq 0) {
        return $null
    }
    if ($taskMatches.Count -ne 1) {
        throw "Scheduled task inventory returned multiple exact matches for '$taskName'. Refusing to modify them."
    }

    $taskXmlText = @(& schtasks.exe /Query /TN $taskName /XML 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Scheduled task '$taskName' exists but its XML could not be exported. Refusing to modify it."
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

    $actionNodes = @($TaskXml.SelectNodes("/*[local-name()='Task']/*[local-name()='Actions']/*"))
    $execNodes = @($TaskXml.SelectNodes("/*[local-name()='Task']/*[local-name()='Actions']/*[local-name()='Exec']"))
    if ($actionNodes.Count -ne 1 -or $execNodes.Count -ne 1) {
        return $false
    }

    $commandNode = $execNodes[0].SelectSingleNode("*[local-name()='Command']")
    $argumentsNode = $execNodes[0].SelectSingleNode("*[local-name()='Arguments']")
    if ($null -eq $commandNode -or $null -eq $argumentsNode) {
        return $false
    }
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

function Test-LabDirectoryItemAllowed {
    param(
        [Parameter(Mandatory)]
        [object]$Item,

        [Parameter(Mandatory)]
        [ValidateSet('LabRoot', 'DecoyRoot')]
        [string]$Kind
    )

    if ($Item.PSIsContainer) {
        return $false
    }
    if ($Kind -eq 'LabRoot') {
        return $Item.Name -in @($ownershipMarkerName, 'mc.exe')
    }
    return $Item.Name -eq $ownershipMarkerName -or
        $Item.Name -match '^(?i:(?:decoy|public)-\d{2}\.(?:tmp|candy))$'
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
        if (-not (Test-LabDirectoryItemAllowed -Item $item -Kind $Kind)) {
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

function Remove-OwnedDirectory {
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
        return
    }
    if (-not (Test-DirectoryOwned `
        -Path $Path `
        -Kind $Kind `
        -LegacyRegistryMarkerPresent $LegacyRegistryMarkerPresent)) {
        throw "Reserved path '$Path' changed after preflight. Refusing cleanup."
    }

    # Remove only the allowlisted leaf files, then remove the now-empty folder
    # without -Recurse. A newly introduced file therefore makes cleanup fail
    # closed instead of being swept into a recursive deletion.
    $markerPath = Join-Path $Path $ownershipMarkerName
    $items = @(Get-ChildItem -LiteralPath $Path -Force)
    foreach ($item in $items) {
        if (-not (Test-LabDirectoryItemAllowed -Item $item -Kind $Kind)) {
            throw "Reserved path '$Path' gained an unrecognized item after preflight. Refusing cleanup."
        }
    }
    foreach ($item in @($items | Where-Object Name -CNE $ownershipMarkerName)) {
        Remove-Item -LiteralPath $item.FullName -Force
    }
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        Remove-Item -LiteralPath $markerPath -Force
    }
    try {
        Remove-Item -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        # Keep a recoverable ownership marker if a concurrent write prevented
        # the non-recursive directory removal.
        if (Test-Path -LiteralPath $Path -PathType Container) {
            Set-Content -LiteralPath $markerPath -Value $ownershipMarkerValue -NoNewline
        }
        throw "Reserved path '$Path' was not empty at deletion time. Its ownership marker was restored; refusing recursive cleanup."
    }
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
    param(
        [switch]$Preview
    )

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
    if ($logExists) {
        $eventSources = @(Get-CustomEventLogSources)
        if ($eventSources.Count -ne 1 -or $eventSources[0] -cne $eventSource) {
            throw "Event log '$eventLogName' has an unexpected source inventory. Refusing cleanup."
        }
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

    if ($Preview) {
        return
    }

    # Phase 2: all ownership checks passed; remove only the validated artifacts.
    if ($null -ne $taskXml) {
        $currentTaskXml = Get-LabTaskXml
        if ($null -ne $currentTaskXml) {
            if (-not (Test-LabTaskOwned `
                -TaskXml $currentTaskXml `
                -LegacyRegistryMarkerPresent $registryMarkerOwned)) {
                throw "Scheduled task '$taskName' changed after preflight. Refusing cleanup."
            }
            & schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
            Assert-NativeCommandSucceeded -Operation "Deleting scheduled task '$taskName'"
        }
    }
    if ($sourceExists) {
        $currentSourceExists = [System.Diagnostics.EventLog]::SourceExists($eventSource)
        $currentLogExists = [System.Diagnostics.EventLog]::Exists($eventLogName)
        $currentEventSources = if ($currentLogExists) { @(Get-CustomEventLogSources) } else { @() }
        if (-not $currentSourceExists -or -not $currentLogExists -or
            [System.Diagnostics.EventLog]::LogNameFromSourceName($eventSource, '.') -cne $eventLogName -or
            $currentEventSources.Count -ne 1 -or $currentEventSources[0] -cne $eventSource) {
            throw "Event log '$eventLogName' changed after preflight. Refusing cleanup."
        }
        Remove-EventLog -LogName $eventLogName
    }
    foreach ($directory in $directories) {
        Remove-OwnedDirectory `
            -Path $directory.Path `
            -Kind $directory.Kind `
            -LegacyRegistryMarkerPresent $registryMarkerOwned
    }
    if ($registryMarkerOwned) {
        if ((Get-RegistryMarkerValue) -cne $registryValueData) {
            throw "Registry marker '$registryValueName' changed after preflight. Refusing cleanup."
        }
        Remove-ItemProperty `
            -LiteralPath $registryPowerShellPath `
            -Name $registryValueName `
            -ErrorAction Stop
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session on a disposable lab endpoint.'
}

if ($CleanupOnly) {
    $cleanupCompleted = $false
    if ($WhatIfPreference) {
        Remove-LabArtifacts -Preview
        $null = $PSCmdlet.ShouldProcess('exact owned NLS GigaWiper lab artifacts', 'Remove')
    }
    elseif ($PSCmdlet.ShouldProcess('exact owned NLS GigaWiper lab artifacts', 'Remove')) {
        Remove-LabArtifacts
        $cleanupCompleted = $true
    }
    [pscustomobject]@{
        Safe = $true
        Operation = if ($WhatIfPreference) {
            'cleanup-what-if'
        }
        elseif ($cleanupCompleted) {
            'cleanup'
        }
        else {
            'cleanup-declined'
        }
        LabRoot = $labRoot
        Completed = if ($cleanupCompleted) { (Get-Date).ToUniversalTime() } else { $null }
    }
    return
}

# WhatIf still performs every read-only collision check and reports unsafe
# same-name artifacts instead of claiming a safe preview.
Assert-GenerationNamesAvailable
$generationCompleted = $false
if ($PSCmdlet.ShouldProcess($labRoot, 'Generate bounded benign telemetry')) {
    New-Item -ItemType Directory -Path $labRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $labRoot $ownershipMarkerName) -Value $ownershipMarkerValue -NoNewline
    New-Item -ItemType Directory -Path $decoyRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $decoyRoot $ownershipMarkerName) -Value $ownershipMarkerValue -NoNewline

    if (-not (Test-Path -LiteralPath $registryPowerShellPath -PathType Container)) {
        $null = New-Item -Path $registryPowerShellPath -Force
    }
    if ($null -ne (Get-RegistryMarkerValue)) {
        throw "Registry marker '$registryValueName' appeared after preflight. Refusing overwrite."
    }
    New-ItemProperty `
        -LiteralPath $registryPowerShellPath `
        -Name $registryValueName `
        -Value $registryValueData `
        -PropertyType String `
        -ErrorAction Stop | Out-Null

    $startTime = (Get-Date).AddMinutes(10).ToString('HH:mm')
    if ($null -ne (Get-LabTaskXml)) {
        throw "Scheduled task '$taskName' appeared after preflight. Refusing overwrite."
    }
    & schtasks.exe /Create /TN $taskName /TR $taskAction /SC ONCE /ST $startTime /RU SYSTEM | Out-Null
    Assert-NativeCommandSucceeded -Operation "Creating scheduled task '$taskName'"

    if ([System.Diagnostics.EventLog]::SourceExists($eventSource) -or
        [System.Diagnostics.EventLog]::Exists($eventLogName)) {
        throw "Event log '$eventLogName' or source '$eventSource' appeared after preflight. Refusing reuse."
    }
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
    $generationCompleted = $true
}

[pscustomobject]@{
    Safe = $true
    Operation = if ($WhatIfPreference) {
        'generate-what-if'
    }
    elseif ($generationCompleted) {
        'generate'
    }
    else {
        'generate-declined'
    }
    ScheduledTask = $taskName
    RegistryPath = $registryNativePath
    RegistryValue = $registryValueName
    ClearedLog = $eventLogName
    DecoyFiles = 8
    RealEncryption = $false
    BootOrRecoveryChanges = $false
    NetworkTransfer = $false
    Completed = if ($generationCompleted) { (Get-Date).ToUniversalTime() } else { $null }
}
