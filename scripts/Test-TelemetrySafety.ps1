# Parse-only regression guard for this repository's bounded telemetry helper.
# This is not a sandbox or proof that arbitrary PowerShell is safe. Existing
# ownership checks and review of the complete script remain required.

function Get-TelemetrySafetyFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Source)

    $parseTokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Source, [ref]$parseTokens, [ref]$parseErrors)
    if ($parseErrors.Count) {
        [pscustomobject]@{ Line = 1; Command = '(parse)'; Reason = 'Telemetry must parse before safety review.' }
        return
    }
    # Only this exact, singly assigned literal may stand for the custom log.
    $logAssignments = @($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
        ($node.Left.VariablePath.UserPath -split ':')[-1] -ieq 'eventLogName'
    }, $true))
    $fixedLog = $false
    if ($logAssignments.Count -eq 1) {
        $right = $logAssignments[0].Right
        if ($right -is [Management.Automation.Language.CommandExpressionAst]) {
            $expression = $right.Expression
            if ($expression -is [Management.Automation.Language.StringConstantExpressionAst]) {
                $fixedLog = $expression.Value -ceq 'NLS-GigaWiper-Lab'
            }
        }
    }

    function Get-StaticArgument {
        param($Element)
        if ($Element -is [Management.Automation.Language.VariableExpressionAst]) {
            if ($fixedLog -and $Element.VariablePath.UserPath -ceq 'eventLogName') { return 'NLS-GigaWiper-Lab' }
            return '(dynamic)'
        }
        try {
            $value = $Element.SafeGetValue()
            if ($value -is [string] -or $value -is [ValueType]) { return [string]$value }
        } catch { }
        return '(dynamic)'
    }

    foreach ($command in $ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]}, $true)) {
        $name = $command.GetCommandName()
        $arguments = [Collections.Generic.List[string]]::new()
        foreach ($element in @($command.CommandElements | Select-Object -Skip 1)) {
            if ($element -is [Management.Automation.Language.CommandParameterAst]) {
                $arguments.Add('-' + $element.ParameterName.ToLowerInvariant())
                if ($null -ne $element.Argument) { $arguments.Add((Get-StaticArgument $element.Argument)) }
            } else { $arguments.Add((Get-StaticArgument $element)) }
        }
        $reason = $null
        if (-not $name) {
            # The one reviewed dynamic executable is a copy of cmd.exe whose
            # entire argument string only echoes a fixed inert marker.
            if ($command.CommandElements[0].Extent.Text -cne '$mcPath' -or
                $arguments.Count -ne 2 -or $arguments[0] -cne '/c' -or
                $arguments[1] -cne 'echo NLS safe MinIO mirror simulation - no transfer performed') {
                $reason = 'Unreviewed dynamic command invocation.'
            }
            $name = '(dynamic)'
        } else {
            $name = (($name -replace '\\', '/') -split '/')[-1].ToLowerInvariant() -replace '\.exe$', ''
            $lowerArgs = @($arguments | ForEach-Object { $_.ToLowerInvariant() })
            if ($name -in @('format-volume', 'clear-disk', 'initialize-disk', 'format', 'diskpart',
                    'invoke-expression', 'iex', 'start-process', 'saps', 'start',
                    'cmd', 'powershell', 'pwsh', 'wscript', 'cscript')) {
                $reason = 'Destructive storage or unreviewed shell/process execution is forbidden.'
            } elseif ($name -in @('wevtutil', 'clear-eventlog', 'remove-eventlog')) {
                if ($name -eq 'wevtutil' -and $lowerArgs.Count -gt 0 -and $lowerArgs[0] -notin @('cl', 'clear-log')) {
                    # Read-only enumerations are permitted; other wevtutil
                    # mutations are not part of the telemetry contract.
                    if ($lowerArgs[0] -notin @('el', 'enum-logs', 'gl', 'get-log', 'qe', 'query-events')) {
                        $reason = 'Unreviewed event-log operation.'
                    }
                } else {
                    $validVerb = if ($name -eq 'wevtutil') { @('cl', 'clear-log') } else { @('-logname') }
                    if ($arguments.Count -ne 2 -or $lowerArgs[0] -notin $validVerb -or
                        $arguments[1] -cne 'NLS-GigaWiper-Lab') {
                        $reason = 'Event-log clearing/removal must target only the exact custom lab log.'
                    }
                }
            } elseif ($name -eq 'reagentc' -and '/disable' -in $lowerArgs) {
                $reason = 'Recovery disablement is forbidden.'
            } elseif ($name -eq 'bcdedit' -and @($lowerArgs | Where-Object { $_ -in @('/set', '/delete', '/deletevalue', '/import', '/createstore') }).Count) {
                $reason = 'Boot-configuration mutation is forbidden.'
            } elseif (($name -eq 'vssadmin' -and 'delete' -in $lowerArgs) -or
                      ($name -eq 'wbadmin' -and 'delete' -in $lowerArgs) -or
                      ($name -eq 'wmic' -and 'shadowcopy' -in $lowerArgs -and 'delete' -in $lowerArgs)) {
                $reason = 'Recovery-data deletion is forbidden.'
            } elseif ($name -in @('remove-item', 'ri', 'rm', 'del', 'erase', 'rd', 'rmdir')) {
                $parent = $command.Parent
                while ($parent -and $parent -isnot [Management.Automation.Language.FunctionDefinitionAst]) { $parent = $parent.Parent }
                $shape = ($command.CommandElements | Select-Object -Skip 1 | ForEach-Object {$_.Extent.Text}) -join ' '
                $allowedShapes = @('-LiteralPath $item.FullName -Force', '-LiteralPath $markerPath -Force', '-LiteralPath $Path -ErrorAction Stop')
                if (-not $parent -or $parent.Name -cne 'Remove-OwnedDirectory' -or $name -ne 'remove-item' -or $shape -cnotin $allowedShapes) {
                    $reason = 'Deletion must use the reviewed nonrecursive owned-directory cleanup shapes.'
                }
            }
        }
        if ($reason) { [pscustomobject]@{ Line = $command.Extent.StartLineNumber; Command = $name; Reason = $reason } }
    }
}

function Test-TelemetrySafetyFixtures {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FixturePath)
    $cases = @(Get-Content -LiteralPath $FixturePath -Raw | ConvertFrom-Json)
    foreach ($case in $cases) {
        $findings = @(Get-TelemetrySafetyFindings -Source $case.source)
        if (($findings.Count -gt 0) -ne [bool]$case.reject) {
            throw "Telemetry safety fixture failed: $($case.name)"
        }
    }
    return $cases.Count
}
