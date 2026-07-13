[CmdletBinding()]
param(
    [ValidateSet('Plan', 'Apply', 'Inspect')]
    [string]$Mode = 'Plan',

    [ValidateSet('All', 'Canary')]
    [string]$Scope = 'All',

    [ValidateNotNullOrEmpty()]
    [string]$DetectionPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'detections')
)

$ErrorActionPreference = 'Stop'
$graphBaseUri = 'https://graph.microsoft.com/beta/security/rules/detectionRules'
$allowedRootProperties = @(
    'id',
    'displayName',
    'description',
    'status',
    'queryCondition',
    'schedule',
    'detectionAction'
)

if ($Mode -ne 'Inspect' -and -not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI with the Bicep CLI is required.'
}

$files = @(Get-ChildItem -LiteralPath $DetectionPath -Filter '*.bicep' | Sort-Object Name)
if ($Scope -eq 'Canary') {
    $files = @($files | Where-Object Name -Like '*canary*')
}
if ($files.Count -eq 0) {
    throw "No detection Bicep files were found under '$DetectionPath'."
}

function ConvertFrom-DetectionBicep {
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File
    )

    $compileOutput = & az bicep build --file $File.FullName --stdout --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Bicep compilation failed for $($File.Name):`n$($compileOutput -join "`n")"
    }

    $template = ($compileOutput -join "`n") | ConvertFrom-Json -Depth 100
    $resources = @(
        $template.resources.PSObject.Properties.Value |
            Where-Object type -EQ 'Microsoft.Security/detectionRules@2026-06-01-preview'
    )
    if ($resources.Count -ne 1) {
        throw "Expected one custom detection resource in $($File.Name); found $($resources.Count)."
    }

    $properties = $resources[0].properties | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
    $unsupportedProperties = @($properties.Keys | Where-Object { $_ -notin $allowedRootProperties })
    if ($unsupportedProperties.Count -gt 0) {
        throw "Unsupported Graph root properties in $($File.Name): $($unsupportedProperties -join ', ')."
    }

    # The Microsoft Security Bicep schema requires an entity-mapping id. The
    # Graph entity-mapping schemas do not accept it, so retain the rule's root
    # id while removing only these provider-specific nested values.
    $entityMappings = $properties.detectionAction.alertTemplate.entityMappings
    if ($entityMappings) {
        foreach ($mappingType in @($entityMappings.Keys)) {
            foreach ($mapping in @($entityMappings[$mappingType])) {
                if ($mapping -is [System.Collections.IDictionary] -and $mapping.Contains('id')) {
                    $mapping.Remove('id')
                }
            }
        }
    }

    $createBody = [ordered]@{
        '@odata.type' = '#microsoft.graph.security.detectionRule'
    }
    foreach ($key in $properties.Keys) {
        $createBody[$key] = $properties[$key]
    }

    if (-not $createBody.id -or -not $createBody.displayName -or -not $createBody.status) {
        throw "Compiled custom detection in $($File.Name) is missing id, displayName, or status."
    }

    return $createBody
}

function Invoke-DetectionGraphRequest {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH')]
        [string]$Method,

        [Parameter(Mandatory)]
        [uri]$Uri,

        [AllowNull()]
        [string]$Body,

        [int[]]$AllowedStatus = @(200),

        [switch]$SanitizedErrors
    )

    $headers = @{
        Authorization = "Bearer $($env:GRAPH_ACCESS_TOKEN)"
        Accept = 'application/json'
    }
    $invokeParameters = @{
        Method = $Method
        Uri = $Uri
        Headers = $headers
        SkipHttpErrorCheck = $true
    }
    if ($Body) {
        $invokeParameters.ContentType = 'application/json'
        $invokeParameters.Body = $Body
    }

    $response = $null
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            $response = Invoke-WebRequest @invokeParameters
        }
        catch {
            if ($attempt -lt 4) {
                Start-Sleep -Seconds ([math]::Min([math]::Pow(2, $attempt), 60))
                continue
            }
            if ($SanitizedErrors) {
                throw 'Microsoft Graph request failed before a response was returned after 4 attempts.'
            }
            throw
        }
        $status = [int]$response.StatusCode
        if (($status -eq 429 -or $status -ge 500) -and $attempt -lt 4) {
            $retryAfter = 0
            if ($response.Headers.'Retry-After') {
                [void][int]::TryParse([string]$response.Headers.'Retry-After', [ref]$retryAfter)
            }
            if ($retryAfter -le 0) {
                $retryAfter = [math]::Pow(2, $attempt)
            }
            Start-Sleep -Seconds ([math]::Min($retryAfter, 60))
            continue
        }
        break
    }

    $parsedBody = $null
    if ($response.Content) {
        try {
            $parsedBody = $response.Content | ConvertFrom-Json -Depth 100
        }
        catch {
            $parsedBody = $response.Content
        }
    }

    if ($status -notin $AllowedStatus) {
        $code = if ($parsedBody.error.code) { $parsedBody.error.code } else { 'UnknownGraphError' }
        if ($SanitizedErrors) {
            throw "Microsoft Graph $Method failed with HTTP $status ($code)."
        }
        $message = if ($parsedBody.error.message) { $parsedBody.error.message } else { 'No error message returned.' }
        $requestId = if ($parsedBody.error.innerError.'request-id') { $parsedBody.error.innerError.'request-id' } else { 'not-returned' }
        throw "Microsoft Graph $Method $Uri failed with HTTP $status ($code): $message Request ID: $requestId"
    }

    [pscustomobject]@{
        StatusCode = $status
        Body = $parsedBody
        RequestId = [string]$response.Headers.'request-id'
    }
}

function Get-DetectionResponseActionCount {
    param(
        [AllowNull()]
        [object]$DetectionAction
    )

    if ($null -eq $DetectionAction) {
        return 0
    }

    $count = if ($null -eq $DetectionAction.responseActions) {
        0
    } else {
        @($DetectionAction.responseActions).Count
    }
    if ($DetectionAction.automatedActions) {
        foreach ($property in $DetectionAction.automatedActions.PSObject.Properties) {
            if ($property.Name -notlike '@*' -and $null -ne $property.Value) {
                $count += @($property.Value).Count
            }
        }
    }
    return $count
}

function Assert-ExistingDetectionIsAlertOnly {
    param(
        [Parameter(Mandatory)]
        [string]$RuleId,

        [Parameter(Mandatory)]
        [object]$Rule
    )

    $responseActionCount = Get-DetectionResponseActionCount -DetectionAction $Rule.detectionAction
    if ($responseActionCount -gt 0) {
        throw "Existing rule '$RuleId' has $responseActionCount response action(s). Refusing to modify an armed rule."
    }
}

function ConvertTo-UtcIsoTimestamp {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return ''
    }

    try {
        return ([DateTimeOffset]$Value).ToUniversalTime().ToString(
            'o',
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    catch {
        throw 'Microsoft Graph returned an invalid scheduler timestamp.'
    }
}

function New-DetectionInspection {
    param(
        [Parameter(Mandatory)]
        [object]$Rule
    )

    $failureReason = ([string]$Rule.lastRunDetails.failureReason -replace '[\r\n]+', ' ').Trim()
    [pscustomobject][ordered]@{
        Id = [string]$Rule.id
        Status = [string]$Rule.status
        Frequency = [string]$Rule.schedule.frequency
        NextRunDateTime = ConvertTo-UtcIsoTimestamp -Value $Rule.schedule.nextRunDateTime
        LastRunStatus = [string]$Rule.lastRunDetails.status
        LastRunDateTime = ConvertTo-UtcIsoTimestamp -Value $Rule.lastRunDetails.lastRunDateTime
        LastRunErrorCode = [string]$Rule.lastRunDetails.errorCode
        LastRunFailureReason = $failureReason
        ResponseActionCount = Get-DetectionResponseActionCount -DetectionAction $Rule.detectionAction
    }
}

function Assert-DetectionMatches {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Expected,

        [Parameter(Mandatory)]
        [object]$Actual
    )

    $normalizeQuery = {
        param([string]$Query)
        return ($Query -replace "`r`n", "`n").TrimEnd()
    }
    $checks = [ordered]@{
        id = [string]$Actual.id
        displayName = [string]$Actual.displayName
        status = [string]$Actual.status
        queryText = & $normalizeQuery ([string]$Actual.queryCondition.queryText)
        frequency = [string]$Actual.schedule.frequency
        alertTitle = [string]$Actual.detectionAction.alertTemplate.title
        alertDescription = [string]$Actual.detectionAction.alertTemplate.description
        alertSeverity = [string]$Actual.detectionAction.alertTemplate.severity
    }
    $expectedChecks = [ordered]@{
        id = [string]$Expected.id
        displayName = [string]$Expected.displayName
        status = [string]$Expected.status
        queryText = & $normalizeQuery ([string]$Expected.queryCondition.queryText)
        frequency = [string]$Expected.schedule.frequency
        alertTitle = [string]$Expected.detectionAction.alertTemplate.title
        alertDescription = [string]$Expected.detectionAction.alertTemplate.description
        alertSeverity = [string]$Expected.detectionAction.alertTemplate.severity
    }

    foreach ($key in $expectedChecks.Keys) {
        if ($checks[$key] -cne $expectedChecks[$key]) {
            throw "Verification mismatch for rule '$($Expected.id)' property '$key'."
        }
    }

    $getMitreFingerprints = {
        param([object[]]$Tactics)

        @(
            $Tactics | ForEach-Object {
                $tactic = ([string]$_.tactic).Trim().ToUpperInvariant()
                $_.techniques | ForEach-Object {
                    $technique = ([string]$_.technique).Trim().ToUpperInvariant()
                    $subTechniques = @(
                        $_.subTechniques |
                            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                            ForEach-Object { ([string]$_).Trim().ToUpperInvariant() }
                    )

                    # Graph can canonicalize T1053.005 into technique T1053 plus
                    # subTechniques [T1053.005]. Treat those forms as equivalent.
                    if ($subTechniques.Count -gt 0) {
                        $subTechniques | ForEach-Object { "$tactic/$_" }
                    }
                    elseif ($technique) {
                        "$tactic/$technique"
                    }
                }
            } |
                Sort-Object -Unique
        )
    }
    $expectedTechniques = & $getMitreFingerprints @($Expected.detectionAction.alertTemplate.tactics)
    $actualTechniques = & $getMitreFingerprints @($Actual.detectionAction.alertTemplate.tactics)
    if (($expectedTechniques -join '|') -cne ($actualTechniques -join '|')) {
        throw "Verification mismatch for rule '$($Expected.id)' MITRE tactics or techniques."
    }

    $expectedHostColumns = @($Expected.detectionAction.alertTemplate.entityMappings.hosts.deviceIdColumn | Sort-Object)
    $actualHostColumns = @($Actual.detectionAction.alertTemplate.entityMappings.hosts.deviceIdColumn | Sort-Object)
    if (($expectedHostColumns -join '|') -cne ($actualHostColumns -join '|')) {
        throw "Verification mismatch for rule '$($Expected.id)' host entity mapping."
    }
    $responseActionCount = Get-DetectionResponseActionCount -DetectionAction $Actual.detectionAction
    if ($responseActionCount -gt 0) {
        throw "Rule '$($Expected.id)' has $responseActionCount response action(s) after deployment; the lab requires alert-only rules."
    }
}

if ($Mode -eq 'Inspect') {
    if ([string]::IsNullOrWhiteSpace($env:GRAPH_ACCESS_TOKEN)) {
        throw 'Set GRAPH_ACCESS_TOKEN to an app-only token containing CustomDetection.Read.All or CustomDetection.ReadWrite.All.'
    }

    $ruleIds = @(
        foreach ($file in $files) {
            $content = Get-Content -LiteralPath $file.FullName -Raw
            $match = [regex]::Match(
                $content,
                "(?ms)resource\s+\w+\s+'Microsoft\.Security/detectionRules@2026-06-01-preview'\s*=\s*\{\s*id:\s*'([^']+)'"
            )
            if (-not $match.Success) {
                throw "Unable to extract the exact custom-detection ID from $($file.Name)."
            }

            $ruleId = $match.Groups[1].Value
            if ($ruleId -notmatch '^nls-gw-[a-z0-9-]+$') {
                throw "Refusing to inspect unexpected rule ID '$ruleId'."
            }
            $ruleId
        }
    )
    if (($ruleIds | Sort-Object -Unique).Count -ne $ruleIds.Count) {
        throw 'Custom-detection inspection IDs are not unique.'
    }

    $inspectionResults = @(
        foreach ($ruleId in $ruleIds) {
            $ruleUri = '{0}/{1}?$select=id,status,schedule,lastRunDetails,detectionAction' -f `
                $graphBaseUri, [uri]::EscapeDataString($ruleId)
            $response = Invoke-DetectionGraphRequest `
                -Method GET `
                -Uri $ruleUri `
                -AllowedStatus @(200, 404) `
                -SanitizedErrors
            if ($response.StatusCode -eq 404) {
                throw "Exact custom-detection rule '$ruleId' was not found."
            }
            New-DetectionInspection -Rule $response.Body
        }
    )

    $inspectionResults | ConvertTo-Json -Depth 5
    if ($env:GITHUB_STEP_SUMMARY) {
        @(
            '### Custom-detection scheduler inspection',
            '',
            '| Rule ID | Status | Frequency | Next run | Last-run status | Last run | Error | Failure | Response actions |',
            '|---|---|---|---|---|---|---|---|---:|'
        ) | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
        foreach ($result in $inspectionResults) {
            $failure = ([string]$result.LastRunFailureReason).Replace('|', '\|')
            "| ``$($result.Id)`` | $($result.Status) | $($result.Frequency) | $($result.NextRunDateTime) | $($result.LastRunStatus) | $($result.LastRunDateTime) | $($result.LastRunErrorCode) | $failure | $($result.ResponseActionCount) |" |
                Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
        }
    }
    return
}

$compiledRules = @($files | ForEach-Object { ConvertFrom-DetectionBicep -File $_ })
if (($compiledRules.id | Sort-Object -Unique).Count -ne $compiledRules.Count) {
    throw 'Compiled custom detection IDs are not unique.'
}

if ($Mode -eq 'Plan') {
    $compiledRules |
        ForEach-Object {
            [pscustomobject]@{
                RuleId = $_.id
                DisplayName = $_.displayName
                DesiredStatus = $_.status
                Operation = 'plan-only'
            }
        } |
        Format-Table -AutoSize
    Write-Host "Planned $($compiledRules.Count) rule(s). No Microsoft Graph request was made."
    return
}

if ([string]::IsNullOrWhiteSpace($env:GRAPH_ACCESS_TOKEN)) {
    throw 'Set GRAPH_ACCESS_TOKEN to an app-only token containing CustomDetection.ReadWrite.All.'
}

$results = foreach ($rule in $compiledRules) {
    $ruleUri = '{0}/{1}' -f $graphBaseUri, [uri]::EscapeDataString([string]$rule.id)
    $existing = Invoke-DetectionGraphRequest -Method GET -Uri $ruleUri -AllowedStatus @(200, 404)
    if ($existing.StatusCode -eq 200) {
        Assert-ExistingDetectionIsAlertOnly -RuleId $rule.id -Rule $existing.Body
    }

    if ($existing.StatusCode -eq 404) {
        $createJson = $rule | ConvertTo-Json -Depth 100 -Compress
        $write = Invoke-DetectionGraphRequest -Method POST -Uri $graphBaseUri -Body $createJson -AllowedStatus @(201, 409)
        if ($write.StatusCode -eq 409) {
            $raceCheck = Invoke-DetectionGraphRequest -Method GET -Uri $ruleUri -AllowedStatus @(200, 404)
            if ($raceCheck.StatusCode -ne 200) {
                throw "Rule '$($rule.id)' conflicted by name, title, or ID, but its stable ID is still absent. Refusing to adopt another rule."
            }
            Assert-ExistingDetectionIsAlertOnly -RuleId $rule.id -Rule $raceCheck.Body
            $updateBody = [ordered]@{}
            foreach ($key in @('displayName', 'description', 'status', 'queryCondition', 'schedule', 'detectionAction')) {
                if ($rule.Contains($key)) {
                    $updateBody[$key] = $rule[$key]
                }
            }
            $updateJson = $updateBody | ConvertTo-Json -Depth 100 -Compress
            $write = Invoke-DetectionGraphRequest -Method PATCH -Uri $ruleUri -Body $updateJson -AllowedStatus @(200)
            $operation = 'updated-after-conflict'
        }
        else {
            $operation = 'created'
        }
    }
    else {
        $updateBody = [ordered]@{}
        foreach ($key in @('displayName', 'description', 'status', 'queryCondition', 'schedule', 'detectionAction')) {
            if ($rule.Contains($key)) {
                $updateBody[$key] = $rule[$key]
            }
        }
        $updateJson = $updateBody | ConvertTo-Json -Depth 100 -Compress
        $write = Invoke-DetectionGraphRequest -Method PATCH -Uri $ruleUri -Body $updateJson -AllowedStatus @(200)
        $operation = 'updated'
    }

    $verified = Invoke-DetectionGraphRequest -Method GET -Uri $ruleUri -AllowedStatus @(200)
    Assert-DetectionMatches -Expected $rule -Actual $verified.Body

    [pscustomobject]@{
        RuleId = $rule.id
        Operation = $operation
        HttpStatus = $write.StatusCode
        VerifiedStatus = $verified.Body.status
        ResponseActions = Get-DetectionResponseActionCount -DetectionAction $verified.Body.detectionAction
        LastModified = $verified.Body.lastModifiedDateTime
        RequestId = if ($write.RequestId) { $write.RequestId } else { 'not-returned' }
    }
}

$results | Format-Table -AutoSize
if ($env:GITHUB_STEP_SUMMARY) {
    @(
        '### Custom-detection preview fallback',
        '',
        '| Rule ID | Operation | HTTP | Final status | Response actions | Last modified | Request ID |',
        '|---|---|---:|---|---:|---|---|'
    ) | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
    foreach ($result in $results) {
        "| ``$($result.RuleId)`` | $($result.Operation) | $($result.HttpStatus) | $($result.VerifiedStatus) | $($result.ResponseActions) | $($result.LastModified) | ``$($result.RequestId)`` |" |
            Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY
    }
}
Write-Host "Applied and verified $($results.Count) custom detection rule(s) through Microsoft Graph beta."
