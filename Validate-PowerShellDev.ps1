param(
    [string[]]$TargetFiles = @('NMR5_Baseline.ps1'),
    [string]$RootPath = (Get-Location).Path
)

$ErrorActionPreference = 'Continue'
$WarningPreference = 'Continue'

$startTime = Get-Date
$timestamp = $startTime.ToString('yyyyMMdd_HHmmss')
$logPath = Join-Path $RootPath ("NMR5_runtime_validation_" + $timestamp + '.log')
$out = [System.Collections.Generic.List[string]]::new()

function Add-Row {
    param(
        [string]$Line
    )
    $null = $out.Add($Line)
}

function Add-Section {
    param(
        [string]$Title
    )
    Add-Row ""
    Add-Row ("## " + $Title + " ##")
}

function Get-Relevance {
    param(
        [string]$RuleName
    )
    $highRules = @(
        'PSAvoidUsingEmptyCatchBlock',
        'PSAvoidUsingWriteHost',
        'PSAvoidUsingWMICmdlet',
        'PSUseOutputTypeCorrectly',
        'PSUseShouldProcessForStateChangingFunctions'
    )

    if ($highRules -contains $RuleName) {
        return 'HIGH'
    }
    return 'LOW'
}

Add-Section 'PowerShell Dev Validation'
Add-Row ("timestamp: " + $timestamp)
Add-Row ("runner: " + $PSVersionTable.PSVersion.ToString() + " " + $PSVersionTable.PSEdition)
Add-Row ("root: " + $RootPath)
Add-Row ("targets: " + ($TargetFiles -join ', '))

Add-Section 'Parser'
$parserErrors = 0
foreach ($file in $TargetFiles) {
    $full = Join-Path $RootPath $file
    if (-not (Test-Path -LiteralPath $full)) {
        Add-Row ("PARSER_MISSING_FILE: " + $file)
        $parserErrors++
        continue
    }
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        Add-Row ("PARSER_ERRORS: " + $file + '=' + $errors.Count)
        $parserErrors += $errors.Count
    }
    else {
        Add-Row ("PARSER_OK: " + $file)
    }
}

Add-Section 'ScriptAnalyzer'
if ((Get-Module -ListAvailable -Name 'PSScriptAnalyzer').Count -eq 0) {
    Add-Row 'SCRIPTANALYZER_MISSING'
}
else {
    $records = @()
    foreach ($file in $TargetFiles) {
        $full = Join-Path $RootPath $file
        if (Test-Path -LiteralPath $full) {
            try {
                $records += Invoke-ScriptAnalyzer -Path $full -Severity Error, Warning, Information
            }
            catch {
                Add-Row ('SCRIPTANALYZER_ERROR: ' + $file + ' -> ' + $_.Exception.Message)
            }
        }
    }

    if ($records.Count -eq 0) {
        Add-Row 'SCRIPTANALYZER_OK'
    }
    else {
        Add-Row ("SCRIPTANALYZER_TOTAL: " + $records.Count)

        $bySeverity = $records | Group-Object Severity | Sort-Object Name
        foreach ($group in $bySeverity) {
            Add-Row ('SCRIPTANALYZER_SEVERITY ' + $group.Name + '=' + $group.Count)
        }

        $high = $records | Where-Object { $_.Severity -eq 'Error' -or (Get-Relevance -RuleName $_.RuleName) -eq 'HIGH' }
        if ($high.Count -gt 0) {
            Add-Section 'ScriptAnalyzer_High_Relevance'
            foreach ($item in ($high | Group-Object RuleName | Sort-Object Count -Descending | Select-Object -First 15)) {
                Add-Row ('  ' + $item.Name + '=' + $item.Count)
            }
        }
        else {
            Add-Row 'ScriptAnalyzer_High_Relevance: none'
        }

        $low = $records | Where-Object { (Get-Relevance -RuleName $_.RuleName) -ne 'HIGH' -and $_.Severity -ne 'Error' }
        if ($low.Count -gt 0) {
            Add-Section 'ScriptAnalyzer_Low_Relevance'
            Add-Row ('count=' + $low.Count + ' (not blocker for now)')
            $topLow = $low | Group-Object RuleName | Sort-Object Count -Descending | Select-Object -First 6
            foreach ($item in $topLow) {
                Add-Row ('  ' + $item.Name + '=' + $item.Count)
            }
        }
    }
}

Add-Section 'Pester'
if ((Get-Module -ListAvailable -Name 'Pester').Count -eq 0) {
    Add-Row 'PESTER_MISSING'
}
else {
    $testFiles = Get-ChildItem -Path $RootPath -Recurse -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue
    if ($null -eq $testFiles -or $testFiles.Count -eq 0) {
        Add-Row 'PESTER_NO_TESTS'
    }
    else {
    try {
        $res = Invoke-Pester -Path $RootPath -PassThru -ErrorAction Stop
        if ($null -ne $res -and $res.TotalCount -eq 0) {
            Add-Row 'PESTER_NO_TESTS'
        }
        elseif ($null -ne $res) {
            Add-Row ('PESTER_OK: passed=' + $res.PassedCount + ' failed=' + $res.FailedCount + ' skipped=' + $res.SkippedCount)
        }
    }
    catch {
        if ($_.Exception.Message -like '*No test files were found*') {
            Add-Row 'PESTER_NO_TESTS'
        }
        else {
            Add-Row ('PESTER_ERROR: ' + $_.Exception.Message)
        }
    }
    }
}

Add-Section 'Runtime Gate'
$isWindowsRuntime = if ($PSVersionTable.PSVersion.Major -lt 6) {
    $env:OS -eq 'Windows_NT'
}
else {
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [bool]$IsWindows
    }
    else {
        $true
    }
}
Add-Row ('IS_WINDOWS_RUNTIME=' + $isWindowsRuntime)

Add-Section 'Startup'
foreach ($file in $TargetFiles) {
    $full = Join-Path $RootPath $file
    if (-not (Test-Path -LiteralPath $full)) {
        Add-Row ('STARTUP_SKIPPED_MISSING_FILE=' + $file)
        continue
    }
    try {
        . $full
        Add-Row ('STARTUP_DOTSOURCE_OK=' + $file)
    }
    catch {
        Add-Row ('STARTUP_DOTSOURCE_ERROR=' + $file + ' -> ' + $_.Exception.Message)
    }
}

Add-Section 'Windows-only command availability'
$windowsCommands = @('Get-CimInstance','Get-WmiObject','Get-Service','Get-WinEvent','Get-NetAdapter','Get-LocalUser')
foreach ($cmd in $windowsCommands) {
    $present = [bool](Get-Command -Name $cmd -ErrorAction SilentlyContinue)
    Add-Row ('CMD_' + $cmd + '=' + $present)
}

$endTime = Get-Date
$seconds = [math]::Round(($endTime - $startTime).TotalSeconds, 3)
Add-Section 'Result'
if ($parserErrors -gt 0) {
    $exitState = 'BLOCKED'
}
else {
    $exitState = 'PASS'
}
Add-Row ("STATUS=" + $exitState + " elapsed_seconds=" + $seconds)

Add-Row ''
Add-Row ("LOG_PATH=" + $logPath)

$out | ForEach-Object { Write-Output $_ }
$out | Out-File -FilePath $logPath -Encoding UTF8
