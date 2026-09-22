#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.Diagnostics
using namespace System.IO
using namespace System.Management.Automation.Language
using namespace Microsoft.Win32

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'These registry regression tests require Windows.' }

# Load only the production helpers, never the integration script's main block.
$SourcePath = Join-Path $PSScriptRoot 'Test-PuTTYCAC.ps1'
$Tokens = $null
$ParseErrors = $null
$Ast = [Parser]::ParseFile($SourcePath, [ref]$Tokens, [ref]$ParseErrors)
if ($ParseErrors.Count) { throw ($ParseErrors.Message -join "`n") }
foreach ($Name in @('Invoke-Native', 'Backup-PuTTYRegistry', 'Restore-PuTTYRegistry')) {
    $Definitions = @($Ast.FindAll({
        param($Node)
        $Node -is [FunctionDefinitionAst] -and $Node.Name -eq $Name
    }, $true))
    if ($Definitions.Count -ne 1) { throw "Expected one definition of $Name." }
    . ([ScriptBlock]::Create($Definitions[0].Extent.Text))
}

$FixtureRoot = "Software\PuTTYCAC-RegistryTests\$([Guid]::NewGuid().ToString('N'))"
$ExpectedFixtureRoot = $FixtureRoot
$ArtifactRoot = Join-Path ([Path]::GetTempPath()) "PuTTYCAC-RegistryTests-$([Guid]::NewGuid().ToString('N'))"
[Directory]::CreateDirectory($ArtifactRoot) | Out-Null
$script:Paths = @{ Run = $ArtifactRoot }
$script:State = @{ PuTTYRegistryBackup = $null }
$script:Assertions = 0
$script:Results = [List[object]]::new()
$RegExe = Join-Path $env:WINDIR 'System32\reg.exe'

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:Assertions++
}

function Assert-FixturePath([string]$RegistryPath) {
    if (-not $RegistryPath.StartsWith("$FixtureRoot\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to access a registry path outside the disposable fixture: $RegistryPath"
    }
}

function New-FixtureKey([string]$RegistryPath) {
    Assert-FixturePath $RegistryPath
    return [Registry]::CurrentUser.CreateSubKey($RegistryPath)
}

function Test-FixtureKey([string]$RegistryPath) {
    Assert-FixturePath $RegistryPath
    $Key = [Registry]::CurrentUser.OpenSubKey($RegistryPath)
    if ($null -eq $Key) { return $false }
    $Key.Dispose()
    return $true
}

function Backup-Fixture([string]$RegistryPath) {
    Assert-FixturePath $RegistryPath
    Backup-PuTTYRegistry -RegistryPath $RegistryPath
    Assert-Test ($script:State.PuTTYRegistryBackup.RegistryPath -eq $RegistryPath) 'Backup changed the target path.'
}

function Restore-Fixture {
    Assert-FixturePath $script:State.PuTTYRegistryBackup.RegistryPath
    Restore-PuTTYRegistry
}

function Get-FixtureExport([string]$RegistryPath) {
    Assert-FixturePath $RegistryPath
    $Destination = Join-Path $ArtifactRoot "$([Guid]::NewGuid().ToString('N')).reg"
    Invoke-Native -FilePath $RegExe -ArgumentList @('export', "HKCU\$RegistryPath", $Destination) | Out-Null
    return ,([File]::ReadAllBytes($Destination))
}

function Assert-Bytes([byte[]]$Expected, [byte[]]$Actual, [string]$Message) {
    Assert-Test ([Convert]::ToBase64String($Expected) -ceq [Convert]::ToBase64String($Actual)) $Message
}

function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $Threw = $false
    try { & $Action } catch { $Threw = $true }
    Assert-Test $Threw $Message
}

function Invoke-Case([string]$Name, [scriptblock]$Action) {
    $script:State.PuTTYRegistryBackup = $null
    try {
        & $Action "$FixtureRoot\$Name"
        $script:Results.Add([PSCustomObject]@{ Name = $Name; Passed = $true; Error = $null })
        Write-Host "[PASS] $Name"
    }
    catch {
        $script:Results.Add([PSCustomObject]@{ Name = $Name; Passed = $false; Error = $_.ToString() })
        Write-Host "[FAIL] $Name`: $_"
    }
}

try {
    Invoke-Case 'AllValueKinds' {
        param($Target)
        $Key = New-FixtureKey $Target
        try {
            $Key.SetValue('', 'Unnamed value', [RegistryValueKind]::String)
            $Key.SetValue('String', 'Unicode λ, quotes " and backslash \', [RegistryValueKind]::String)
            $Key.SetValue('Binary', [byte[]]@(0, 255, 127, 1), [RegistryValueKind]::Binary)
            $Key.SetValue('EmptyBinary', [byte[]]@(), [RegistryValueKind]::Binary)
            $Key.SetValue('DWord', [int]-1, [RegistryValueKind]::DWord)
            $Key.SetValue('QWord', [long]::MinValue, [RegistryValueKind]::QWord)
            $Key.SetValue('ExpandString', '%USERPROFILE%\unexpanded', [RegistryValueKind]::ExpandString)
            $Key.SetValue('MultiString', [string[]]@('first', 'λ second'), [RegistryValueKind]::MultiString)
            $Key.SetValue('EmptyMultiString', [string[]]@(), [RegistryValueKind]::MultiString)
            $Key.SetValue('None', [byte[]]@(0, 7, 255), [RegistryValueKind]::None)
            foreach ($Name in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                $Key.SetValue($Name, "Real registry value $Name", [RegistryValueKind]::String)
            }
        }
        finally { $Key.Dispose() }
        $Before = Get-FixtureExport $Target
        Backup-Fixture $Target
        $Key = New-FixtureKey $Target
        try {
            $Key.SetValue('DWord', 'changed kind', [RegistryValueKind]::String)
            $Key.SetValue('AddedByTest', 1, [RegistryValueKind]::DWord)
        }
        finally { $Key.Dispose() }
        Restore-Fixture
        Assert-Bytes $Before (Get-FixtureExport $Target) 'Value names, kinds or data changed after restoration.'
        Assert-Test (Test-Path -LiteralPath $script:State.PuTTYRegistryBackup.Path) 'Recovery file was removed.'
    }

    Invoke-Case 'EmptyRootWithSubkeys' {
        param($Target)
        foreach ($Name in @('Sessions\saved%20session', 'SshHostKeys', 'TrustedHostCAs', 'Nested\Empty')) {
            $Key = New-FixtureKey "$Target\$Name"
            try {
                if ($Name -ne 'Nested\Empty') { $Key.SetValue('Preserve', $Name, [RegistryValueKind]::String) }
            }
            finally { $Key.Dispose() }
        }
        $Before = Get-FixtureExport $Target
        Backup-Fixture $Target
        Assert-Test $script:State.PuTTYRegistryBackup.Existed 'An existing root without values was treated as absent.'
        Assert-Test (@($script:State.PuTTYRegistryBackup.ValueNames).Count -eq 0) 'The fixture root is not empty.'
        [Registry]::CurrentUser.DeleteSubKeyTree($Target)
        $Key = New-FixtureKey $Target
        try { $Key.SetValue('AddedByTest', 1, [RegistryValueKind]::DWord) } finally { $Key.Dispose() }
        Restore-Fixture
        Assert-Bytes $Before (Get-FixtureExport $Target) 'Deleted descendants or empty keys were not restored.'
    }

    Invoke-Case 'EmptyRoot' {
        param($Target)
        (New-FixtureKey $Target).Dispose()
        $Before = Get-FixtureExport $Target
        Backup-Fixture $Target
        $Key = New-FixtureKey $Target
        try { $Key.SetValue('AddedByTest', 1, [RegistryValueKind]::DWord) } finally { $Key.Dispose() }
        Restore-Fixture
        Assert-Test (Test-FixtureKey $Target) 'An originally empty root was deleted.'
        Assert-Bytes $Before (Get-FixtureExport $Target) 'The originally empty root was not restored exactly.'
    }

    Invoke-Case 'AbsentRoot' {
        param($Target)
        Backup-Fixture $Target
        Assert-Test (-not $script:State.PuTTYRegistryBackup.Existed) 'An absent root was recorded as existing.'
        Restore-Fixture
        Assert-Test (-not (Test-FixtureKey $Target)) 'Restoration created an originally absent root.'
        $Key = New-FixtureKey $Target
        try { $Key.SetValue('AddedByTest', 1, [RegistryValueKind]::DWord) } finally { $Key.Dispose() }
        Restore-Fixture
        Assert-Test (-not (Test-FixtureKey $Target)) 'A newly created empty root was not removed.'
    }

    Invoke-Case 'ConcurrentSubkeys' {
        param($Target)
        Backup-Fixture $Target
        $Key = New-FixtureKey "$Target\Concurrent\Empty"
        $Key.Dispose()
        $Key = New-FixtureKey $Target
        try { $Key.SetValue('AddedByTest', 1, [RegistryValueKind]::DWord) } finally { $Key.Dispose() }
        Restore-Fixture
        Assert-Test (Test-FixtureKey "$Target\Concurrent\Empty") 'A concurrent new subkey was recursively deleted.'
        $Key = [Registry]::CurrentUser.OpenSubKey($Target)
        try { Assert-Test ($Key.ValueCount -eq 0) 'The test-created root value was not removed.' }
        finally { $Key.Dispose() }
        Backup-Fixture $Target
        (New-FixtureKey "$Target\AnotherConcurrent").Dispose()
        Restore-Fixture
        Assert-Test (Test-FixtureKey "$Target\AnotherConcurrent") 'Import deleted a new sibling subkey.'
    }

    Invoke-Case 'ImmutableBackups' {
        param($Target)
        $Key = New-FixtureKey $Target
        try { $Key.SetValue('Version', 1, [RegistryValueKind]::DWord) } finally { $Key.Dispose() }
        Backup-Fixture $Target
        $First = $script:State.PuTTYRegistryBackup
        $FirstBytes = [File]::ReadAllBytes($First.Path)
        $Key = New-FixtureKey $Target
        try { $Key.SetValue('Version', 2, [RegistryValueKind]::DWord) } finally { $Key.Dispose() }
        Backup-Fixture $Target
        Assert-Test ($First.Path -ne $script:State.PuTTYRegistryBackup.Path) 'Repeated backups reused a recovery file.'
        Assert-Bytes $FirstBytes ([File]::ReadAllBytes($First.Path)) 'A later backup overwrote the original file.'
        $script:State.PuTTYRegistryBackup = $First
        Restore-Fixture
        $Key = [Registry]::CurrentUser.OpenSubKey($Target)
        try { Assert-Test ($Key.GetValue('Version') -eq 1) 'The first immutable backup could not restore its value.' }
        finally { $Key.Dispose() }
    }

    foreach ($Failure in @('HashMismatch', 'MissingFile', 'ImportFailure')) {
        Invoke-Case $Failure {
            param($Target)
            $Key = New-FixtureKey $Target
            try { $Key.SetValue('Original', 'before', [RegistryValueKind]::String) } finally { $Key.Dispose() }
            Backup-Fixture $Target
            $Backup = $script:State.PuTTYRegistryBackup
            $Key = New-FixtureKey $Target
            try { $Key.SetValue('AddedByTest', 1, [RegistryValueKind]::DWord) } finally { $Key.Dispose() }
            $Before = Get-FixtureExport $Target
            if ($Failure -eq 'MissingFile') { [File]::Move($Backup.Path, "$($Backup.Path).retained") }
            else {
                [File]::WriteAllText($Backup.Path, 'Not a registry export')
                if ($Failure -eq 'ImportFailure') { $Backup.Hash = (Get-FileHash -LiteralPath $Backup.Path).Hash }
            }
            Assert-Throws { Restore-Fixture } "$Failure did not fail restoration."
            Assert-Bytes $Before (Get-FixtureExport $Target) "$Failure changed current registry data before success."
        }
    }

    Invoke-Case 'BackupFailure' {
        param($Target)
        $Key = New-FixtureKey $Target
        try { $Key.SetValue('Preserve', 'unchanged', [RegistryValueKind]::String) } finally { $Key.Dispose() }
        $Before = Get-FixtureExport $Target
        $BlockedDirectory = Join-Path $ArtifactRoot 'not-a-directory'
        [File]::WriteAllText($BlockedDirectory, 'block export directory creation')
        $script:Paths.Run = $BlockedDirectory
        try { Assert-Throws { Backup-PuTTYRegistry -RegistryPath $Target } 'A failed export was accepted.' }
        finally { $script:Paths.Run = $ArtifactRoot }
        Assert-Test ($null -eq $script:State.PuTTYRegistryBackup) 'A failed backup published restoration state.'
        Assert-Bytes $Before (Get-FixtureExport $Target) 'Backup failure changed registry data.'
    }
}
finally {
    if ($FixtureRoot -ne $ExpectedFixtureRoot -or
        $FixtureRoot -notmatch '^Software\\PuTTYCAC-RegistryTests\\[0-9a-f]{32}$') {
        throw 'Refusing to clean an unexpected registry fixture path.'
    }
    [Registry]::CurrentUser.DeleteSubKeyTree($FixtureRoot, $false)
    $script:Results | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $ArtifactRoot 'results.json') -Encoding utf8
}

$Failed = @($script:Results | Where-Object { -not $_.Passed }).Count
Write-Host "$($script:Results.Count - $Failed) cases passed, $Failed failed; $script:Assertions assertions."
Write-Host "Artifacts: $ArtifactRoot"
if ($Failed) { throw 'Registry preservation regression tests failed.' }
