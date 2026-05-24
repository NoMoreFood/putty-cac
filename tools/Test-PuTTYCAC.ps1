#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.Diagnostics
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Security.Principal
using namespace System.Runtime.InteropServices
using namespace System.IO
using namespace System.Security.AccessControl

[CmdletBinding()]
param(
    [string]$PuTTYRoot,
    [string]$OpenSSHRoot = (Join-Path $env:WINDIR 'System32\OpenSSH'),
    [string]$WorkingRoot = (Join-Path $env:TEMP 'PuTTYCAC-Test'),
    [int[]]$RsaKeyLengths = @(1024, 2048, 3072, 4096),
    [switch]$IncludeLegacyRsaProviders,
    [switch]$TrustTestRoots,
    [switch]$SkipEd25519,
    [switch]$UseSmartCard,
    [string]$SmartCardProvider = 'Microsoft Smart Card Key Storage Provider',
    [string]$Pkcs11Library,
    [string]$Pkcs11Pin = '1234'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$HostName = '127.0.0.1'
$Port = 22
$UserName = $env:USERNAME

Set-StrictMode -Version Latest

$PSNativeCommandUseErrorActionPreference = $true

# Initialize state and path hashtables for tracking test results and system resources
$script:State = [ordered]@{
    Results             = [List[object]]::new()
    CreatedThumbprints  = [List[string]]::new()
    TrustedThumbprints  = [List[string]]::new()
    AuthorizedKeyLines  = [List[string]]::new()
    PageantProcesses    = [List[Process]]::new()
    SshdConfigBackup    = $null
    PuTTYRegistryBackup = $null
    Marker              = '# PuTTYCAC-TEST'
    WorkspaceRoot       = Split-Path -Parent $PSScriptRoot
}
$script:Paths = [ordered]@{}

# Shared constants
$CngProvider = 'Microsoft Software Key Storage Provider'
$LegacyEnhancedProvider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
$LegacyOldProvider = 'Microsoft Enhanced Cryptographic Provider v1.0'
$ClientAuthEku = '1.3.6.1.5.5.7.3.2'
$ServerAuthEku = '1.3.6.1.5.5.7.3.1'

# Add test result entry to the results collection and write to host
function Add-Result([string]$Name, [string]$Status, [string]$Detail, [hashtable]$Data = @{}) {
    $Entry = [PSCustomObject]([ordered]@{
            Name   = $Name
            Status = $Status
            Detail = $Detail
            Data   = $Data
        })

    $script:State.Results.Add($Entry) | Out-Null
    Write-Host ("[{0}] {1}: {2}" -f $Status.ToUpperInvariant(), $Name, $Detail)
}

# Verify current PowerShell session has administrator privileges
function Test-IsAdmin {
    $Identity = [WindowsIdentity]::GetCurrent()
    $Principal = [WindowsPrincipal]::new($Identity)
    return $Principal.IsInRole([WindowsBuiltInRole]::Administrator)
}

# Create directory if it doesn't exist; returns the resolved path
function New-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

# Verify file exists and return its full resolved path
function Get-CommandPath([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing required file: $Path" }
    return (Resolve-Path -LiteralPath $Path).Path
}

# Execute native command and return exit code, stdout, and stderr
function Invoke-Native([string]$FilePath, [string[]]$ArgumentList, [switch]$IgnoreExitCode) {
    $ProcessInfo = [ProcessStartInfo]::new()
    $ProcessInfo.FileName = $FilePath

    foreach ($Arg in $ArgumentList) {
        [void]$ProcessInfo.ArgumentList.Add($Arg)
    }

    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.CreateNoWindow = $true

    $Process = [Process]::Start($ProcessInfo)
    $StdOut = $Process.StandardOutput.ReadToEnd()
    $StdErr = $Process.StandardError.ReadToEnd()
    $Process.WaitForExit()

    if (-not $IgnoreExitCode -and $Process.ExitCode -ne 0) { throw "Command failed ($($Process.ExitCode)): $FilePath $($ArgumentList -join ' ')`n$StdOut`n$StdErr" }

    return [PSCustomObject]@{
        ExitCode = $Process.ExitCode
        StdOut   = $StdOut.Trim()
        StdErr   = $StdErr.Trim()
    }
}

# Add certificate to the Current User's trusted root store
function Add-ToCurrentUserRootStore([X509Certificate2]$Certificate) {
    $Store = [X509Store]::new('Root', 'CurrentUser')

    try {
        $Store.Open([OpenFlags]::ReadWrite)
        $Store.Add($Certificate)
    }
    finally {
        $Store.Close()
    }
}

# Remove certificate from the Current User's trusted root store by thumbprint
function Remove-FromCurrentUserRootStore([string]$Thumbprint) {
    $Store = [X509Store]::new('Root', 'CurrentUser')

    try {
        $Store.Open([OpenFlags]::ReadWrite)

        foreach ($Cert in @($Store.Certificates.Find(
                    [X509FindType]::FindByThumbprint,
                    $Thumbprint,
                    $false
                ))) {
            $Store.Remove($Cert)
        }
    }
    finally {
        $Store.Close()
    }
}

# Map OS architecture to native PuTTY binary directory name
function Get-NativePuTTYArch {
    switch ([RuntimeInformation]::OSArchitecture) {
        'X64' { return 'x64' }
        'Arm64' { return 'arm64' }
        'X86' { return 'x86' }
        default {
            throw "Unsupported OS architecture: $([RuntimeInformation]::OSArchitecture)"
        }
    }
}

# Locate PuTTY binary directory matching native architecture
function Resolve-PuTTYRoot {
    $NativeArch = Get-NativePuTTYArch

    if ($PuTTYRoot) {
        $Resolved = (Resolve-Path -LiteralPath $PuTTYRoot).Path
        $PlinkPath = Join-Path $Resolved 'plink.exe'
        if (-not (Test-Path -LiteralPath $PlinkPath -PathType Leaf)) { throw "PuTTYRoot does not contain plink.exe: $Resolved" }
        return $Resolved
    }

    $Candidates = @(
        (Join-Path $script:State.WorkspaceRoot "binaries\$NativeArch"),
        (Join-Path $script:State.WorkspaceRoot "build\$NativeArch\Release"),
        (Join-Path $script:State.WorkspaceRoot "build\$NativeArch\Debug")
    )

    foreach ($Candidate in $Candidates) {
        if (
            (Test-Path -LiteralPath (Join-Path $Candidate 'plink.exe')) -and
            (Test-Path -LiteralPath (Join-Path $Candidate 'pageant.exe'))
        ) {
            return (Resolve-Path -LiteralPath $Candidate).Path
        }
    }

    throw "Unable to locate a native PuTTY-CAC binary directory for '$NativeArch' containing at least plink.exe and pageant.exe. Use -PuTTYRoot with a matching build."
}

# Backup current PuTTY registry settings to file
function Backup-PuTTYRegistry {
    $RegPath = 'HKCU:\Software\SimonTatham\PuTTY'
    $script:State.PuTTYRegistryBackup = Join-Path $script:Paths.Run 'putty-registry-backup.clixml'

    $Payload = if (Test-Path -LiteralPath $RegPath) {
        Get-ItemProperty -LiteralPath $RegPath | Select-Object *
    }
    else {
        $null
    }

    $Payload | Export-Clixml -LiteralPath $script:State.PuTTYRegistryBackup
}

# Restore PuTTY registry settings from backup file
function Restore-PuTTYRegistry {
    $RegPath = 'HKCU:\Software\SimonTatham\PuTTY'

    if (-not $script:State.PuTTYRegistryBackup -or -not (Test-Path -LiteralPath $script:State.PuTTYRegistryBackup -PathType Leaf)) {
        return
    }

    $Backup = Import-Clixml -LiteralPath $script:State.PuTTYRegistryBackup

    if ($null -eq $Backup) {
        Remove-Item -LiteralPath $RegPath -Recurse -Force -ErrorAction SilentlyContinue
        return
    }

    New-Item -Path $RegPath -Force | Out-Null
    $Keep = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

    # Remove properties that were added during testing
    $Current = if (Test-Path -LiteralPath $RegPath) { Get-ItemProperty -LiteralPath $RegPath } else { $null }

    if ($Current) { foreach ($Prop in $Current.PSObject.Properties.Name | Where-Object { $_ -notin $Keep }) { Remove-ItemProperty -LiteralPath $RegPath -Name $Prop -Force -ErrorAction SilentlyContinue } }

    # Restore original properties
    foreach ($Prop in $Backup.PSObject.Properties | Where-Object { $_.Name -notin $Keep }) {
        $Kind = if ($Prop.Value -is [int]) { 'DWord' }
        elseif ($Prop.Value -is [string[]]) { 'MultiString' }
        else { 'String' }

        New-ItemProperty -LiteralPath $RegPath -Name $Prop.Name -Value $Prop.Value -PropertyType $Kind -Force | Out-Null
    }
}

# Create a self-signed test certificate with configurable parameters
function New-TestCertificate([string]$CaseName, [string]$Provider, [string]$KeyAlgorithm, [int]$KeyLength, [string[]]$EnhancedKeyUsage, [datetime]$NotAfter, [switch]$TrustRoot) {
    $FriendlyName = "PuTTYCAC Test $CaseName"
    $NotBefore = if ($NotAfter -lt (Get-Date)) { $NotAfter.AddDays(-30) } else { (Get-Date).AddMinutes(-5) }

    $CertArgs = @{
        CertStoreLocation = 'Cert:\CurrentUser\My'
        Subject           = "CN=$CaseName"
        FriendlyName      = $FriendlyName
        Provider          = $Provider
        HashAlgorithm     = 'SHA256'
        KeyUsage          = 'DigitalSignature'
        KeyUsageProperty  = 'Sign'
        NotBefore         = $NotBefore
        NotAfter          = $NotAfter
        TextExtension     = @('2.5.29.19={text}CA=false')
    }

    if ($EnhancedKeyUsage.Count -gt 0) { $CertArgs.TextExtension += ('2.5.29.37={text}' + ($EnhancedKeyUsage -join '&')) }

    if ($KeyAlgorithm -eq 'RSA') {
        $CertArgs.KeyAlgorithm = 'RSA'
        $CertArgs.KeyLength = $KeyLength
    }
    else {
        $CertArgs.KeyAlgorithm = $KeyAlgorithm
        $CertArgs.CurveExport = 'CurveName'
    }

    $Cert = New-SelfSignedCertificate @CertArgs
    $script:State.CreatedThumbprints.Add($Cert.Thumbprint) | Out-Null

    if ($TrustRoot) {
        Add-ToCurrentUserRootStore -Certificate $Cert
        $script:State.TrustedThumbprints.Add($Cert.Thumbprint) | Out-Null
    }

    return $Cert
}

# Create Ed25519 certificate using OpenSSL and convert to PFX format
function New-Ed25519Certificate([string]$CaseName, [datetime]$NotAfter, [switch]$TrustRoot) {
    $OpenSSL = Get-Command openssl -ErrorAction SilentlyContinue
    $SshKeyGen = Get-Command ssh-keygen -ErrorAction SilentlyContinue

    if (-not $OpenSSL -or -not $SshKeyGen) {
        Add-Result -Name $CaseName -Status 'Skip' -Detail 'Skipped Ed25519 certificate creation because openssl and/or ssh-keygen was not available.'
        return $null
    }

    $Dir = New-Directory (Join-Path $script:Paths.Run $CaseName)
    $KeyPath = Join-Path $Dir 'ed25519.key'
    $CrtPath = Join-Path $Dir 'ed25519.crt'
    $PfxPath = Join-Path $Dir 'ed25519.pfx'
    $PubPath = Join-Path $Dir 'id_ed25519.pub'

    # Generate Ed25519 private key
    Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('genpkey', '-algorithm', 'ED25519', '-out', $KeyPath) | Out-Null

    # Create self-signed certificate from private key
    $DaysValid = [int][Math]::Max(1, [Math]::Ceiling(($NotAfter - (Get-Date)).TotalDays))
    Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('req', '-x509', '-new', '-key', $KeyPath, '-out', $CrtPath, '-subj', "/CN=$CaseName", '-days', $DaysValid, '-addext', 'keyUsage=digitalSignature', '-addext', 'extendedKeyUsage=clientAuth') | Out-Null

    # Export to PKCS#12 format
    Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('pkcs12', '-export', '-inkey', $KeyPath, '-in', $CrtPath, '-out', $PfxPath, '-passout', 'pass:') | Out-Null

    # Extract public key in OpenSSH format
    (Invoke-Native -FilePath $SshKeyGen.Source -ArgumentList @('-y', '-f', $KeyPath)).StdOut |
    Set-Content -LiteralPath $PubPath -Encoding ascii

    # Import certificate into Windows certificate store
    $Cert = Import-PfxCertificate -FilePath $PfxPath -Password (ConvertTo-SecureString -String '' -AsPlainText -Force) -CertStoreLocation 'Cert:\CurrentUser\My'
    $script:State.CreatedThumbprints.Add($Cert.Thumbprint) | Out-Null

    if ($TrustRoot) {
        Add-ToCurrentUserRootStore -Certificate $Cert
        $script:State.TrustedThumbprints.Add($Cert.Thumbprint) | Out-Null
    }

    return [PSCustomObject]@{
        Certificate   = $Cert
        AuthorizedKey = (Get-Content -LiteralPath $PubPath -Raw).Trim()
    }
}

# Locate pkcs11-tool (OpenSC) in PATH or common install locations
function Find-Pkcs11Tool {
    $Cmd = Get-Command 'pkcs11-tool' -ErrorAction SilentlyContinue
    if ($Cmd) { return $Cmd.Source }

    $Candidates = @(
        'C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe',
        'C:\Program Files (x86)\OpenSC Project\OpenSC\tools\pkcs11-tool.exe'
    )
    foreach ($C in $Candidates) {
        if (Test-Path -LiteralPath $C -PathType Leaf) { return $C }
    }
    return $null
}

# Create a test certificate on a PKCS#11 token: generate key via OpenSSL, import to token
function New-Pkcs11TestCertificate([string]$CaseName, [string]$KeyAlgorithm, [int]$KeyLength, [string]$Curve, [datetime]$NotAfter) {
    $Pkcs11Tool = Find-Pkcs11Tool
    $OpenSSL = Get-Command openssl -ErrorAction SilentlyContinue

    if (-not $Pkcs11Tool) {
        Add-Result -Name $CaseName -Status 'Skip' -Detail 'Skipped PKCS#11 certificate creation: pkcs11-tool (OpenSC) not found.'
        return $null
    }
    if (-not $OpenSSL) {
        Add-Result -Name $CaseName -Status 'Skip' -Detail 'Skipped PKCS#11 certificate creation: openssl not found.'
        return $null
    }

    $Dir = New-Directory (Join-Path $script:Paths.Run "pkcs11-$CaseName")
    $KeyPath = Join-Path $Dir 'key.pem'
    $CertPemPath = Join-Path $Dir 'cert.pem'
    $KeyDerPath = Join-Path $Dir 'key.der'
    $CertDerPath = Join-Path $Dir 'cert.der'

    try {
        # Generate private key with OpenSSL
        if ($KeyAlgorithm -eq 'RSA') {
            Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('genrsa', '-out', $KeyPath, $KeyLength.ToString()) | Out-Null
        }
        else {
            Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('ecparam', '-name', $Curve, '-genkey', '-noout', '-out', $KeyPath) | Out-Null
        }

        # Convert private key to PKCS#8 DER for token import
        Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('pkcs8', '-topk8', '-nocrypt', '-in', $KeyPath, '-outform', 'DER', '-out', $KeyDerPath) | Out-Null

        # Create self-signed certificate
        $DaysValid = [int][Math]::Max(1, [Math]::Ceiling(($NotAfter - (Get-Date)).TotalDays))
        Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @(
            'req', '-x509', '-new', '-key', $KeyPath, '-out', $CertPemPath,
            '-subj', "/CN=$CaseName", '-days', $DaysValid.ToString(),
            '-addext', 'keyUsage=digitalSignature',
            '-addext', 'extendedKeyUsage=clientAuth'
        ) | Out-Null

        # Convert certificate to DER for token import
        Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('x509', '-in', $CertPemPath, '-outform', 'DER', '-out', $CertDerPath) | Out-Null

        # Extract SHA-1 thumbprint (40 hex chars, no colons)
        $FingerprintLine = (Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @(
                'x509', '-in', $CertPemPath, '-fingerprint', '-sha1', '-noout'
            )).StdOut
        $Thumbprint = ($FingerprintLine -replace '(?i)^.*?=', '' -replace ':', '').Trim().ToLowerInvariant()

        # Generate a unique key/cert slot ID for this test object
        $SlotId = '{0:x2}{1:x2}' -f (Get-Random -Minimum 1 -Maximum 255), (Get-Random -Minimum 1 -Maximum 255)

        # Import private key to token
        Invoke-Native -FilePath $Pkcs11Tool -ArgumentList @(
            '--module', $Pkcs11Library,
            '--login', '--pin', $Pkcs11Pin,
            '--write-object', $KeyDerPath,
            '--type', 'privkey',
            '--id', $SlotId,
            '--label', $CaseName
        ) | Out-Null

        # Import certificate to token
        Invoke-Native -FilePath $Pkcs11Tool -ArgumentList @(
            '--module', $Pkcs11Library,
            '--login', '--pin', $Pkcs11Pin,
            '--write-object', $CertDerPath,
            '--type', 'cert',
            '--id', $SlotId,
            '--label', $CaseName
        ) | Out-Null

        # Load certificate as X509Certificate2 for SSH public key extraction (no store import needed)
        $CertObj = [X509Certificate2]::new([System.IO.File]::ReadAllBytes($CertPemPath))

        return [PSCustomObject]@{
            Certificate = $CertObj
            Thumbprint  = $Thumbprint
            CertId      = "PKCS:$Thumbprint=$Pkcs11Library"
            SlotId      = $SlotId
        }
    }
    catch {
        Add-Result -Name $CaseName -Status 'Fail' -Detail "PKCS#11 certificate setup failed: $($_.Exception.Message)"
        return $null
    }
}

# Build a test matrix of certificates created on a PKCS#11 token
function New-Pkcs11TestMatrix {
    $Matrix = [List[object]]::new()

    $Cases = @(
        [PSCustomObject]@{ Name = 'PKCS11-RSA-2048';     KeyAlgorithm = 'RSA';   KeyLength = 2048; Curve = '' }
        [PSCustomObject]@{ Name = 'PKCS11-RSA-4096';     KeyAlgorithm = 'RSA';   KeyLength = 4096; Curve = '' }
        [PSCustomObject]@{ Name = 'PKCS11-ECDSA-P256';   KeyAlgorithm = 'ECDSA'; KeyLength = 256;  Curve = 'prime256v1' }
        [PSCustomObject]@{ Name = 'PKCS11-ECDSA-P384';   KeyAlgorithm = 'ECDSA'; KeyLength = 384;  Curve = 'secp384r1' }
    )

    foreach ($Case in $Cases) {
        try {
            $Result = New-Pkcs11TestCertificate -CaseName $Case.Name -KeyAlgorithm $Case.KeyAlgorithm `
                -KeyLength $Case.KeyLength -Curve $Case.Curve -NotAfter (Get-Date).AddDays(30)

            if ($Result) {
                $SshKey = Get-OpenSshKeyLine -Certificate $Result.Certificate
                $Matrix.Add([PSCustomObject]@{
                        Name          = $Case.Name
                        Cert          = $Result.Certificate
                        CertId        = $Result.CertId
                        KeyType       = $Case.KeyAlgorithm
                        Provider      = 'PKCS#11'
                        Bits          = $Case.KeyLength
                        AuthorizedKey = $SshKey
                    }) | Out-Null
                Add-Result -Name $Case.Name -Status 'Pass' -Detail "Created PKCS#11 $($Case.KeyAlgorithm) test certificate on token."
            }
        }
        catch {
            Add-Result -Name $Case.Name -Status 'Skip' -Detail $_.Exception.Message
        }
    }

    return $Matrix
}

# Extract OpenSSH public key from certificate or return fallback key
function Get-OpenSshKeyLine([X509Certificate2]$Certificate, [string]$FallbackPublicKey) {
    if ($FallbackPublicKey) { return $FallbackPublicKey }
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'CertificateTransformer.ps1') -PathType Leaf)) { throw 'Missing tools\CertificateTransformer.ps1.' }

    . (Join-Path $PSScriptRoot 'CertificateTransformer.ps1')
    return (Get-CertificateKeyString -Certificate $Certificate).Trim()
}

# Extract key identifier from OpenSSH public key line
function Get-KeyId([string]$KeyLine) {
    return (($KeyLine -split '\s+' | Select-Object -First 2) -join ' ').Trim()
}

# Determine label based on trust root installation setting
function Get-TrustLabel {
    if ($TrustTestRoots) { return 'Created trusted' }
    return 'Created untrusted'
}

# Get Pageant autoload filter status message
function Get-PageantAutoloadMessage {
    if ($TrustTestRoots) { return 'Pageant autoload honored trust, expiry, and EKU filters.' }
    return 'Pageant autoload honored expiry and EKU filters without requiring trusted-root changes.'
}

# Build matrix of RSA providers for testing
function Get-RsaProviderMatrix {
    $Providers = [List[object]]::new()

    if ($UseSmartCard) {
        $Providers.Add([PSCustomObject]@{
                Name    = $SmartCardProvider
                Alias   = 'SCCNG'
                Enabled = $true
            }) | Out-Null
    }
    else {
        $Providers.Add([PSCustomObject]@{
                Name    = $CngProvider
                Alias   = 'CNG'
                Enabled = $true
            }) | Out-Null

        if ($IncludeLegacyRsaProviders) {
            $Providers.Add([PSCustomObject]@{
                    Name    = $LegacyEnhancedProvider
                    Alias   = 'LEGENH'
                    Enabled = $true
                }) | Out-Null

            $Providers.Add([PSCustomObject]@{
                    Name    = $LegacyOldProvider
                    Alias   = 'LEGOLD'
                    Enabled = $true
                }) | Out-Null
        }
    }

    return $Providers
}

# Create test certificate matrix for positive and negative test cases
function New-TestMatrix {
    $Matrix = [List[object]]::new()

    # Create RSA test certificates with various key lengths and providers
    foreach ($Provider in Get-RsaProviderMatrix) {
        foreach ($Bits in $RsaKeyLengths) {
            $Case = "RSA-$Bits-$($Provider.Alias)"

            try {
                $Cert = New-TestCertificate -CaseName $Case -Provider $Provider.Name -KeyAlgorithm 'RSA' -KeyLength $Bits -EnhancedKeyUsage @($ClientAuthEku) -NotAfter (Get-Date).AddDays(30) -TrustRoot:$TrustTestRoots

                $Matrix.Add([PSCustomObject]@{
                        Name          = $Case
                        Cert          = $Cert
                        CertId        = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                        KeyType       = 'RSA'
                        Provider      = $Provider.Name
                        Bits          = $Bits
                        AuthorizedKey = (Get-OpenSshKeyLine -Certificate $Cert)
                    }) | Out-Null

                Add-Result -Name $Case -Status 'Pass' -Detail ((Get-TrustLabel) + " RSA test certificate using $($Provider.Name) ($Bits bits).")
            }
            catch {
                Add-Result -Name $Case -Status 'Skip' -Detail $_.Exception.Message
            }
        }
    }

    # Create ECDSA test certificates for various curves
    $EcdsaProvider = if ($UseSmartCard) { $SmartCardProvider } else { $CngProvider }
    foreach ($Curve in @('ECDSA_nistP256', 'ECDSA_nistP384', 'ECDSA_nistP521')) {
        $Case = $Curve.Replace('_', '-')
        if ($UseSmartCard) { $Case = "$Case-SC" }

        try {
            $Cert = New-TestCertificate -CaseName $Case -Provider $EcdsaProvider -KeyAlgorithm $Curve -KeyLength 0 -EnhancedKeyUsage @($ClientAuthEku) -NotAfter (Get-Date).AddDays(30) -TrustRoot:$TrustTestRoots

            $ECDSA = [ECDsaCertificateExtensions]::GetECDsaPublicKey($Cert)

            $Matrix.Add([PSCustomObject]@{
                    Name          = $Case
                    Cert          = $Cert
                    CertId        = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                    KeyType       = 'ECDSA'
                    Provider      = $EcdsaProvider
                    Bits          = $ECDSA.KeySize
                    AuthorizedKey = (Get-OpenSshKeyLine -Certificate $Cert)
                }) | Out-Null

            if ($ECDSA) { $ECDSA.Dispose() }

            Add-Result -Name $Case -Status 'Pass' `
                -Detail ((Get-TrustLabel) + ' ECDSA test certificate.')
        }
        catch {
            Add-Result -Name $Case -Status 'Skip' -Detail $_.Exception.Message
        }
    }

    # Create Ed25519 test certificate if not skipped (not supported by smart card KSP)
    if (-not $SkipEd25519 -and -not $UseSmartCard) {
        $Case = 'ED25519'

        try {
            $Ed = New-Ed25519Certificate -CaseName $Case -NotAfter (Get-Date).AddDays(30) -TrustRoot:$TrustTestRoots

            if ($Ed) {
                $Matrix.Add([PSCustomObject]@{
                        Name          = $Case
                        Cert          = $Ed.Certificate
                        CertId        = "CAPI:$($Ed.Certificate.Thumbprint.ToLowerInvariant())"
                        KeyType       = 'ED25519'
                        Provider      = 'OpenSSL'
                        Bits          = 255
                        AuthorizedKey = (Get-OpenSshKeyLine -Certificate $Ed.Certificate -FallbackPublicKey $Ed.AuthorizedKey)
                    }) | Out-Null

                Add-Result -Name $Case -Status 'Pass' -Detail ((Get-TrustLabel) + ' Ed25519 test certificate via OpenSSL.')
            }
        }
        catch {
            Add-Result -Name $Case -Status 'Skip' -Detail $_.Exception.Message
        }
    }

    # Create negative test certificates (invalid scenarios)
    $Negative = [List[object]]::new()

    # Server auth only (should not be eligible for client auth)
    try {
        $Cert = New-TestCertificate -CaseName 'NEG-SERVERAUTH' -Provider $CngProvider -KeyAlgorithm 'RSA' -KeyLength 2048 -EnhancedKeyUsage @($ServerAuthEku) -NotAfter (Get-Date).AddDays(30)

        $Negative.Add([PSCustomObject]@{
                Name           = 'NEG-SERVERAUTH'
                CertId         = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                ExpectedListed = $false
                KeyId          = (Get-KeyId (Get-OpenSshKeyLine -Certificate $Cert))
            }) | Out-Null

        Add-Result -Name 'NEG-SERVERAUTH' -Status 'Pass' -Detail 'Created server-auth-only negative certificate.'
    }
    catch {
        Add-Result -Name 'NEG-SERVERAUTH' -Status 'Skip' -Detail $_.Exception.Message
    }

    # Expired certificate (should be filtered)
    try {
        $Cert = New-TestCertificate -CaseName 'NEG-EXPIRED' -Provider $CngProvider -KeyAlgorithm 'RSA' -KeyLength 2048 -EnhancedKeyUsage @($ClientAuthEku) -NotAfter (Get-Date).AddDays(-1) -TrustRoot:$TrustTestRoots

        $Negative.Add([PSCustomObject]@{
                Name           = 'NEG-EXPIRED'
                CertId         = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                ExpectedListed = $false
                KeyId          = (Get-KeyId (Get-OpenSshKeyLine -Certificate $Cert))
            }) | Out-Null

        Add-Result -Name 'NEG-EXPIRED' -Status 'Pass' -Detail 'Created expired negative certificate.'
    }
    catch {
        Add-Result -Name 'NEG-EXPIRED' -Status 'Skip' -Detail $_.Exception.Message
    }

    # Untrusted certificate (should be filtered if trust checking enabled)
    try {
        $Cert = New-TestCertificate -CaseName 'NEG-UNTRUSTED' -Provider $CngProvider -KeyAlgorithm 'RSA' -KeyLength 2048 -EnhancedKeyUsage @($ClientAuthEku) -NotAfter (Get-Date).AddDays(30)

        $Negative.Add([PSCustomObject]@{
                Name           = 'NEG-UNTRUSTED'
                Cert           = $Cert
                CertId         = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                ExpectedListed = $false
                KeyId          = (Get-KeyId (Get-OpenSshKeyLine -Certificate $Cert))
            }) | Out-Null

        Add-Result -Name 'NEG-UNTRUSTED' -Status 'Pass' -Detail 'Created untrusted negative certificate.'
    }
    catch {
        Add-Result -Name 'NEG-UNTRUSTED' -Status 'Skip' -Detail $_.Exception.Message
    }

    return [PSCustomObject]@{
        Positive = $Matrix
        Negative = $Negative
    }
}

# Backup current sshd configuration file
function Backup-SshdConfig {
    $ConfigPath = Join-Path $env:ProgramData 'ssh\sshd_config'
    $script:State.SshdConfigBackup = Join-Path $script:Paths.Run 'sshd_config.bak'
    Copy-Item -LiteralPath $ConfigPath -Destination $script:State.SshdConfigBackup -Force
    return $ConfigPath
}

# Update sshd configuration to allow certificate-based authentication for current user
function Set-SshdConfig([string]$ConfigPath) {
    $Existing = if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) { Get-Content -LiteralPath $ConfigPath } else { @() }
    
    $InBlock = $false
    $Filtered = foreach ($Line in $Existing) {
        if ($Line -match "^$($script:State.Marker) BEGIN") { $InBlock = $true; continue }
        if ($Line -match "^$($script:State.Marker) END") { $InBlock = $false; continue }
        if (-not $InBlock) { $Line }
    }

    $AuthKeysAbs = (Join-Path $HOME '.ssh/authorized_keys').Replace('\', '/')
    $Block = @(
        "$($script:State.Marker) BEGIN"
        "StrictModes no"
        "Match Address 127.0.0.1 # PuTTYCAC-TEST"
        "    AuthorizedKeysFile `"$AuthKeysAbs`""
        "    PubkeyAuthentication yes"
        "    PasswordAuthentication no"
        "    KbdInteractiveAuthentication no"
        "Match All # PuTTYCAC-TEST"
        "$($script:State.Marker) END"
    )

    Set-Content -LiteralPath $ConfigPath -Value ($Block + $Filtered) -Encoding ascii
}

# Restore sshd configuration from backup
function Restore-SshdConfig {
    if ($script:State.SshdConfigBackup -and (Test-Path -LiteralPath $script:State.SshdConfigBackup -PathType Leaf)) { Copy-Item -LiteralPath $script:State.SshdConfigBackup -Destination (Join-Path $env:ProgramData 'ssh\sshd_config') -Force }
}

# Add test certificates to authorized_keys file with proper SSH directory permissions
function Set-AuthorizedKeys([object[]]$Matrix) {
    $SshDir = New-Directory (Join-Path $HOME '.ssh')
    $AuthorizedKeys = Join-Path $SshDir 'authorized_keys'
    $Existing = if (Test-Path -LiteralPath $AuthorizedKeys -PathType Leaf) { Get-Content -LiteralPath $AuthorizedKeys } else { @() }

    # Preserve non-test entries
    $Filtered = $Existing | Where-Object { $_ -notmatch '^# PuTTYCAC-TEST' }

    # Add test certificate public keys
    $Block = @("$($script:State.Marker) BEGIN") + ($Matrix | ForEach-Object { $_.AuthorizedKey }) + @("$($script:State.Marker) END")

    Set-Content -LiteralPath $AuthorizedKeys -Value ($Filtered + $Block) -Encoding ascii

    # Configure Windows SSH permissions: full access for user and SYSTEM
    $UserSid = [WindowsIdentity]::GetCurrent().User
    $SysSid = [SecurityIdentifier]::new([WellKnownSidType]::LocalSystemSid, $null)
    $Full = [FileSystemRights]::FullControl
    $CiOi = [InheritanceFlags]'ContainerInherit, ObjectInherit'
    $Prop = [PropagationFlags]::None

    $AclDir = [DirectorySecurity]::new()
    $AclDir.SetAccessRuleProtection($true, $false)
    $AclDir.AddAccessRule([FileSystemAccessRule]::new($UserSid, $Full, $CiOi, $Prop, 'Allow'))
    $AclDir.AddAccessRule([FileSystemAccessRule]::new($SysSid, $Full, $CiOi, $Prop, 'Allow'))
    Set-Acl -LiteralPath $SshDir -AclObject $AclDir

    $AclFile = [FileSecurity]::new()
    $AclFile.SetAccessRuleProtection($true, $false)
    $AclFile.AddAccessRule([FileSystemAccessRule]::new($UserSid, $Full, 'Allow'))
    $AclFile.AddAccessRule([FileSystemAccessRule]::new($SysSid, $Full, 'Allow'))
    Set-Acl -LiteralPath $AuthorizedKeys -AclObject $AclFile

    $script:State.AuthorizedKeyLines.Clear()
    foreach ($Line in $Matrix.AuthorizedKey) {
        $script:State.AuthorizedKeyLines.Add($Line) | Out-Null
    }

    return $AuthorizedKeys
}

# Retrieve SSH host key fingerprints using ssh-keygen
function Get-HostKeyFingerprints {
    $SshKeyGen = Get-CommandPath (Join-Path $script:Paths.OpenSSH 'ssh-keygen.exe')
    $PubKeys = Get-ChildItem -LiteralPath (Join-Path $env:ProgramData 'ssh') -Filter 'ssh_host_*_key.pub' -File

    if (-not $PubKeys) {
        throw 'No sshd host public keys were found under ProgramData\ssh.'
    }

    $Fingerprints = foreach ($Key in $PubKeys) {
        $Output = Invoke-Native -FilePath $SshKeyGen -ArgumentList @('-lf', $Key.FullName)
        if ($Output.StdOut -match '^\S+\s+(\S+)\s+') {
            $Matches[1]
        }
    }

    return @($Fingerprints | Where-Object { $_ } | Select-Object -Unique)
}

# Start or restart the OpenSSH server (sshd) service
function Restart-Sshd {
    $Service = Get-Service -Name sshd -ErrorAction SilentlyContinue

    if (-not $Service) {
        throw 'OpenSSH SSH Server (sshd) service is not installed.'
    }

    Set-Service -Name sshd -StartupType Automatic

    try {
        Restart-Service -Name sshd -Force -ErrorAction Stop 
    }
    catch {
        # Service may have never been started; try a plain Start-Service and re-throw on second failure
        try {
            Start-Service -Name sshd -ErrorAction Stop
        }
        catch {
            throw $_.Exception
        }
    }
}

# Test SSH connectivity using plink with certificate authentication
function Invoke-PlinkTest([string]$Name, [string]$CertId, [string[]]$HostKeys) {
    $ArgList = @('-batch', '-ssh', '-P', $Port.ToString(), '-l', $UserName) +
    ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
    @('-i', $CertId, $HostName, 'whoami')

    $Result = Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $ArgList

    if ($Result.StdOut -notmatch [regex]::Escape($UserName)) { throw "Unexpected plink output: $($Result.StdOut)" }

    Add-Result -Name "PLINK-$Name" -Status 'Pass' -Detail 'Direct CAPI authentication succeeded.'
}

# Test SFTP connectivity using psftp with certificate authentication
function Invoke-PsftpTest([string]$Name, [string]$CertId, [string[]]$HostKeys) {
    $Batch = Join-Path $script:Paths.Run "psftp-$Name.txt"
    Set-Content -LiteralPath $Batch -Value @('pwd', 'quit') -Encoding ascii

    $ArgList = @('-batch', '-P', $Port.ToString(), '-l', $UserName) +
    ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
    @('-i', $CertId, '-b', $Batch, $HostName)

    $Result = Invoke-Native -FilePath $script:Paths.Psftp -ArgumentList $ArgList

    if ($Result.StdOut -notmatch '/' -and $Result.StdErr -notmatch 'Remote directory is') { throw 'PSFTP did not return a working directory.' }

    Add-Result -Name "PSFTP-$Name" -Status 'Pass' -Detail 'Batch PSFTP authentication succeeded.'
}

# Test secure file copy using pscp with certificate authentication
function Invoke-PscpTest([string]$Name, [string]$CertId, [string[]]$HostKeys) {
    if (-not (Test-Path -LiteralPath $script:Paths.Pscp -PathType Leaf)) {
        Add-Result -Name "PSCP-$Name" -Status 'Skip' -Detail 'pscp.exe not found; skipping PSCP test.'
        return
    }

    $LocalFile = Join-Path $script:Paths.Run "pscp-$Name.txt"
    Set-Content -LiteralPath $LocalFile -Value "PuTTYCAC-PSCP-TEST-$Name" -Encoding ascii

    $RemotePath = "$UserName@${HostName}:pscp-$Name.txt"
    $ArgList = @('-batch', '-P', $Port.ToString(), '-l', $UserName) +
    ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
    @('-i', $CertId, $LocalFile, $RemotePath)

    Invoke-Native -FilePath $script:Paths.Pscp -ArgumentList $ArgList | Out-Null

    Add-Result -Name "PSCP-$Name" -Status 'Pass' -Detail 'PSCP file upload authentication succeeded.'
}

# Test SSH authentication via Pageant acting as SSH agent (uses OpenSSH ssh.exe)
function Invoke-PageantAgentTest([string]$Name, [string]$CertId, [string[]]$HostKeys) {
    $Bridge = Start-Pageant -Arguments @($CertId)

    try {
        # Build known_hosts from the actual host public key files — $HostKeys contains
        # fingerprints for plink, but ssh.exe needs "hostname keytype base64key" lines.
        $KnownHostsPath = Join-Path $script:Paths.Run 'pageant_known_hosts'
        $KnownHostsLines = Get-ChildItem -LiteralPath (Join-Path $env:ProgramData 'ssh') -Filter 'ssh_host_*_key.pub' -File |
            ForEach-Object { "$HostName $((Get-Content -LiteralPath $_.FullName -Raw).Trim())" }
        Set-Content -LiteralPath $KnownHostsPath -Value $KnownHostsLines -Encoding ascii

        # Write a config file so paths with spaces are properly quoted (inline -o quoting
        # is unreliable when the pipe path or temp dir contains spaces, e.g. "Bryan Berns")
        $SshConfigPath = Join-Path $script:Paths.Run "pageant_agent_$Name.conf"
        Set-Content -LiteralPath $SshConfigPath -Value @(
            "IdentityAgent `"$($Bridge.Agent)`""
            "UserKnownHostsFile `"$KnownHostsPath`""
            'StrictHostKeyChecking yes'
            'BatchMode yes'
        ) -Encoding ascii

        $ArgList = @(
            '-F', $SshConfigPath,
            '-p', $Port.ToString(),
            '-l', $UserName,
            $HostName,
            'whoami'
        )

        $Result = Invoke-Native -FilePath $script:Paths.SshExe -ArgumentList $ArgList

        if ($Result.StdOut -notmatch [regex]::Escape($UserName)) { throw "Unexpected ssh output: $($Result.StdOut)" }

        Add-Result -Name "PAGEANT-AGENT-$Name" -Status 'Pass' -Detail 'SSH via Pageant agent socket authenticated successfully.'
    }
    finally {
        if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
    }
}

# Test that -allowanycert permits authentication with an untrusted certificate
function Test-AllowAnyCert([object]$UntrustedCase, [string[]]$HostKeys) {
    if (-not $UntrustedCase) {
        Add-Result -Name 'ALLOWANYCERT' -Status 'Skip' -Detail 'No untrusted negative certificate available for -allowanycert test.'
        return
    }

    # Temporarily add the untrusted cert's public key to authorized_keys
    $AuthorizedKeys = Join-Path $HOME '.ssh\authorized_keys'
    $UntrustedKey = Get-OpenSshKeyLine -Certificate $UntrustedCase.Cert
    $Existing = if (Test-Path -LiteralPath $AuthorizedKeys -PathType Leaf) { Get-Content -LiteralPath $AuthorizedKeys } else { @() }
    $Marker = "$($script:State.Marker) ALLOWANYCERT"
    Set-Content -LiteralPath $AuthorizedKeys -Value ($Existing + @($Marker, $UntrustedKey)) -Encoding ascii

    try {
        $ArgList = @('-batch', '-ssh', '-P', $Port.ToString(), '-l', $UserName) +
        ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
        @('-allowanycert', '-i', $UntrustedCase.CertId, $HostName, 'whoami')

        $Result = Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $ArgList

        if ($Result.StdOut -notmatch [regex]::Escape($UserName)) { throw "Unexpected plink output: $($Result.StdOut)" }

        Add-Result -Name 'ALLOWANYCERT' -Status 'Pass' -Detail 'plink authenticated with untrusted certificate using -allowanycert.'
    }
    finally {
        # Remove the temporary authorized_keys entry
        $Content = Get-Content -LiteralPath $AuthorizedKeys | Where-Object { $_ -ne $Marker -and $_ -ne $UntrustedKey }
        Set-Content -LiteralPath $AuthorizedKeys -Value $Content -Encoding ascii

        # plink persisted AllowAnyCert=1 to the registry; clear it now so Test-PageantFilters
        # is not affected (AllowAnyCert bypasses EKU filtering, which would cause NEG-SERVERAUTH
        # to appear in the autoloaded key list)
        Remove-ItemProperty -LiteralPath 'HKCU:\Software\SimonTatham\PuTTY' -Name 'AllowAnyCert' -Force -ErrorAction SilentlyContinue
    }
}

# Start Pageant with specified arguments and wait for initialization
function Start-Pageant([string[]]$Arguments) {
    $Config = Join-Path $script:Paths.Run ("pageant-{0}.conf" -f ([guid]::NewGuid().ToString('N')))
    $ArgList = @('--openssh-config', $Config) + $Arguments
    $Process = Start-Process -FilePath $script:Paths.Pageant -ArgumentList $ArgList -PassThru -WindowStyle Hidden
    $script:State.PageantProcesses.Add($Process) | Out-Null

    # Wait for Pageant to initialize and create config file
    $Deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $Deadline) {
        if (Test-Path -LiteralPath $Config -PathType Leaf) {
            $Line = Get-Content -LiteralPath $Config | Where-Object { $_ -match '^IdentityAgent ' } | Select-Object -First 1

            if ($Line) {
                return [PSCustomObject]@{
                    Process = $Process
                    Agent   = ($Line -replace '^IdentityAgent\s+"?(.+?)"?$', '$1')
                    Config  = $Config
                }
            }
        }

        Start-Sleep -Milliseconds 200
    }

    throw 'Timed out waiting for Pageant to initialize.'
}

# Stop all running Pageant processes
function Stop-Pageants {
    foreach ($Process in $script:State.PageantProcesses) {
        if ($Process -and -not $Process.HasExited) { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue }
    }
}

# Get list of keys loaded in Pageant via SSH agent
function Get-PageantKeys([string]$Agent) {
    $env:SSH_AUTH_SOCK = $Agent
    $Result = Invoke-Native -FilePath $script:Paths.SshAdd -ArgumentList @('-L') -IgnoreExitCode

    if ($Result.ExitCode -ne 0 -and $Result.StdErr -notmatch 'The agent has no identities' -and $Result.StdOut -notmatch 'The agent has no identities') { throw "ssh-add -L failed: Exit=$($Result.ExitCode) Out=$($Result.StdOut) Err=$($Result.StdErr)" }

    return @($Result.StdOut -split "`r?`n" | Where-Object { $_ -match '^(ssh-|ecdsa-)' })
}

# Get registry DWord value from PuTTY settings
function Get-RegistryDword([string]$Path, [string]$Name) {
    $Item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $Item) { return $null }
    return $Item.PSObject.Properties[$Name]?.Value
}

# Execute PuTTY tool with flag and verify registry persistence
function Invoke-FlagSetter([string]$FilePath, [string]$Flag, [string]$RegistryName, [int]$ExpectedValue) {
    $Process = Start-Process -FilePath $FilePath -ArgumentList @($Flag) -PassThru -WindowStyle Hidden

    try {
        $Deadline = (Get-Date).AddSeconds(5)
        do {
            if ((Get-RegistryDword -Path 'HKCU:\Software\SimonTatham\PuTTY' -Name $RegistryName) -eq $ExpectedValue) { return }
            Start-Sleep -Milliseconds 200
        }
        while ((Get-Date) -lt $Deadline -and -not $Process.HasExited)

        if ((Get-RegistryDword -Path 'HKCU:\Software\SimonTatham\PuTTY' -Name $RegistryName) -ne $ExpectedValue) {
            throw "$([IO.Path]::GetFileName($FilePath)) failed to set $RegistryName with $Flag."
        }
    }
    finally {
        if ($Process -and -not $Process.HasExited) { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue }
    }
}

# Test Pageant certificate autoload and filtering capabilities
function Test-PageantFilters([object[]]$Positive, [object[]]$Negative) {
    if ($Positive.Count -eq 0) {
        foreach ($N in @('PAGEANT-AUTOLOAD', 'PAGEANT-IGNOREEXPIRED', 'PAGEANT-TRUSTFILTER', 'PAGEANT-SAVELIST')) {
            Add-Result -Name $N -Status 'Skip' -Detail 'No positive test certificates available for Pageant tests.'
        }
        return
    }

    $ExpiredCase = $Negative | Where-Object Name -eq 'NEG-EXPIRED' | Select-Object -First 1

    # Test autoload with expiry and optional trust filters
    $AutoloadArgs = [List[string]]::new()
    $AutoloadArgs.Add('-autoload') | Out-Null
    $AutoloadArgs.Add('-ignoreexpiredcerts') | Out-Null
    if ($TrustTestRoots) { $AutoloadArgs.Add('-trustedcertsonly') | Out-Null }

    $Bridge = Start-Pageant -Arguments $AutoloadArgs

    try {
        $Keys = @(Get-PageantKeys -Agent $Bridge.Agent | ForEach-Object { Get-KeyId $_ })

        # Verify all positive certificates are autoloaded
        foreach ($Case in $Positive) {
            if ($Keys -notcontains (Get-KeyId $Case.AuthorizedKey)) { throw "Missing autoloaded key for $($Case.Name)." }
        }

        # Verify negative certificates are properly filtered
        $ExpectedFiltered = if ($TrustTestRoots) {
            @($Negative | Where-Object Name -ne 'NEG-EXPIRED')
        }
        else {
            @($Negative | Where-Object { $_.Name -notin @('NEG-UNTRUSTED', 'NEG-EXPIRED') })
        }

        foreach ($Case in $ExpectedFiltered) {
            if ($Keys -contains $Case.KeyId) { throw "Unexpected filtered key listed for $($Case.Name)." }
        }

        Add-Result -Name 'PAGEANT-AUTOLOAD' -Status 'Pass' -Detail (Get-PageantAutoloadMessage)

        # Test -ignoreexpiredcerts behavior
        if ($ExpiredCase) {
            if ($Keys -notcontains $ExpiredCase.KeyId) { throw 'Expected NEG-EXPIRED to be listed when -ignoreexpiredcerts is enabled.' }
            Add-Result -Name 'PAGEANT-IGNOREEXPIRED' -Status 'Pass' -Detail 'Verified current implementation behavior: -ignoreexpiredcerts causes expired certificates to remain eligible for autoload.'
        }

        if (-not $TrustTestRoots) { Add-Result -Name 'PAGEANT-TRUSTFILTER' -Status 'Skip' -Detail 'Skipped TrustedCertsOnly autoload coverage because trusted root installation was not requested.' }
    }
    finally {
        if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
    }

    # Test certificate list persistence in registry
    $SaveList = $Positive | Select-Object -First ([Math]::Min(2, $Positive.Count))

    if ($SaveList.Count -gt 0) {
        New-Item -Path 'HKCU:\Software\SimonTatham\PuTTY' -Force | Out-Null
        New-ItemProperty -LiteralPath 'HKCU:\Software\SimonTatham\PuTTY' -Name 'SaveCertListEnabled' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -LiteralPath 'HKCU:\Software\SimonTatham\PuTTY' -Name 'SaveCertList' -PropertyType MultiString -Value ($SaveList.CertId) -Force | Out-Null

        $Bridge = Start-Pageant -Arguments @()

        try {
            $Keys = @(Get-PageantKeys -Agent $Bridge.Agent | ForEach-Object { Get-KeyId $_ })

            foreach ($Case in $SaveList) {
                if ($Keys -notcontains (Get-KeyId $Case.AuthorizedKey)) { throw "Saved certificate $($Case.Name) was not restored into Pageant." }
            }

            Add-Result -Name 'PAGEANT-SAVELIST' -Status 'Pass' -Detail 'Pageant restored saved certificate list from registry.'
        }
        finally {
            if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
        }
    }
}

# Test registry persistence of PuTTY command-line flags
function Test-RegistryFlags {
    # Build table of on/off flag pairs that should persist to registry
    $Flags = [ordered]@{
        AutoloadCerts           = @{ On = '-autoload';                Off = '-autoloadoff' }
        SaveCertListEnabled     = @{ On = '-savecertlist';            Off = '-savecertlistoff' }
        ForcePinCaching         = @{ On = '-forcepincache';           Off = '-forcepincacheoff' }
        CertAuthPrompting       = @{ On = '-certauthprompting';       Off = '-certauthpromptingoff' }
        SmartCardLogonCertsOnly = @{ On = '-smartcardlogoncertsonly'; Off = '-smartcardlogoncertsonlyoff' }
        TrustedCertsOnly        = @{ On = '-trustedcertsonly';        Off = '-trustedcertsonlyoff' }
        IgnoreExpiredCerts      = @{ On = '-ignoreexpiredcerts';      Off = '-ignoreexpiredcertsoff' }
        AllowAnyCert            = @{ On = '-allowanycert';            Off = '-allowanycertoff' }
    }

    $Executables = @($script:Paths.Plink, $script:Paths.Pscp, $script:Paths.Psftp, $script:Paths.Pageant) |
    Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }

    foreach ($Exe in $Executables) {
        foreach ($Name in $Flags.Keys) {
            Remove-ItemProperty -LiteralPath 'HKCU:\Software\SimonTatham\PuTTY' -Name $Name -Force -ErrorAction SilentlyContinue
            Invoke-FlagSetter -FilePath $Exe -Flag $Flags[$Name].On  -RegistryName $Name -ExpectedValue 1
            Invoke-FlagSetter -FilePath $Exe -Flag $Flags[$Name].Off -RegistryName $Name -ExpectedValue 0
        }

        Add-Result -Name "REGISTRY-$([IO.Path]::GetFileName($Exe))" -Status 'Pass' `
            -Detail 'All PuTTY-CAC registry-backed CLI SET and UNSET flags persisted to registry as expected.'
    }
}

# Delete all test certificates from certificate store
function Remove-TestCertificates {
    foreach ($Thumb in $script:State.CreatedThumbprints | Select-Object -Unique) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\$Thumb") -DeleteKey -Force -ErrorAction SilentlyContinue
        Remove-FromCurrentUserRootStore -Thumbprint $Thumb
    }
}

# Remove test entries from authorized_keys file
function Restore-AuthorizedKeys {
    $AuthorizedKeys = Join-Path $HOME '.ssh\authorized_keys'

    if (-not (Test-Path -LiteralPath $AuthorizedKeys -PathType Leaf)) {
        return
    }

    $Content = Get-Content -LiteralPath $AuthorizedKeys |
    Where-Object { $_ -notmatch '^# PuTTYCAC-TEST' -and $_ -notin $script:State.AuthorizedKeyLines }

    Set-Content -LiteralPath $AuthorizedKeys -Value $Content -Encoding ascii
}

# Write test results summary to JSON file and console
function Write-Summary {
    $SummaryPath = Join-Path $script:Paths.Run 'summary.json'
    $script:State.Results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $SummaryPath -Encoding utf8

    $Pass = @($script:State.Results | Where-Object Status -eq 'Pass').Count
    $Skip = @($script:State.Results | Where-Object Status -eq 'Skip').Count
    $Fail = @($script:State.Results | Where-Object Status -eq 'Fail').Count

    Write-Host ("Summary: {0} passed, {1} skipped, {2} failed. Log: {3}" -f $Pass, $Skip, $Fail, $SummaryPath)

    if ($Fail -gt 0) {
        throw 'One or more PuTTY-CAC tests failed.'
    }
}

# Main execution block
try {
    $script:Paths.Run = New-Directory $WorkingRoot

    if (-not (Test-Path -LiteralPath $OpenSSHRoot -PathType Container)) {
        throw "Missing OpenSSH directory: $OpenSSHRoot"
    }

    $script:Paths.OpenSSH = (Resolve-Path -LiteralPath $OpenSSHRoot).Path
    $PuttyRootResolved = Resolve-PuTTYRoot
    $script:Paths.Putty = Join-Path $PuttyRootResolved 'putty.exe'
    $script:Paths.Plink = Get-CommandPath (Join-Path $PuttyRootResolved 'plink.exe')
    $script:Paths.Psftp = Get-CommandPath (Join-Path $PuttyRootResolved 'psftp.exe')
    $script:Paths.Pscp = Join-Path $PuttyRootResolved 'pscp.exe'
    $script:Paths.Pageant = Get-CommandPath (Join-Path $PuttyRootResolved 'pageant.exe')
    $script:Paths.PuttyTel = Join-Path $PuttyRootResolved 'puttytel.exe'
    $script:Paths.PTerm = Join-Path $PuttyRootResolved 'pterm.exe'
    $script:Paths.SshExe = Get-CommandPath (Join-Path $OpenSSHRoot 'ssh.exe')
    $script:Paths.SshAdd = Get-CommandPath (Join-Path $OpenSSHRoot 'ssh-add.exe')

    Backup-PuTTYRegistry

    $Matrix = New-TestMatrix

    if (-not (Test-IsAdmin)) { throw 'OpenSSH setup requires elevated PowerShell session.' }

    $ConfigPath = Backup-SshdConfig
    Set-SshdConfig -ConfigPath $ConfigPath
    Set-AuthorizedKeys -Matrix $Matrix.Positive | Out-Null
    Restart-Sshd
    Add-Result -Name 'OPENSSH-SETUP' -Status 'Pass' -Detail 'Configured local OpenSSH server for current-user public key auth.'

    $HostKeys = Get-HostKeyFingerprints

    # Build PKCS#11 test matrix if a PKCS#11 library was supplied
    $Pkcs11Matrix = [List[object]]::new()
    if ($Pkcs11Library) {
        if (-not (Test-Path -LiteralPath $Pkcs11Library -PathType Leaf)) {
            Add-Result -Name 'PKCS11-SETUP' -Status 'Fail' -Detail "PKCS#11 library not found: $Pkcs11Library"
        }
        else {
            foreach ($Entry in (New-Pkcs11TestMatrix)) { $Pkcs11Matrix.Add($Entry) | Out-Null }
            if ($Pkcs11Matrix.Count -gt 0) {
                Set-AuthorizedKeys -Matrix ($Matrix.Positive + $Pkcs11Matrix) | Out-Null
                Add-Result -Name 'PKCS11-SETUP' -Status 'Pass' -Detail "Loaded $($Pkcs11Matrix.Count) PKCS#11 test certificate(s) from $Pkcs11Library."
            }
        }
    }

    foreach ($Case in $Matrix.Positive) {
        Invoke-PlinkTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys
        Invoke-PscpTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys

        if (Test-Path -LiteralPath $script:Paths.Psftp -PathType Leaf) { Invoke-PsftpTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys }
    }

    # Run plink and psftp tests for PKCS#11 certificates
    foreach ($Case in $Pkcs11Matrix) {
        Invoke-PlinkTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys
        Invoke-PscpTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys

        if (Test-Path -LiteralPath $script:Paths.Psftp -PathType Leaf) { Invoke-PsftpTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys }
    }

    # Test Pageant as an SSH agent (using first positive cert to keep runtime reasonable)
    $AgentTestCase = $Matrix.Positive | Select-Object -First 1
    if ($AgentTestCase) { Invoke-PageantAgentTest -Name $AgentTestCase.Name -CertId $AgentTestCase.CertId -HostKeys $HostKeys }

    # Test -allowanycert functional behavior with an untrusted certificate
    $UntrustedNeg = $Matrix.Negative | Where-Object Name -eq 'NEG-UNTRUSTED' | Select-Object -First 1
    Test-AllowAnyCert -UntrustedCase $UntrustedNeg -HostKeys $HostKeys

    Test-PageantFilters -Positive $Matrix.Positive -Negative $Matrix.Negative

    Test-RegistryFlags
}
catch {
    $Message = $_.Exception.Message
    Add-Result -Name 'UNHANDLED' -Status 'Fail' -Detail $Message
}
finally {
    Stop-Pageants

    Restore-AuthorizedKeys
    Restore-SshdConfig
    Restore-PuTTYRegistry
    Remove-TestCertificates

    Write-Summary 
}
