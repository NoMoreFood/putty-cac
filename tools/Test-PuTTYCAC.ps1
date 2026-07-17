#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.Diagnostics
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Security.Principal
using namespace System.Runtime.InteropServices
using namespace System.IO
using namespace System.Security.AccessControl
using namespace System.Text

[CmdletBinding()]
param(
    [string]$PuTTYRoot,
    [string]$OpenSSHRoot = (Join-Path $env:WINDIR 'System32\OpenSSH'),
    [string]$WorkingRoot = (Join-Path $env:TEMP 'PuTTYCAC-Test'),
    [int[]]$RsaKeyLengths = @(1024, 2048, 3072, 4096),
    [switch]$IncludeLegacyRsaProviders,
    [switch]$TrustTestRoots,
    [switch]$UseSmartCard,
    [string]$SmartCardProvider = 'Microsoft Smart Card Key Storage Provider',
    [string]$Pkcs11Library,
    [string]$Pkcs11Pin = '1234'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$HostName = '127.0.0.1'
$Port = 2222
$UserName = 'testuser'

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
$SecureShellClientEku = '1.3.6.1.5.5.7.3.21'
$ServerAuthEku = '1.3.6.1.5.5.7.3.1'
$SmartCardLogonEku = '1.3.6.1.4.1.311.20.2.2'

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
    $OutTask = $Process.StandardOutput.ReadToEndAsync()
    $ErrTask = $Process.StandardError.ReadToEndAsync()
    $Process.WaitForExit()

    $StdOut = $OutTask.GetAwaiter().GetResult()
    $StdErr = $ErrTask.GetAwaiter().GetResult()

    if (-not $IgnoreExitCode -and $Process.ExitCode -ne 0) { throw "Command failed ($($Process.ExitCode)): $FilePath $($ArgumentList -join ' ')`n$StdOut`n$StdErr" }

    return [PSCustomObject]@{
        ExitCode = $Process.ExitCode
        StdOut   = $StdOut.Trim()
        StdErr   = $StdErr.Trim()
    }
}

# Add certificate to the trusted root store (LocalMachine if running as Admin to avoid prompt, otherwise CurrentUser)
function Add-ToCurrentUserRootStore([X509Certificate2]$Certificate) {
    $IsAdmin = ([WindowsPrincipal][WindowsIdentity]::GetCurrent()).IsInRole([WindowsBuiltInRole]::Administrator)
    $StoreLocation = if ($IsAdmin) { 'LocalMachine' } else { 'CurrentUser' }
    $Store = [X509Store]::new('Root', $StoreLocation)

    try {
        $Store.Open([OpenFlags]::ReadWrite)
        $Store.Add($Certificate)
    }
    finally {
        $Store.Close()
    }
}

# Remove certificate from the trusted root store by thumbprint
function Remove-FromCurrentUserRootStore([string]$Thumbprint) {
    # Delete from Registry to avoid the Windows Security Warning popup for Root store deletions
    $Paths = @(
        "HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates\$Thumbprint",
        "HKLM:\Software\Microsoft\SystemCertificates\Root\Certificates\$Thumbprint"
    )
    foreach ($Path in $Paths) {
        if (Test-Path -LiteralPath $Path) {
            try {
                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            }
            catch {
                # Ignore access errors (e.g. HKLM if not admin)
            }
        }
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
        (Join-Path $script:State.WorkspaceRoot "build\$NativeArch\Release"),
        (Join-Path $script:State.WorkspaceRoot "build\$NativeArch\Debug"),
        (Join-Path $script:State.WorkspaceRoot "binaries\$NativeArch")
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

    if ($EnhancedKeyUsage.Count -gt 0) { $CertArgs.TextExtension += ('2.5.29.37={text}' + ($EnhancedKeyUsage -join ',')) }

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

# Create a leaf/intermediate/root hierarchy for RFC 6187 chain encoding tests.
function New-ChainedTestCertificate {
    $Suffix = [Guid]::NewGuid().ToString('N')
    $Common = @{
        Type              = 'Custom'
        CertStoreLocation = 'Cert:\CurrentUser\My'
        KeyAlgorithm      = 'RSA'
        KeyLength         = 2048
        Provider          = $CngProvider
        HashAlgorithm     = 'SHA256'
    }

    $Root = New-SelfSignedCertificate @Common `
        -Subject "CN=PuTTYCAC Chain Root $Suffix" `
        -KeyUsage CertSign, CRLSign `
        -TextExtension @('2.5.29.19={critical}{text}ca=true&pathlength=1') `
        -NotAfter (Get-Date).AddDays(30)
    $script:State.CreatedThumbprints.Add($Root.Thumbprint) | Out-Null

    $Intermediate = New-SelfSignedCertificate @Common -Signer $Root `
        -Subject "CN=PuTTYCAC Chain Intermediate $Suffix" `
        -KeyUsage CertSign, CRLSign `
        -TextExtension @('2.5.29.19={critical}{text}ca=true&pathlength=0') `
        -NotAfter (Get-Date).AddDays(29)
    $script:State.CreatedThumbprints.Add($Intermediate.Thumbprint) | Out-Null

    $Leaf = New-SelfSignedCertificate @Common -Signer $Intermediate `
        -Subject "CN=PuTTYCAC Chain Leaf $Suffix" `
        -KeyUsage DigitalSignature `
        -TextExtension @(
            '2.5.29.19={critical}{text}ca=false',
            "2.5.29.37={text}$ClientAuthEku"
        ) `
        -NotAfter (Get-Date).AddDays(28)
    $script:State.CreatedThumbprints.Add($Leaf.Thumbprint) | Out-Null

    $EcdsaLeaves = [List[object]]::new()
    foreach ($Bits in @(256, 384, 521)) {
        $EcdsaLeaf = New-SelfSignedCertificate `
            -Type Custom `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -Signer $Intermediate `
            -Subject "CN=PuTTYCAC ECDSA P$Bits Chain Leaf $Suffix" `
            -Provider $CngProvider `
            -KeyAlgorithm "ECDSA_nistP$Bits" `
            -CurveExport CurveName `
            -HashAlgorithm 'SHA256' `
            -KeyUsage DigitalSignature `
            -TextExtension @(
                '2.5.29.19={critical}{text}ca=false',
                "2.5.29.37={text}$ClientAuthEku"
            ) `
            -NotAfter (Get-Date).AddDays(28)
        $script:State.CreatedThumbprints.Add($EcdsaLeaf.Thumbprint) | Out-Null
        $EcdsaLeaves.Add([PSCustomObject]@{
                Name    = "ECDSA-P$Bits-CHAIN"
                CertId  = "CAPI:$($EcdsaLeaf.Thumbprint.ToLowerInvariant())"
                Cert    = $EcdsaLeaf
                KeyType = 'ECDSA'
                Bits    = $Bits
            }) | Out-Null
    }

    if ($TrustTestRoots) {
        Add-ToCurrentUserRootStore -Certificate $Root
        $script:State.TrustedThumbprints.Add($Root.Thumbprint) | Out-Null
    }

    return [PSCustomObject]@{
        Name         = 'RFC6187-CHAIN'
        CertId       = "CAPI:$($Leaf.Thumbprint.ToLowerInvariant())"
        Leaf         = $Leaf
        Intermediate = $Intermediate
        Root         = $Root
        EcdsaLeaves  = $EcdsaLeaves.ToArray()
    }
}

# Write a certificate in the PEM form expected by PKIX-SSH's X.509 trust store.
function Write-CertificatePem([X509Certificate2]$Certificate, [string]$Path) {
    $Base64 = [Convert]::ToBase64String($Certificate.RawData)
    $Body = [List[string]]::new()
    for ($Offset = 0; $Offset -lt $Base64.Length; $Offset += 64) {
        $Body.Add($Base64.Substring($Offset, [Math]::Min(64, $Base64.Length - $Offset))) | Out-Null
    }

    $Pem = (@('-----BEGIN CERTIFICATE-----') + $Body.ToArray() +
        @('-----END CERTIFICATE-----')) -join "`n"
    [File]::WriteAllText($Path, "$Pem`n", [UTF8Encoding]::new($false))
}

function Set-PkixSelfIssuedPolicy([bool]$Allow) {
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $DockerCmd) { throw 'Docker is unavailable while setting PKIX-SSH certificate policy.' }

    $Value = $Allow ? 'yes' : 'no'
    $Cmd = "sed -i '/^KeyAllowSelfIssued/d' /etc/pkixssh/sshd_config && printf '%s\n' 'KeyAllowSelfIssued $Value' >> /etc/pkixssh/sshd_config"
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'exec', $PkixContainerName, 'sh', '-c', $Cmd
    ) | Out-Null
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'exec', $PkixContainerName, '/opt/pkixssh/sbin/sshd', '-t',
        '-f', '/etc/pkixssh/sshd_config'
    ) | Out-Null
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'kill', '-s', 'HUP', $PkixContainerName
    ) | Out-Null
    Start-Sleep -Milliseconds 100
}

# Give the isolated PKIX-SSH server only the root trust anchor. The intermediate
# deliberately remains client-side so chain authentication depends on RFC 6187
# transmitting it with the leaf certificate.
function Install-PkixChainTrust([object]$ChainCase) {
    if (-not $ChainCase) { return }

    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $DockerCmd) { throw 'Docker is unavailable while installing the chain trust anchor.' }

    $PemPath = Join-Path $script:Paths.Run 'rfc6187-chain-root.pem'
    $ContainerPemPath = '/etc/pkixssh/puttycac-chain-root.pem'
    Write-CertificatePem -Certificate $ChainCase.Root -Path $PemPath
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'cp', $PemPath, "${PkixContainerName}:$ContainerPemPath"
    ) | Out-Null

    $Cmd = "sed -i '/^CACertificateFile/d' /etc/pkixssh/sshd_config && printf '%s\n' 'CACertificateFile $ContainerPemPath' >> /etc/pkixssh/sshd_config"
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'exec', $PkixContainerName, 'sh', '-c', $Cmd
    ) | Out-Null
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'exec', $PkixContainerName, '/opt/pkixssh/sbin/sshd', '-t',
        '-f', '/etc/pkixssh/sshd_config'
    ) | Out-Null
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'kill', '-s', 'HUP', $PkixContainerName
    ) | Out-Null
    Start-Sleep -Milliseconds 100

    $script:Paths.PkixChainRoot = $PemPath
    Add-Result -Name 'PKIX-SSH-CHAIN-TRUST' -Status 'Pass' -Detail `
        'Configured the server with only the self-signed chain root; the intermediate remains client-side.'
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
        $CertObj = [X509Certificate2]::new([File]::ReadAllBytes($CertPemPath))

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

# Create a RFC 6187 x509v3-ssh-rsa public key line from an X509Certificate2
function Get-X509v3SshRsaKeyLine([X509Certificate2]$Certificate) {
    $RawCert = $Certificate.RawData
    $Stream = [MemoryStream]::new()
    $Writer = [BinaryWriter]::new($Stream)

    $WriteUInt32BE = {
        param($val)
        $bytes = [BitConverter]::GetBytes([uint32]$val)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        $Writer.Write($bytes)
    }

    $AlgBytes = [Encoding]::ASCII.GetBytes("x509v3-ssh-rsa")
    $WriteUInt32BE.Invoke($AlgBytes.Length)
    $Writer.Write($AlgBytes)
    $WriteUInt32BE.Invoke(1)
    $WriteUInt32BE.Invoke($RawCert.Length)
    $Writer.Write($RawCert)
    $WriteUInt32BE.Invoke(0) # OCSP response count (0)
    $Writer.Flush()

    $Blob = $Stream.ToArray()
    $Base64 = [Convert]::ToBase64String($Blob)
    return "x509v3-ssh-rsa $Base64"
}

# Create a RFC 6187 x509v3-rsa2048-sha256 public key line from an X509Certificate2
function Get-X509v3Rsa2048Sha256KeyLine([X509Certificate2]$Certificate) {
    $RawCert = $Certificate.RawData
    $Stream = [MemoryStream]::new()
    $Writer = [BinaryWriter]::new($Stream)

    $WriteUInt32BE = {
        param($val)
        $bytes = [BitConverter]::GetBytes([uint32]$val)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        $Writer.Write($bytes)
    }

    $AlgBytes = [Encoding]::ASCII.GetBytes("x509v3-rsa2048-sha256")
    $WriteUInt32BE.Invoke($AlgBytes.Length)
    $Writer.Write($AlgBytes)
    $WriteUInt32BE.Invoke(1)
    $WriteUInt32BE.Invoke($RawCert.Length)
    $Writer.Write($RawCert)
    $WriteUInt32BE.Invoke(0) # OCSP response count (0)
    $Writer.Flush()

    $Blob = $Stream.ToArray()
    $Base64 = [Convert]::ToBase64String($Blob)
    return "x509v3-rsa2048-sha256 $Base64"
}

# Create a RFC 6187 x509v3-ecdsa-sha2-nistp256 public key line from an X509Certificate2
function Get-X509v3EcdsaSha2Nistp256KeyLine([X509Certificate2]$Certificate) {
    return Get-X509v3EcdsaKeyLine -Certificate $Certificate -CurveAlg "x509v3-ecdsa-sha2-nistp256"
}

# Create a RFC 6187 x509v3-ecdsa-sha2-nistp384 public key line from an X509Certificate2
function Get-X509v3EcdsaSha2Nistp384KeyLine([X509Certificate2]$Certificate) {
    return Get-X509v3EcdsaKeyLine -Certificate $Certificate -CurveAlg "x509v3-ecdsa-sha2-nistp384"
}

# Create a RFC 6187 x509v3-ecdsa-sha2-nistp521 public key line from an X509Certificate2
function Get-X509v3EcdsaSha2Nistp521KeyLine([X509Certificate2]$Certificate) {
    return Get-X509v3EcdsaKeyLine -Certificate $Certificate -CurveAlg "x509v3-ecdsa-sha2-nistp521"
}

function Get-X509v3EcdsaKeyLine([X509Certificate2]$Certificate, [string]$CurveAlg) {
    $RawCert = $Certificate.RawData
    $Stream = [System.IO.MemoryStream]::new()
    $Writer = [System.IO.BinaryWriter]::new($Stream)

    $WriteUInt32BE = {
        param($val)
        $bytes = [BitConverter]::GetBytes([uint32]$val)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        $Writer.Write($bytes)
    }

    $AlgBytes = [System.Text.Encoding]::ASCII.GetBytes($CurveAlg)
    $WriteUInt32BE.Invoke($AlgBytes.Length)
    $Writer.Write($AlgBytes)
    $WriteUInt32BE.Invoke(1)
    $WriteUInt32BE.Invoke($RawCert.Length)
    $Writer.Write($RawCert)
    $WriteUInt32BE.Invoke(0) # OCSP response count (0)
    $Writer.Flush()

    $Blob = $Stream.ToArray()
    $Base64 = [Convert]::ToBase64String($Blob)
    return "$CurveAlg $Base64"
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

    # RFC 6187 defines a dedicated Secure Shell Client EKU. A certificate
    # containing only that EKU must be eligible anywhere clientAuth is.
    try {
        $Case = 'RSA-2048-SSH-EKU'
        $Cert = New-TestCertificate -CaseName $Case -Provider $CngProvider `
            -KeyAlgorithm 'RSA' -KeyLength 2048 `
            -EnhancedKeyUsage @($SecureShellClientEku) `
            -NotAfter (Get-Date).AddDays(30) -TrustRoot:$TrustTestRoots

        $Matrix.Add([PSCustomObject]@{
                Name          = $Case
                Cert          = $Cert
                CertId        = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                KeyType       = 'RSA'
                Provider      = $CngProvider
                Bits          = 2048
                AuthorizedKey = (Get-OpenSshKeyLine -Certificate $Cert)
            }) | Out-Null
        Add-Result -Name $Case -Status 'Pass' -Detail `
            'Created RFC 6187 Secure Shell Client EKU certificate.'
    }
    catch {
        Add-Result -Name 'RSA-2048-SSH-EKU' -Status 'Skip' -Detail $_.Exception.Message
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

    # Create negative test certificates (invalid scenarios)
    $Negative = [List[object]]::new()

    # Server auth only (should not be eligible for client auth)
    try {
        $Cert = New-TestCertificate -CaseName 'NEG-SERVERAUTH' -Provider $CngProvider -KeyAlgorithm 'RSA' -KeyLength 2048 -EnhancedKeyUsage @($ServerAuthEku) -NotAfter (Get-Date).AddDays(30)

        $Negative.Add([PSCustomObject]@{
                Name           = 'NEG-SERVERAUTH'
                CertId         = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
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
                KeyId          = (Get-KeyId (Get-OpenSshKeyLine -Certificate $Cert))
            }) | Out-Null

        Add-Result -Name 'NEG-UNTRUSTED' -Status 'Pass' -Detail 'Created untrusted negative certificate.'
    }
    catch {
        Add-Result -Name 'NEG-UNTRUSTED' -Status 'Skip' -Detail $_.Exception.Message
    }

    # Smart card logon cert (has the SC Logon EKU) for the -smartcardlogoncertsonly test
    $SmartCardLogon = $null
    try {
        $Cert = New-TestCertificate -CaseName 'POS-SCLOGON' -Provider $CngProvider -KeyAlgorithm 'RSA' -KeyLength 2048 -EnhancedKeyUsage @($ClientAuthEku, $SmartCardLogonEku) -NotAfter (Get-Date).AddDays(30) -TrustRoot:$TrustTestRoots

        $SmartCardLogon = [PSCustomObject]@{
            Name   = 'POS-SCLOGON'
            Cert   = $Cert
            CertId = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
            KeyId  = (Get-KeyId (Get-OpenSshKeyLine -Certificate $Cert))
        }

        Add-Result -Name 'POS-SCLOGON' -Status 'Pass' -Detail 'Created smart card logon certificate.'
    }
    catch {
        Add-Result -Name 'POS-SCLOGON' -Status 'Skip' -Detail $_.Exception.Message
    }

    $ChainCase = $null
    try {
        $ChainCase = New-ChainedTestCertificate
        Add-Result -Name 'RFC6187-CHAIN-SETUP' -Status 'Pass' -Detail `
            'Created leaf, intermediate, and self-signed root certificates.'
    }
    catch {
        Add-Result -Name 'RFC6187-CHAIN-SETUP' -Status 'Skip' -Detail $_.Exception.Message
    }

    return [PSCustomObject]@{
        Positive       = $Matrix
        Negative       = $Negative
        SmartCardLogon = $SmartCardLogon
        ChainCase      = $ChainCase
    }
}



# Test SSH connectivity using plink with certificate authentication
function Invoke-PlinkTest(
    [string]$Name,
    [string]$CertId,
    [string[]]$HostKeys,
    [switch]$NoRetry,
    [int]$ServerPort = $Port
) {
    $ArgList = @('-batch', '-ssh', '-P', $ServerPort.ToString(), '-l', $UserName) +
    ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
    @('-i', $CertId, $HostName, 'whoami')

    $MaxAttempts = $NoRetry ? 1 : 3
    $Attempt = 0
    $Success = $false
    $Result = $null

    while (-not $Success -and $Attempt -lt $MaxAttempts) {
        $Attempt++
        try {
            $Result = Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $ArgList
            if ($Result.StdOut -match [regex]::Escape($UserName)) {
                $Success = $true
            } else {
                if ($Attempt -eq $MaxAttempts) {
                    throw "Unexpected plink output: $($Result.StdOut)`n$($Result.StdErr)"
                }
                Start-Sleep -Milliseconds 500
            }
        }
        catch {
            if ($Attempt -eq $MaxAttempts) {
                throw
            }
            Start-Sleep -Milliseconds 500
        }
    }

    $CredentialType = ($CertId -split ':', 2)[0]
    Add-Result -Name "PLINK-$Name" -Status 'Pass' -Detail "Direct $CredentialType authentication succeeded."
}

# Test SFTP connectivity using psftp with certificate authentication
function Invoke-PsftpTest(
    [string]$Name,
    [string]$CertId,
    [string[]]$HostKeys,
    [int]$ServerPort = $Port
) {
    $Batch = Join-Path $script:Paths.Run "psftp-$Name.txt"
    Set-Content -LiteralPath $Batch -Value @('pwd', 'quit') -Encoding ascii

    $ArgList = @('-batch', '-P', $ServerPort.ToString(), '-l', $UserName) +
    ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
    @('-i', $CertId, '-b', $Batch, $HostName)

    $Result = Invoke-Native -FilePath $script:Paths.Psftp -ArgumentList $ArgList

    if ($Result.StdOut -notmatch '/' -and $Result.StdErr -notmatch 'Remote directory is') { throw 'PSFTP did not return a working directory.' }

    Add-Result -Name "PSFTP-$Name" -Status 'Pass' -Detail 'Batch PSFTP authentication succeeded.'
}

# Test secure file copy using pscp with certificate authentication
function Invoke-PscpTest(
    [string]$Name,
    [string]$CertId,
    [string[]]$HostKeys,
    [int]$ServerPort = $Port
) {
    if (-not (Test-Path -LiteralPath $script:Paths.Pscp -PathType Leaf)) {
        Add-Result -Name "PSCP-$Name" -Status 'Skip' -Detail 'pscp.exe not found; skipping PSCP test.'
        return
    }

    $LocalFile = Join-Path $script:Paths.Run "pscp-$Name.txt"
    Set-Content -LiteralPath $LocalFile -Value "PuTTYCAC-PSCP-TEST-$Name" -Encoding ascii

    $RemotePath = "$UserName@${HostName}:pscp-$Name.txt"
    $ArgList = @('-batch', '-P', $ServerPort.ToString(), '-l', $UserName) +
    ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
    @('-i', $CertId, $LocalFile, $RemotePath)

    Invoke-Native -FilePath $script:Paths.Pscp -ArgumentList $ArgList | Out-Null

    Add-Result -Name "PSCP-$Name" -Status 'Pass' -Detail 'PSCP file upload authentication succeeded.'
}

# Test SSH authentication via Pageant acting as SSH agent (uses OpenSSH ssh.exe)
function Invoke-PageantAgentTest(
    [string]$Name,
    [string]$CertId,
    [string[]]$HostKeys,
    [int]$ServerPort = $Port,
    [string]$HostKeyDirectory = $script:Paths.PkixHostKeys
) {
    $Bridge = Start-Pageant -Arguments @($CertId)

    try {
        # Build known_hosts from the actual host public key files — $HostKeys contains
        # fingerprints for plink, but ssh.exe needs "hostname keytype base64key" lines.
        $KnownHostsPath = Join-Path $script:Paths.Run "pageant_known_hosts_$Name"
        $KnownHostsHost = if ($ServerPort -eq 22) { $HostName } else { "[$HostName]:$ServerPort" }
        $KnownHostsLines = Get-ChildItem -LiteralPath $HostKeyDirectory -Filter 'ssh_host_*_key.pub' -File |
            ForEach-Object { "$KnownHostsHost $((Get-Content -LiteralPath $_.FullName -Raw).Trim())" }
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
            '-p', $ServerPort.ToString(),
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

# Validate standard public-key authentication against Dropbear, an SSH server
# implementation independent of the OpenSSH-derived PKIX-SSH server above.
function Test-DropbearInteroperability(
    [object[]]$Cases,
    [object]$AgentTestCase,
    [object]$UnauthorizedCase
) {
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $DockerCmd) { throw 'Docker is unavailable for Dropbear interoperability testing.' }
    if (-not (Test-Path -LiteralPath $DropbearDockerfile -PathType Leaf)) {
        throw "Dropbear Dockerfile not found at $DropbearDockerfile"
    }

    $AuthKeysPath = Join-Path $script:Paths.Run 'dropbear_authorized_keys'
    $HostKeyDirectory = Join-Path $script:Paths.Run 'dropbear_hostkeys'

    try {
        Write-Host 'Building Dropbear Docker image (cached after first build)...'
        $BuildContext = Split-Path -Parent $DropbearDockerfile
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'build', '-t', $DropbearImageName, $BuildContext
        ) | Out-Null

        $AuthorizedKeys = @($Cases | ForEach-Object { $_.AuthorizedKey } | Where-Object { $_ })
        if ($AuthorizedKeys.Count -eq 0) { throw 'No raw SSH public keys were available for Dropbear testing.' }
        Set-Content -LiteralPath $AuthKeysPath -Value $AuthorizedKeys -Encoding ascii

        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'rm', '-f', $DropbearContainerName
        ) -IgnoreExitCode | Out-Null

        Write-Host "Starting Dropbear Docker container on port $DropbearPort..."
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'run', '-d',
            '--name', $DropbearContainerName,
            '-p', "127.0.0.1:$($DropbearPort):2223",
            $DropbearImageName
        ) | Out-Null

        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'cp', $AuthKeysPath,
            "${DropbearContainerName}:/home/testuser/.ssh/authorized_keys"
        ) | Out-Null
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $DropbearContainerName, 'sh', '-c',
            'chown testuser:testuser /home/testuser/.ssh/authorized_keys && chmod 600 /home/testuser/.ssh/authorized_keys'
        ) | Out-Null

        $Listening = $false
        $Timeout = (Get-Date).AddSeconds(15)
        while ((Get-Date) -lt $Timeout) {
            if (Get-NetTCPConnection -LocalPort $DropbearPort -ErrorAction SilentlyContinue) {
                $Listening = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $Listening) { throw "Dropbear failed to listen on port $DropbearPort." }

        New-Directory $HostKeyDirectory | Out-Null
        $HostKeyFiles = @(
            [PSCustomObject]@{ Name = 'rsa'; Path = '/etc/dropbear/dropbear_rsa_host_key' }
            [PSCustomObject]@{ Name = 'ecdsa'; Path = '/etc/dropbear/dropbear_ecdsa_host_key' }
            [PSCustomObject]@{ Name = 'ed25519'; Path = '/etc/dropbear/dropbear_ed25519_host_key' }
        )
        foreach ($HostKeyFile in $HostKeyFiles) {
            $Output = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
                'exec', $DropbearContainerName, 'dropbearkey', '-y', '-f', $HostKeyFile.Path
            )
            $PublicKeyLine = $Output.StdOut -split "`r?`n" |
                Where-Object { $_ -match '^(ssh-|ecdsa-)' } |
                Select-Object -First 1
            if (-not $PublicKeyLine) { throw "Unable to extract Dropbear $($HostKeyFile.Name) host public key." }

            $PublicKeyPath = Join-Path $HostKeyDirectory "ssh_host_dropbear_$($HostKeyFile.Name)_key.pub"
            Set-Content -LiteralPath $PublicKeyPath -Value $PublicKeyLine -Encoding ascii
        }

        $SshKeyGen = Get-CommandPath (Join-Path $script:Paths.OpenSSH 'ssh-keygen.exe')
        $HostKeys = @($(Get-ChildItem -LiteralPath $HostKeyDirectory -Filter 'ssh_host_*_key.pub' -File |
            ForEach-Object {
                $Output = Invoke-Native -FilePath $SshKeyGen -ArgumentList @('-lf', $_.FullName)
                if ($Output.StdOut -match '^\S+\s+(\S+)\s+') { $Matches[1] }
            }) | Where-Object { $_ } | Select-Object -Unique)
        if ($HostKeys.Count -eq 0) { throw 'Unable to calculate Dropbear host-key fingerprints.' }

        $VersionResult = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $DropbearContainerName, '/usr/sbin/dropbear', '-V'
        ) -IgnoreExitCode
        $Version = (($VersionResult.StdOut, $VersionResult.StdErr) -join ' ').Trim()
        Add-Result -Name 'DROPBEAR-SETUP' -Status 'Pass' `
            -Detail "Started Dockerized $Version for independent SSH implementation coverage."

        if ($UnauthorizedCase) {
            $ArgList = @('-batch', '-ssh', '-P', $DropbearPort.ToString(), '-l', $UserName) +
                ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
                @('-i', $UnauthorizedCase.CertId, $HostName, 'whoami')
            $Result = Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $ArgList -IgnoreExitCode
            if ($Result.ExitCode -eq 0) {
                throw 'Dropbear unexpectedly authenticated a public key absent from authorized_keys.'
            }

            $FailureText = "$($Result.StdOut)`n$($Result.StdErr)"
            if ($FailureText -notmatch '(?i)(authenticat|public[ -]?key|publickey)') {
                throw "Dropbear unauthorized-key test failed for an unrelated reason: $FailureText"
            }
            Add-Result -Name 'DROPBEAR-AUTH-MISMATCH' -Status 'Pass' `
                -Detail 'Dropbear rejected a valid signing key absent from its authorized_keys file.'
        }

        foreach ($Case in $Cases) {
            $TestName = "DROPBEAR-$($Case.Name)"
            Invoke-PlinkTest -Name $TestName -CertId $Case.CertId -HostKeys $HostKeys -ServerPort $DropbearPort
            Invoke-PscpTest -Name $TestName -CertId $Case.CertId -HostKeys $HostKeys -ServerPort $DropbearPort
            if (Test-Path -LiteralPath $script:Paths.Psftp -PathType Leaf) {
                Invoke-PsftpTest -Name $TestName -CertId $Case.CertId -HostKeys $HostKeys -ServerPort $DropbearPort
            }
        }

        if ($AgentTestCase) {
            Invoke-PageantAgentTest -Name "DROPBEAR-$($AgentTestCase.Name)" `
                -CertId $AgentTestCase.CertId -HostKeys $HostKeys `
                -ServerPort $DropbearPort -HostKeyDirectory $HostKeyDirectory
        }
    }
    catch {
        $Logs = Invoke-Native -FilePath $DockerCmd.Source `
            -ArgumentList @('logs', $DropbearContainerName) -IgnoreExitCode
        $LogText = (($Logs.StdOut, $Logs.StdErr) -join "`n").Trim()
        throw "Dropbear interoperability testing failed: $($_.Exception.Message)`n$LogText"
    }
    finally {
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'rm', '-f', $DropbearContainerName
        ) -IgnoreExitCode | Out-Null
        Remove-Item -LiteralPath $AuthKeysPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $HostKeyDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Validate RFC 6187 certificate authentication against wolfSSH. wolfSSH is an
# independent SSH and X.509 implementation, so success here catches encoding,
# chain, and signature assumptions that PKIX-SSH might happen to share with the
# PuTTY/OpenSSH implementation family.
function Test-WolfSshX509Interoperability(
    [object]$ChainCase,
    [object]$UntrustedCase
) {
    if (-not $ChainCase) {
        Add-Result -Name 'WOLFSSH-X509' -Status 'Skip' -Detail `
            'No RFC 6187 certificate-chain test case was available.'
        return
    }

    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $DockerCmd) { throw 'Docker is unavailable for wolfSSH X.509 interoperability testing.' }
    if (-not (Test-Path -LiteralPath $WolfSshDockerfile -PathType Leaf)) {
        throw "wolfSSH Dockerfile not found at $WolfSshDockerfile"
    }

    $RootPemPath = Join-Path $script:Paths.Run 'wolfssh-client-ca.pem'
    $HostKeyDirectory = Join-Path $script:Paths.Run 'wolfssh_hostkeys'

    try {
        Write-Host 'Building wolfSSH Docker image with RFC 6187 support (cached after first build)...'
        $BuildContext = Split-Path -Parent $WolfSshDockerfile
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'build', '-t', $WolfSshImageName, $BuildContext
        ) | Out-Null

        Write-CertificatePem -Certificate $ChainCase.Root -Path $RootPemPath
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'rm', '-f', $WolfSshContainerName
        ) -IgnoreExitCode | Out-Null

        # The CA must exist before wolfsshd starts because it loads its trust
        # manager during process initialization.
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'create',
            '--name', $WolfSshContainerName,
            '-p', "127.0.0.1:$($WolfSshPort):2224",
            $WolfSshImageName
        ) | Out-Null
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'cp', $RootPemPath,
            "${WolfSshContainerName}:/etc/wolfssh/client-ca.pem"
        ) | Out-Null
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'start', $WolfSshContainerName
        ) | Out-Null

        $Listening = $false
        $Timeout = (Get-Date).AddSeconds(15)
        while ((Get-Date) -lt $Timeout) {
            if (Get-NetTCPConnection -LocalPort $WolfSshPort -ErrorAction SilentlyContinue) {
                $Listening = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $Listening) { throw "wolfSSH failed to listen on port $WolfSshPort." }

        New-Directory $HostKeyDirectory | Out-Null
        $PublicKeyLine = (Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $WolfSshContainerName, 'cat', '/etc/wolfssh/server-key.pub'
        )).StdOut.Trim()
        if ($PublicKeyLine -notmatch '^(ssh-|ecdsa-)') {
            throw 'Unable to extract the wolfSSH server host public key.'
        }

        $PublicKeyPath = Join-Path $HostKeyDirectory 'ssh_host_wolfssh_key.pub'
        Set-Content -LiteralPath $PublicKeyPath -Value $PublicKeyLine -Encoding ascii
        $SshKeyGen = Get-CommandPath (Join-Path $script:Paths.OpenSSH 'ssh-keygen.exe')
        $FingerprintOutput = Invoke-Native -FilePath $SshKeyGen -ArgumentList @('-lf', $PublicKeyPath)
        if ($FingerprintOutput.StdOut -notmatch '^\S+\s+(\S+)\s+') {
            throw 'Unable to calculate the wolfSSH host-key fingerprint.'
        }
        $WolfSshHostKeys = @($Matches[1])

        Add-Result -Name 'WOLFSSH-X509-SETUP' -Status 'Pass' -Detail `
            'Started Dockerized wolfSSH 1.5.0 with RFC 6187 enabled and only the test root CA trusted.'

        $WolfSshCases = [List[object]]::new()
        $WolfSshCases.Add([PSCustomObject]@{
                Name      = 'RSA-CHAIN'
                CertId    = $ChainCase.CertId
                Algorithm = 'x509v3-ssh-rsa'
            }) | Out-Null
        foreach ($EcdsaLeaf in $ChainCase.EcdsaLeaves) {
            $WolfSshCases.Add([PSCustomObject]@{
                    Name      = $EcdsaLeaf.Name
                    CertId    = $EcdsaLeaf.CertId
                    Algorithm = "x509v3-ecdsa-sha2-nistp$($EcdsaLeaf.Bits)"
                }) | Out-Null
        }

        # wolfsshd's sample exec handler currently exits successfully without
        # relaying command stdout. For this provider, assert the client exit
        # status here and corroborate certificate authorization from the server
        # log below instead of depending on `whoami` output.
        foreach ($Case in $WolfSshCases) {
            $PlinkArgs = @('-batch', '-ssh', '-P', $WolfSshPort.ToString(), '-l', $UserName) +
                ($WolfSshHostKeys | ForEach-Object { @('-hostkey', $_) }) +
                @('-i', $Case.CertId, $HostName, 'whoami')
            Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $PlinkArgs | Out-Null
            Add-Result -Name "PLINK-WOLFSSH-X509-$($Case.Name)" -Status 'Pass' -Detail `
                "Direct CAPI authentication with $($Case.Algorithm) and exec-session setup succeeded."
        }
        if ($UntrustedCase) {
            $UntrustedArgs = @('-batch', '-ssh', '-P', $WolfSshPort.ToString(), '-l', $UserName) +
                ($WolfSshHostKeys | ForEach-Object { @('-hostkey', $_) }) +
                @('-i', $UntrustedCase.CertId, $HostName, 'whoami')
            $UntrustedResult = Invoke-Native -FilePath $script:Paths.Plink `
                -ArgumentList $UntrustedArgs -IgnoreExitCode
            if ($UntrustedResult.ExitCode -eq 0) {
                throw 'wolfSSH unexpectedly accepted a certificate outside its configured trust hierarchy.'
            }

            $FailureText = "$($UntrustedResult.StdOut)`n$($UntrustedResult.StdErr)"
            if ($FailureText -notmatch '(?i)(authenticat|refused our key|public[ -]?key)') {
                throw "The wolfSSH negative control failed for a reason unrelated to authentication: $FailureText"
            }
            Add-Result -Name 'WOLFSSH-X509-UNTRUSTED-REJECTED' -Status 'Pass' -Detail `
                'wolfSSH rejected an otherwise usable RSA client certificate outside the configured CA hierarchy.'
        }

        $Logs = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'logs', $WolfSshContainerName
        ) -IgnoreExitCode
        $LogText = "$($Logs.StdOut)`n$($Logs.StdErr)"
        $CaAuthorizationCount = [regex]::Matches(
            $LogText, 'Relying on CA for public key check'
        ).Count
        if ($CaAuthorizationCount -lt $WolfSshCases.Count) {
            throw "wolfSSH recorded only $CaAuthorizationCount CA-based authorizations for $($WolfSshCases.Count) successful certificate cases."
        }

        Add-Result -Name 'WOLFSSH-X509-RFC6187' -Status 'Pass' -Detail `
            'Independent wolfSSH validation accepted RSA and ECDSA P-256/P-384/P-521 leaf/intermediate chains and authenticated them to the configured root.'
    }
    catch {
        $Logs = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'logs', $WolfSshContainerName
        ) -IgnoreExitCode
        throw "wolfSSH X.509 interoperability testing failed: $($_.Exception.Message)`n$($Logs.StdOut)`n$($Logs.StdErr)"
    }
    finally {
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'rm', '-f', $WolfSshContainerName
        ) -IgnoreExitCode | Out-Null
        Remove-Item -LiteralPath $HostKeyDirectory -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $RootPemPath -Force -ErrorAction SilentlyContinue
    }
}

# Validate every RFC 6187 RSA/ECDSA algorithm against AsyncSSH. A single
# container exposes one listener per certificate algorithm so each successful
# connection proves the intended negotiation rather than relying on client
# preference. AsyncSSH also supplies complete exec, SCP, and SFTP handlers.
function Test-AsyncSshX509Interoperability(
    [object]$ChainCase,
    [object]$UntrustedCase
) {
    if (-not $ChainCase) {
        Add-Result -Name 'ASYNCSSH-X509' -Status 'Skip' -Detail `
            'No RFC 6187 certificate-chain test case was available.'
        return
    }

    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $DockerCmd) { throw 'Docker is unavailable for AsyncSSH X.509 interoperability testing.' }
    if (-not (Test-Path -LiteralPath $AsyncSshDockerfile -PathType Leaf)) {
        throw "AsyncSSH Dockerfile not found at $AsyncSshDockerfile"
    }

    $RootPemPath = Join-Path $script:Paths.Run 'asyncssh-client-ca.pem'
    $AuthorizedKeysPath = Join-Path $script:Paths.Run 'asyncssh-authorized-keys'
    $HostKeyDirectory = Join-Path $script:Paths.Run 'asyncssh_hostkeys'

    try {
        Write-Host 'Building AsyncSSH Docker image with RFC 6187 support (cached after first build)...'
        $BuildContext = Split-Path -Parent $AsyncSshDockerfile
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'build', '-t', $AsyncSshImageName, $BuildContext
        ) | Out-Null

        Write-CertificatePem -Certificate $ChainCase.Root -Path $RootPemPath

        # Subject authorization and CA trust are deliberately separate. The
        # untrusted control is authorized by subject here, so its later failure
        # can only be satisfied by certificate-chain validation.
        $AuthorizedCertificates = [List[X509Certificate2]]::new()
        $AuthorizedCertificates.Add($ChainCase.Leaf) | Out-Null
        foreach ($EcdsaLeaf in $ChainCase.EcdsaLeaves) {
            $AuthorizedCertificates.Add($EcdsaLeaf.Cert) | Out-Null
        }
        if ($UntrustedCase) {
            $AuthorizedCertificates.Add($UntrustedCase.Cert) | Out-Null
        }

        $AuthorizedSubjectLines = @($AuthorizedCertificates |
            ForEach-Object { "principals=`"*`" x509v3-ssh-rsa subject=$($_.Subject)" })
        Set-Content -LiteralPath $AuthorizedKeysPath -Value $AuthorizedSubjectLines -Encoding ascii

        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'rm', '-f', $AsyncSshContainerName
        ) -IgnoreExitCode | Out-Null

        $CreateArgs = [List[string]]::new()
        foreach ($Argument in @('create', '--name', $AsyncSshContainerName)) {
            $CreateArgs.Add($Argument) | Out-Null
        }
        foreach ($Listener in $AsyncSshListeners) {
            $CreateArgs.Add('-p') | Out-Null
            $CreateArgs.Add("127.0.0.1:$($Listener.Port):$($Listener.Port)") | Out-Null
        }
        $CreateArgs.Add($AsyncSshImageName) | Out-Null

        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList $CreateArgs.ToArray() | Out-Null
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'cp', $RootPemPath,
            "${AsyncSshContainerName}:/etc/asyncssh/client-ca.pem"
        ) | Out-Null
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'cp', $AuthorizedKeysPath,
            "${AsyncSshContainerName}:/etc/asyncssh/authorized_keys"
        ) | Out-Null
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'start', $AsyncSshContainerName
        ) | Out-Null

        $PendingPorts = @($AsyncSshListeners.Port)
        $Timeout = (Get-Date).AddSeconds(20)
        while ($PendingPorts.Count -gt 0 -and (Get-Date) -lt $Timeout) {
            $PendingPorts = @($PendingPorts | Where-Object {
                    -not (Get-NetTCPConnection -State Listen -LocalPort $_ -ErrorAction SilentlyContinue)
                })
            if ($PendingPorts.Count -gt 0) { Start-Sleep -Milliseconds 500 }
        }
        if ($PendingPorts.Count -gt 0) {
            throw "AsyncSSH failed to listen on port(s): $($PendingPorts -join ', ')."
        }

        New-Directory $HostKeyDirectory | Out-Null
        $PublicKeyLine = (Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $AsyncSshContainerName, 'cat',
            '/etc/asyncssh/ssh_host_ed25519_key.pub'
        )).StdOut.Trim()
        if ($PublicKeyLine -notmatch '^ssh-ed25519\s+') {
            throw 'Unable to extract the AsyncSSH server host public key.'
        }

        $PublicKeyPath = Join-Path $HostKeyDirectory 'ssh_host_asyncssh_ed25519_key.pub'
        Set-Content -LiteralPath $PublicKeyPath -Value $PublicKeyLine -Encoding ascii
        $SshKeyGen = Get-CommandPath (Join-Path $script:Paths.OpenSSH 'ssh-keygen.exe')
        $FingerprintOutput = Invoke-Native -FilePath $SshKeyGen -ArgumentList @('-lf', $PublicKeyPath)
        if ($FingerprintOutput.StdOut -notmatch '^\S+\s+(\S+)\s+') {
            throw 'Unable to calculate the AsyncSSH host-key fingerprint.'
        }
        $AsyncSshHostKeys = @($Matches[1])

        $Version = (Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $AsyncSshContainerName, 'python', '-c',
            'import asyncssh; print(asyncssh.__version__)'
        )).StdOut.Trim()
        Add-Result -Name 'ASYNCSSH-X509-SETUP' -Status 'Pass' -Detail `
            "Started Dockerized AsyncSSH $Version with five algorithm-exclusive RFC 6187 listeners and only the test root CA trusted."

        $AsyncSshCases = [List[object]]::new()
        foreach ($Listener in $AsyncSshListeners) {
            $CertId = if ($Listener.Bits -eq 0) {
                $ChainCase.CertId
            }
            else {
                ($ChainCase.EcdsaLeaves |
                    Where-Object Bits -eq $Listener.Bits |
                    Select-Object -First 1).CertId
            }
            if (-not $CertId) {
                throw "No certificate was available for AsyncSSH algorithm $($Listener.Algorithm)."
            }

            $AsyncSshCases.Add([PSCustomObject]@{
                    Name      = $Listener.Name
                    CertId    = $CertId
                    Algorithm = $Listener.Algorithm
                    Port      = $Listener.Port
                }) | Out-Null
        }

        foreach ($Case in $AsyncSshCases) {
            $TestName = "ASYNCSSH-X509-$($Case.Name)"
            Invoke-PlinkTest -Name $TestName -CertId $Case.CertId `
                -HostKeys $AsyncSshHostKeys -ServerPort $Case.Port
            Invoke-PscpTest -Name $TestName -CertId $Case.CertId `
                -HostKeys $AsyncSshHostKeys -ServerPort $Case.Port
            if (Test-Path -LiteralPath $script:Paths.Psftp -PathType Leaf) {
                Invoke-PsftpTest -Name $TestName -CertId $Case.CertId `
                    -HostKeys $AsyncSshHostKeys -ServerPort $Case.Port
            }
        }

        if ($UntrustedCase) {
            $Sha256Listener = $AsyncSshListeners |
                Where-Object Algorithm -eq 'x509v3-rsa2048-sha256' |
                Select-Object -First 1
            $UntrustedArgs = @(
                '-batch', '-ssh', '-P', $Sha256Listener.Port.ToString(),
                '-l', $UserName
            ) + ($AsyncSshHostKeys | ForEach-Object { @('-hostkey', $_) }) + @(
                '-i', $UntrustedCase.CertId, $HostName, 'whoami'
            )
            $UntrustedResult = Invoke-Native -FilePath $script:Paths.Plink `
                -ArgumentList $UntrustedArgs -IgnoreExitCode
            if ($UntrustedResult.ExitCode -eq 0) {
                throw 'AsyncSSH unexpectedly accepted a certificate outside its configured trust hierarchy.'
            }

            $FailureText = "$($UntrustedResult.StdOut)`n$($UntrustedResult.StdErr)"
            if ($FailureText -notmatch '(?i)(authenticat|refused our key|public[ -]?key)') {
                throw "The AsyncSSH negative control failed for a reason unrelated to authentication: $FailureText"
            }
            Add-Result -Name 'ASYNCSSH-X509-UNTRUSTED-REJECTED' -Status 'Pass' -Detail `
                'AsyncSSH rejected a subject-authorized RSA certificate outside the configured CA hierarchy.'
        }

        $Logs = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'logs', $AsyncSshContainerName
        ) -IgnoreExitCode
        $LogText = "$($Logs.StdOut)`n$($Logs.StdErr)"
        foreach ($Case in $AsyncSshCases) {
            $Pattern = "Verifying request with $([regex]::Escape($Case.Algorithm)) key"
            if ($LogText -notmatch $Pattern) {
                throw "AsyncSSH did not log a verified request using $($Case.Algorithm)."
            }
        }

        Add-Result -Name 'ASYNCSSH-X509-RFC6187' -Status 'Pass' -Detail `
            'Independent AsyncSSH validation accepted both RSA algorithms and ECDSA P-256/P-384/P-521 leaf/intermediate chains, with command, SCP, and SFTP sessions authenticated to the configured root.'
    }
    catch {
        $Logs = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'logs', $AsyncSshContainerName
        ) -IgnoreExitCode
        throw "AsyncSSH X.509 interoperability testing failed: $($_.Exception.Message)`n$($Logs.StdOut)`n$($Logs.StdErr)"
    }
    finally {
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'rm', '-f', $AsyncSshContainerName
        ) -IgnoreExitCode | Out-Null
        Remove-Item -LiteralPath $HostKeyDirectory -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $RootPemPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $AuthorizedKeysPath -Force -ErrorAction SilentlyContinue
    }
}

# Set accepted algorithms on the PKIX-SSH server
function Set-AcceptedAlgorithms {
    param(
        [string]$AuthorizedKey,
        [string]$CustomAlgorithm
    )

    $Alg = $null
    if ($CustomAlgorithm) {
        $Alg = $CustomAlgorithm
    }
    elseif ($AuthorizedKey) {
        $KeyType = ($AuthorizedKey -split '\s+')[0]
        switch ($KeyType) {
            'ssh-rsa' { $Alg = 'rsa-sha2-512,rsa-sha2-256,ssh-rsa' }
            'ecdsa-sha2-nistp256' { $Alg = 'ecdsa-sha2-nistp256' }
            'ecdsa-sha2-nistp384' { $Alg = 'ecdsa-sha2-nistp384' }
            'ecdsa-sha2-nistp521' { $Alg = 'ecdsa-sha2-nistp521' }
            'ssh-ed25519' { $Alg = 'ssh-ed25519' }
            default {
                throw "Unknown key type: $KeyType"
            }
        }
    }
    else {
        throw "Must provide either -AuthorizedKey or -CustomAlgorithm"
    }

    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($DockerCmd) {
        $Cmd = "sed -i '/^AcceptedAlgorithms/d;/^PubkeyAcceptedAlgorithms/d' /etc/pkixssh/sshd_config && printf '%s\n' 'AcceptedAlgorithms $Alg' 'PubkeyAcceptedAlgorithms $Alg' >> /etc/pkixssh/sshd_config"
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('exec', $PkixContainerName, 'sh', '-c', $Cmd) | Out-Null

        # Verify both the advertised and accepted policies before reloading.
        $ConfigTail = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $PkixContainerName, 'tail', '-n', '2', '/etc/pkixssh/sshd_config'
        )
        $ExpectedLines = "AcceptedAlgorithms $Alg`nPubkeyAcceptedAlgorithms $Alg"
        if (($ConfigTail.StdOut -replace "`r`n", "`n") -ne $ExpectedLines) {
            throw "Failed to configure PKIX-SSH advertised/accepted algorithms. Expected '$ExpectedLines', got '$($ConfigTail.StdOut)'."
        }

        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $PkixContainerName, '/opt/pkixssh/sbin/sshd', '-t',
            '-f', '/etc/pkixssh/sshd_config'
        ) | Out-Null
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('kill', '-s', 'HUP', $PkixContainerName) | Out-Null
        # Give sshd a tiny moment to complete the SIGHUP reload
        Start-Sleep -Milliseconds 100
    }
}

# Capture PKIX-SSH's debug log so X.509 negotiation results can report the
# public-key algorithm observed by the server, when that detail is available.
function Get-PkixServerLogs {
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $DockerCmd -or -not $PkixContainerName) { return '' }

    $Logs = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'logs', $PkixContainerName
    ) -IgnoreExitCode

    return (($Logs.StdOut, $Logs.StdErr) -join "`n").Trim()
}

# Return only log output appended after a snapshot. If Docker cannot provide a
# stable prefix (for example after log rotation), decline to infer an algorithm.
function Get-NewPkixServerLogs([string]$Before) {
    $After = Get-PkixServerLogs
    if (-not $Before) { return $After }
    if ($After.StartsWith($Before, [StringComparison]::Ordinal)) {
        return $After.Substring($Before.Length)
    }
    return ''
}

function Get-ObservedX509RsaAlgorithm([string]$LogText) {
    if (-not $LogText) { return $null }

    $AlgorithmMatches = [regex]::Matches(
        $LogText,
        '(?<![A-Za-z0-9@._-])(x509v3-(?:rsa2048-sha256|ssh-rsa))(?![A-Za-z0-9@._-])'
    )
    if ($AlgorithmMatches.Count -eq 0) { return $null }

    return $AlgorithmMatches[$AlgorithmMatches.Count - 1].Groups[1].Value
}

function Read-SshUint32([byte[]]$Data, [ref]$Offset) {
    $Index = $Offset.Value
    if ($Index -lt 0 -or $Index -gt $Data.Length - 4) { throw 'Truncated SSH uint32.' }
    $Value = ([uint32]$Data[$Index] -shl 24) -bor
        ([uint32]$Data[$Index + 1] -shl 16) -bor
        ([uint32]$Data[$Index + 2] -shl 8) -bor
        [uint32]$Data[$Index + 3]
    $Offset.Value += 4
    return $Value
}

function Read-SshString([byte[]]$Data, [ref]$Offset) {
    $Length = Read-SshUint32 -Data $Data -Offset $Offset
    $Remaining = $Data.Length - $Offset.Value
    if ($Remaining -lt 0 -or $Length -gt [uint32]$Remaining) { throw 'Truncated SSH string.' }
    $IntLength = [int]$Length
    $Value = [byte[]]::new($IntLength)
    [Array]::Copy($Data, $Offset.Value, $Value, 0, $IntLength)
    $Offset.Value += $IntLength
    return ,$Value
}

function Read-StreamExact([IO.Stream]$Stream, [int]$Length) {
    if ($Length -lt 0) { throw 'Invalid negative stream read length.' }

    $Buffer = [byte[]]::new($Length)
    $Offset = 0
    while ($Offset -lt $Length) {
        $BytesRead = $Stream.Read($Buffer, $Offset, $Length - $Offset)
        if ($BytesRead -le 0) { throw 'SSH agent closed the pipe before completing its response.' }
        $Offset += $BytesRead
    }

    return ,$Buffer
}

# Query the SSH agent protocol directly. OpenSSH's ssh-add cannot decode an
# identity whose public-key algorithm is unknown to that OpenSSH build, but the
# wire response still contains the complete RFC 6187 public-key blob.
function Get-PageantRawKeys([string]$Agent) {
    $NormalizedAgent = $Agent.Trim().Replace('/', '\')
    $PipePrefix = '\\.\pipe\'
    if (-not $NormalizedAgent.StartsWith($PipePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsupported Pageant IdentityAgent path '$Agent'."
    }

    $PipeName = $NormalizedAgent.Substring($PipePrefix.Length)
    if ([string]::IsNullOrWhiteSpace($PipeName)) { throw 'Pageant IdentityAgent has an empty pipe name.' }

    $Pipe = [IO.Pipes.NamedPipeClientStream]::new(
        '.', $PipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None)
    try {
        $Pipe.Connect(5000)

        # uint32 packet length (1), followed by SSH2_AGENTC_REQUEST_IDENTITIES (11).
        $Request = [byte[]](0, 0, 0, 1, 11)
        $Pipe.Write($Request, 0, $Request.Length)
        $Pipe.Flush()

        [byte[]]$Header = Read-StreamExact -Stream $Pipe -Length 4
        $HeaderOffset = 0
        $FrameLength = Read-SshUint32 -Data $Header -Offset ([ref]$HeaderOffset)
        $MaximumFrameLength = 16MB
        if ($FrameLength -lt 1 -or $FrameLength -gt $MaximumFrameLength) {
            throw "SSH agent returned invalid frame length $FrameLength."
        }

        [byte[]]$Payload = Read-StreamExact -Stream $Pipe -Length ([int]$FrameLength)
        $Offset = 0
        $MessageType = $Payload[$Offset++]
        if ($MessageType -ne 12) {
            throw "SSH agent returned message type $MessageType instead of SSH2_AGENT_IDENTITIES_ANSWER (12)."
        }

        $IdentityCount = Read-SshUint32 -Data $Payload -Offset ([ref]$Offset)
        $Remaining = $Payload.Length - $Offset
        if ($Remaining -lt 0 -or $IdentityCount -gt [uint32][Math]::Floor($Remaining / 8)) {
            throw "SSH agent identity count $IdentityCount cannot fit in its response frame."
        }

        $Utf8 = [Text.UTF8Encoding]::new($false, $true)
        $Identities = [Collections.Generic.List[object]]::new()
        for ($Index = [uint32]0; $Index -lt $IdentityCount; $Index++) {
            [byte[]]$Blob = Read-SshString -Data $Payload -Offset ([ref]$Offset)
            if ($Blob.Length -eq 0) { throw "SSH agent identity $Index has an empty public-key blob." }
            [byte[]]$CommentBytes = Read-SshString -Data $Payload -Offset ([ref]$Offset)
            $Identities.Add([PSCustomObject]@{
                Blob    = $Blob
                Comment = $Utf8.GetString($CommentBytes)
            }) | Out-Null
        }

        if ($Offset -ne $Payload.Length) { throw 'SSH agent identities response contains trailing data.' }
        return $Identities.ToArray()
    }
    finally {
        $Pipe.Dispose()
    }
}

function Test-X509ChainEncoding([object]$ChainCase) {
    if (-not $ChainCase) {
        Add-Result -Name 'RFC6187-CHAIN' -Status 'Skip' -Detail 'Chain certificate creation was unavailable.'
        return
    }

    $Bridge = Start-Pageant -Arguments @(
        '-trustedcertsonlyoff', '-smartcardlogoncertsonlyoff', $ChainCase.CertId)
    try {
        $Identity = $null
        $Deadline = (Get-Date).AddSeconds(10)
        do {
            $Identity = Get-PageantRawKeys -Agent $Bridge.Agent |
                Where-Object { $_.Comment.Equals($ChainCase.CertId, [StringComparison]::Ordinal) } |
                Select-Object -First 1
            if (-not $Identity) { Start-Sleep -Milliseconds 200 }
        }
        while (-not $Identity -and (Get-Date) -lt $Deadline)
        if (-not $Identity) { throw 'Pageant did not expose the X.509 RSA chain key.' }

        [byte[]]$Blob = $Identity.Blob
        $Offset = 0
        $Algorithm = [Encoding]::ASCII.GetString(
            (Read-SshString -Data $Blob -Offset ([ref]$Offset)))
        if ($Algorithm -ne 'x509v3-ssh-rsa') { throw "Unexpected inner algorithm '$Algorithm'." }

        $CertificateCount = Read-SshUint32 -Data $Blob -Offset ([ref]$Offset)
        if ($CertificateCount -ne 2) {
            throw "Expected leaf and intermediate only, got $CertificateCount certificates."
        }

        $WireLeaf = Read-SshString -Data $Blob -Offset ([ref]$Offset)
        $WireIntermediate = Read-SshString -Data $Blob -Offset ([ref]$Offset)
        if ([Convert]::ToBase64String($WireLeaf) -ne
            [Convert]::ToBase64String($ChainCase.Leaf.RawData)) {
            throw 'The first certificate was not the selected leaf.'
        }
        if ([Convert]::ToBase64String($WireIntermediate) -ne
            [Convert]::ToBase64String($ChainCase.Intermediate.RawData)) {
            throw 'The second certificate was not the issuing intermediate.'
        }

        $OcspCount = Read-SshUint32 -Data $Blob -Offset ([ref]$Offset)
        if ($OcspCount -ne 0 -or $Offset -ne $Blob.Length) {
            throw 'Unexpected OCSP responses or trailing RFC 6187 data.'
        }

        Add-Result -Name 'RFC6187-CHAIN' -Status 'Pass' -Detail `
            'Verified leaf-to-intermediate order, self-signed-root omission, and exact blob framing.'
    }
    finally {
        if ($Bridge.Process -and -not $Bridge.Process.HasExited) {
            Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-X509ChainAuthentication([object]$ChainCase, [string[]]$HostKeys) {
    if (-not $ChainCase) {
        Add-Result -Name 'RFC6187-CHAIN-AUTH' -Status 'Skip' -Detail `
            'Chain certificate creation was unavailable.'
        return
    }

    # An exclusive server policy makes a successful connection direct evidence
    # that the SHA-256 X.509 algorithm was used. The authorized_keys entry has
    # only the leaf, and the server trust store has only the root, so validation
    # also requires the intermediate sent in PuTTY's RFC 6187 public-key blob.
    $ObservedAlgorithm = $null
    try {
        Set-PkixSelfIssuedPolicy -Allow $false
        Set-AcceptedAlgorithms -CustomAlgorithm 'x509v3-rsa2048-sha256'
        Start-Sleep -Milliseconds 300
        $LogSnapshot = Get-PkixServerLogs
        Invoke-PlinkTest -Name 'X509v3-Intermediate-Chain' `
            -CertId $ChainCase.CertId -HostKeys $HostKeys

        $ObservedAlgorithm = Get-ObservedX509RsaAlgorithm -LogText (
            Get-NewPkixServerLogs -Before $LogSnapshot)
        if ($ObservedAlgorithm -and $ObservedAlgorithm -ne 'x509v3-rsa2048-sha256') {
            throw "Server log recorded '$ObservedAlgorithm' while configured exclusively for x509v3-rsa2048-sha256."
        }
    }
    finally {
        # The rest of the interoperability matrix intentionally exercises
        # self-signed leaves, so restore the server's original test policy.
        Set-PkixSelfIssuedPolicy -Allow $true
    }

    $Observation = if ($ObservedAlgorithm) {
        ' The server debug log recorded x509v3-rsa2048-sha256.'
    }
    else { '' }
    Add-Result -Name 'RFC6187-CHAIN-AUTH' -Status 'Pass' -Detail `
        "Authenticated with a leaf/intermediate/root hierarchy while the server held only the leaf authorization and root trust anchor.$Observation"
}

# Test that -allowanycert permits authentication with an untrusted certificate
function Test-AllowAnyCert([object]$UntrustedCase, [string[]]$HostKeys) {
    if (-not $UntrustedCase) {
        Add-Result -Name 'ALLOWANYCERT' -Status 'Skip' -Detail 'No untrusted negative certificate available for -allowanycert test.'
        return
    }

    $UntrustedKey = Get-OpenSshKeyLine -Certificate $UntrustedCase.Cert
    $CleanupTag = 'PuTTYCAC-TEST-ALLOWANYCERT'
    $Marker = "# $CleanupTag"
    $TaggedUntrustedKey = "$UntrustedKey $CleanupTag"
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue

    if ($DockerCmd) {
        # Temporarily inject the untrusted public key into the container's authorized_keys file
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $PkixContainerName, 'sh', '-c', "echo '$Marker' >> /authorized_keys && echo '$TaggedUntrustedKey' >> /authorized_keys"
        ) | Out-Null
    }

    try {
        $ArgList = @('-batch', '-ssh', '-P', $Port.ToString(), '-l', $UserName) +
        ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
        @('-allowanycert', '-i', $UntrustedCase.CertId, $HostName, 'whoami')

        $Result = Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $ArgList

        if ($Result.StdOut -notmatch [regex]::Escape($UserName)) { throw "Unexpected plink output: $($Result.StdOut)" }

        Add-Result -Name 'ALLOWANYCERT' -Status 'Pass' -Detail 'plink authenticated with untrusted certificate using -allowanycert.'
    }
    finally {
        # Both temporary lines carry the same tag, so cleanup removes the marker
        # and the injected key independently without relying on line adjacency.
        if ($DockerCmd) {
            Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
                'exec', $PkixContainerName, 'sh', '-c', "sed -i '/$CleanupTag/d' /authorized_keys"
            ) -IgnoreExitCode | Out-Null
        }

        # plink persisted AllowAnyCert=1 to the registry; clear it now so Test-PageantFilters
        # is not affected (AllowAnyCert bypasses EKU filtering, which would cause NEG-SERVERAUTH
        # to appear in the autoloaded key list)
        Remove-ItemProperty -LiteralPath 'HKCU:\Software\SimonTatham\PuTTY' -Name 'AllowAnyCert' -Force -ErrorAction SilentlyContinue
    }
}

# Intentionally mismatch server auth algorithms and verify authentication failure is detected
function Test-PkixAuthMismatch([object]$Case, [string[]]$HostKeys, [string]$RestoreAlgorithm) {
    if (-not $Case) {
        Add-Result -Name 'PKIX-AUTH-MISMATCH' -Status 'Skip' -Detail 'No positive test certificate available for PKIX auth mismatch verification.'
        return
    }

    $MismatchAlgorithm = 'ssh-ed25519'
    if ($Case.KeyType -eq 'ED25519') {
        $MismatchAlgorithm = 'rsa-sha2-512,rsa-sha2-256,ssh-rsa'
    }

    Set-AcceptedAlgorithms -CustomAlgorithm $MismatchAlgorithm
    Start-Sleep -Milliseconds 300

    try {
        $ArgList = @('-batch', '-ssh', '-P', $Port.ToString(), '-l', $UserName) +
        ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
        @('-i', $Case.CertId, $HostName, 'whoami')

        $Result = Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $ArgList -IgnoreExitCode
        $Succeeded = $Result.ExitCode -eq 0 -and $Result.StdOut -match [regex]::Escape($UserName)

        if ($Succeeded) {
            Add-Result -Name 'PKIX-AUTH-MISMATCH' -Status 'Fail' -Detail "Expected auth failure with intentionally mismatched PubkeyAcceptedAlgorithms ($MismatchAlgorithm), but authentication succeeded."
        }
        else {
            Add-Result -Name 'PKIX-AUTH-MISMATCH' -Status 'Pass' -Detail "Intentionally mismatched PubkeyAcceptedAlgorithms ($MismatchAlgorithm); authentication failed as expected."
        }
    }
    finally {
        Set-AcceptedAlgorithms -CustomAlgorithm $RestoreAlgorithm
        Start-Sleep -Milliseconds 300
    }
}

# Verify SHA-384 and SHA-512 SSH algorithm variants across supported key types
function Test-ShaVariantAlgorithms([object[]]$Cases, [string[]]$HostKeys, [string]$RestoreAlgorithm) {
    $VariantTests = [List[object]]::new()

    $RsaCase = $Cases | Where-Object KeyType -eq 'RSA' | Sort-Object Bits -Descending | Select-Object -First 1
    if ($RsaCase) {
        $VariantTests.Add([PSCustomObject]@{
                Name      = 'RSA-SHA512'
                Algorithm = 'rsa-sha2-512'
                Case      = $RsaCase
                HashName  = 'SHA512'
            }) | Out-Null
    }

    $Ecdsa384Case = $Cases | Where-Object { $_.KeyType -eq 'ECDSA' -and $_.Bits -eq 384 } | Select-Object -First 1
    if ($Ecdsa384Case) {
        $VariantTests.Add([PSCustomObject]@{
                Name      = 'ECDSA-NISTP384'
                Algorithm = 'ecdsa-sha2-nistp384'
                Case      = $Ecdsa384Case
                HashName  = 'SHA384'
            }) | Out-Null
    }

    $Ecdsa521Case = $Cases | Where-Object { $_.KeyType -eq 'ECDSA' -and $_.Bits -eq 521 } | Select-Object -First 1
    if ($Ecdsa521Case) {
        $VariantTests.Add([PSCustomObject]@{
                Name      = 'ECDSA-NISTP521'
                Algorithm = 'ecdsa-sha2-nistp521'
                Case      = $Ecdsa521Case
                HashName  = 'SHA512'
            }) | Out-Null
    }

    if ($VariantTests.Count -eq 0) {
        Add-Result -Name 'PKIX-SHA-VARIANTS' -Status 'Skip' -Detail 'No compatible RSA/ECDSA test certificates were available for SHA-384/SHA-512 algorithm variant checks.'
        return
    }

    foreach ($Variant in $VariantTests) {
        Set-AcceptedAlgorithms -CustomAlgorithm $Variant.Algorithm
        Start-Sleep -Milliseconds 300

        try {
            Invoke-PlinkTest -Name "NEGOTIATION-$($Variant.Name)-$($Variant.Case.Name)" -CertId $Variant.Case.CertId -HostKeys $HostKeys
            Add-Result -Name "PKIX-$($Variant.Name)-$($Variant.Case.Name)" -Status 'Pass' -Detail "Successfully authenticated using $($Variant.Algorithm) ($($Variant.HashName) variant)."
        }
        finally {
            Set-AcceptedAlgorithms -CustomAlgorithm $RestoreAlgorithm
            Start-Sleep -Milliseconds 300
        }
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

    return @($Result.StdOut -split "`r?`n" |
        Where-Object { $_ -match '^(ssh-|ecdsa-|x509v3-)' })
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
            throw "$([Path]::GetFileName($FilePath)) failed to set $RegistryName with $Flag."
        }
    }
    finally {
        if ($Process -and -not $Process.HasExited) { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue }
    }
}

# Test Pageant certificate autoload and filtering capabilities
function Test-PageantFilters([object[]]$Positive, [object[]]$Negative, [object]$SmartCardLogon) {
    if ($Positive.Count -eq 0) {
        foreach ($N in @('PAGEANT-AUTOLOAD', 'PAGEANT-IGNOREEXPIRED', 'PAGEANT-SHOWEXPIRED', 'PAGEANT-SCLOGONFILTER', 'PAGEANT-TRUSTFILTER', 'PAGEANT-SAVELIST')) {
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
        # NEG-SERVERAUTH (EKU) and NEG-EXPIRED (-ignoreexpiredcerts) are always
        # filtered here; NEG-UNTRUSTED only when the trusted-certs check is active.
        $ExpectedFiltered = if ($TrustTestRoots) {
            @($Negative)
        }
        else {
            @($Negative | Where-Object Name -ne 'NEG-UNTRUSTED')
        }

        foreach ($Case in $ExpectedFiltered) {
            if ($Keys -contains $Case.KeyId) { throw "Unexpected filtered key listed for $($Case.Name)." }
        }

        Add-Result -Name 'PAGEANT-AUTOLOAD' -Status 'Pass' -Detail (Get-PageantAutoloadMessage)

        # -ignoreexpiredcerts must exclude expired certs from the list (issue #166)
        if ($ExpiredCase) {
            if ($Keys -contains $ExpiredCase.KeyId) { throw 'Expected NEG-EXPIRED to be filtered out when -ignoreexpiredcerts is enabled.' }
            Add-Result -Name 'PAGEANT-IGNOREEXPIRED' -Status 'Pass' -Detail 'Verified -ignoreexpiredcerts filters expired certificates out of the autoload list.'
        }

        if (-not $TrustTestRoots) { Add-Result -Name 'PAGEANT-TRUSTFILTER' -Status 'Skip' -Detail 'Skipped TrustedCertsOnly autoload coverage because trusted root installation was not requested.' }
    }
    finally {
        if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
    }

    # OFF-state counterpart: with -ignoreexpiredcertsoff the expired cert must stay
    # listed. Mirror the trust filter so the chain path is checked too (issue #166).
    if ($ExpiredCase) {
        $ShowExpiredArgs = [List[string]]::new()
        $ShowExpiredArgs.Add('-autoload') | Out-Null
        $ShowExpiredArgs.Add('-ignoreexpiredcertsoff') | Out-Null
        if ($TrustTestRoots) { $ShowExpiredArgs.Add('-trustedcertsonly') | Out-Null }

        $Bridge = Start-Pageant -Arguments $ShowExpiredArgs

        try {
            $Keys = @(Get-PageantKeys -Agent $Bridge.Agent | ForEach-Object { Get-KeyId $_ })
            if ($Keys -notcontains $ExpiredCase.KeyId) { throw 'Expected NEG-EXPIRED to be listed when -ignoreexpiredcerts is disabled.' }
            Add-Result -Name 'PAGEANT-SHOWEXPIRED' -Status 'Pass' -Detail 'Verified expired certificates remain listed when the No Expired Certs filter is disabled.'
        }
        finally {
            if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
        }
    }

    # -smartcardlogoncertsonly must list only certs with the Smart Card Logon EKU:
    # the SC-logon cert stays, an ordinary client-auth cert is filtered out.
    if ($SmartCardLogon) {
        $Bridge = Start-Pageant -Arguments @('-autoload', '-smartcardlogoncertsonly')

        try {
            $Keys = @(Get-PageantKeys -Agent $Bridge.Agent | ForEach-Object { Get-KeyId $_ })
            if ($Keys -notcontains $SmartCardLogon.KeyId) { throw 'Expected POS-SCLOGON to be listed when -smartcardlogoncertsonly is enabled.' }

            $NonScCase = $Positive | Select-Object -First 1
            if ($NonScCase -and ($Keys -contains (Get-KeyId $NonScCase.AuthorizedKey))) {
                throw "Expected ordinary client-auth certificate $($NonScCase.Name) to be filtered when -smartcardlogoncertsonly is enabled."
            }

            Add-Result -Name 'PAGEANT-SCLOGONFILTER' -Status 'Pass' -Detail 'Verified -smartcardlogoncertsonly lists only smart card logon certificates.'
        }
        finally {
            if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    else {
        Add-Result -Name 'PAGEANT-SCLOGONFILTER' -Status 'Skip' -Detail 'No smart card logon certificate available for SmartCardLogonCertsOnly test.'
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

        Add-Result -Name "REGISTRY-$([Path]::GetFileName($Exe))" -Status 'Pass' `
            -Detail 'All PuTTY-CAC registry-backed CLI SET and UNSET flags persisted to registry as expected.'
    }
}

# Test that passing a specific CAPI key on the command line is accepted by all executables
function Test-CapiArgumentPassing([string]$CertId) {
    if (-not $CertId) {
        Add-Result -Name 'CLI-CAPI-ARGS' -Status 'Skip' -Detail 'No CAPI certificate available for CLI argument testing.'
        return
    }

    # We want to test every PuTTY-CAC executable that we have resolved
    $Executables = @(
        [PSCustomObject]@{ Path = $script:Paths.Plink;   Args = @('-i', $CertId) }
        [PSCustomObject]@{ Path = $script:Paths.Pscp;    Args = @('-i', $CertId) }
        [PSCustomObject]@{ Path = $script:Paths.Psftp;   Args = @('-i', $CertId) }
        [PSCustomObject]@{ Path = $script:Paths.Pageant; Args = @($CertId) }
        [PSCustomObject]@{ Path = $script:Paths.Putty;   Args = @('-i', $CertId) }
        [PSCustomObject]@{ Path = $script:Paths.PuttyTel;Args = @('-i', $CertId) }
    ) | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path -PathType Leaf) }

    foreach ($Exe in $Executables) {
        $Name = [System.IO.Path]::GetFileName($Exe.Path)
        try {
            $ProcessInfo = [System.Diagnostics.ProcessStartInfo]::new()
            $ProcessInfo.FileName = $Exe.Path
            foreach ($Arg in $Exe.Args) {
                [void]$ProcessInfo.ArgumentList.Add($Arg)
            }
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.CreateNoWindow = $true

            $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
            $OutTask = $Process.StandardOutput.ReadToEndAsync()
            $ErrTask = $Process.StandardError.ReadToEndAsync()

            # Wait a short duration (1000ms). If it's a CLI tool, it might exit quickly.
            # If it's a GUI tool, it will run indefinitely.
            $Exited = $Process.WaitForExit(1000)

            if ($Exited) {
                $StdOut = $OutTask.GetAwaiter().GetResult().Trim()
                $StdErr = $ErrTask.GetAwaiter().GetResult().Trim()
                $Output = "$StdOut`n$StdErr"

                # Check for command line errors indicating argument parsing failed
                if ($Output -match 'unknown option|unrecognised|requires an argument') {
                    throw "Command line validation failed: $Output"
                }
            } else {
                # Process is still running, which means it accepted the arguments. Kill it.
                try {
                    $Process.Kill()
                    $Process.WaitForExit()
                } catch {}
            }

            Add-Result -Name "CLI-CAPI-ARG-${Name}" -Status 'Pass' -Detail "Successfully validated command line argument passing of specific CAPI key ($CertId) to ${Name}."
        }
        catch {
            Add-Result -Name "CLI-CAPI-ARG-${Name}" -Status 'Fail' -Detail "Failed to pass CAPI key argument to ${Name}: $($_.Exception.Message)"
        }
    }
}


# Delete all test certificates from certificate store
function Remove-TestCertificates {
    foreach ($Thumb in $script:State.CreatedThumbprints | Select-Object -Unique) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\$Thumb") -DeleteKey -Force -ErrorAction SilentlyContinue
        if ($script:State.TrustedThumbprints -contains $Thumb) {
            Remove-FromCurrentUserRootStore -Thumbprint $Thumb
        }
    }
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
$PkixContainerName = 'puttycac-pkixssh-test'
$PkixImageName = 'puttycac/pkixssh-test'
$PkixDockerfile = Join-Path $script:State.WorkspaceRoot 'tools\docker\pkixssh\Dockerfile'
$DropbearContainerName = 'puttycac-dropbear-test'
$DropbearImageName = 'puttycac/dropbear-test'
$DropbearDockerfile = Join-Path $script:State.WorkspaceRoot 'tools\docker\dropbear\Dockerfile'
$DropbearPort = 2223
$WolfSshContainerName = 'puttycac-wolfssh-test'
$WolfSshImageName = 'puttycac/wolfssh-test'
$WolfSshDockerfile = Join-Path $script:State.WorkspaceRoot 'tools\docker\wolfssh\Dockerfile'
$WolfSshPort = 2224
$AsyncSshContainerName = 'puttycac-asyncssh-test'
$AsyncSshImageName = 'puttycac/asyncssh-test'
$AsyncSshDockerfile = Join-Path $script:State.WorkspaceRoot 'tools\docker\asyncssh\Dockerfile'
$AsyncSshListeners = @(
    [PSCustomObject]@{
        Name = 'RSA-SHA256-CHAIN'; Algorithm = 'x509v3-rsa2048-sha256'; Port = 2225; Bits = 0
    }
    [PSCustomObject]@{
        Name = 'RSA-SHA1-CHAIN'; Algorithm = 'x509v3-ssh-rsa'; Port = 2226; Bits = 0
    }
    [PSCustomObject]@{
        Name = 'ECDSA-P256-CHAIN'; Algorithm = 'x509v3-ecdsa-sha2-nistp256'; Port = 2227; Bits = 256
    }
    [PSCustomObject]@{
        Name = 'ECDSA-P384-CHAIN'; Algorithm = 'x509v3-ecdsa-sha2-nistp384'; Port = 2228; Bits = 384
    }
    [PSCustomObject]@{
        Name = 'ECDSA-P521-CHAIN'; Algorithm = 'x509v3-ecdsa-sha2-nistp521'; Port = 2229; Bits = 521
    }
)
$PkixAuthKeysPath = $null
$script:Paths.Run = $WorkingRoot
$script:Paths.PkixHostKeys = $null
$script:Paths.PkixChainRoot = $null

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

    # Baseline tests exercise raw SSH algorithms regardless of the user's
    # pre-existing global X.509 setting. Cleanup restores the original value.
    $BaselineRegPath = 'HKCU:\Software\SimonTatham\PuTTY'
    if (-not (Test-Path -LiteralPath $BaselineRegPath)) {
        New-Item -Path $BaselineRegPath -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $BaselineRegPath -Name 'AuthX509' `
        -PropertyType DWord -Value 0 -Force | Out-Null

    $Matrix = New-TestMatrix

    # Test CAPI argument passing on all resolved executables
    $FirstCert = $Matrix.Positive | Select-Object -First 1
    if ($FirstCert) {
        Test-CapiArgumentPassing -CertId $FirstCert.CertId
    }

    # Build PKCS#11 test matrix if a PKCS#11 library was supplied
    $Pkcs11Matrix = [List[object]]::new()
    if ($Pkcs11Library) {
        if (-not (Test-Path -LiteralPath $Pkcs11Library -PathType Leaf)) {
            Add-Result -Name 'PKCS11-SETUP' -Status 'Fail' -Detail "PKCS#11 library not found: $Pkcs11Library"
        }
        else {
            foreach ($Entry in (New-Pkcs11TestMatrix)) { $Pkcs11Matrix.Add($Entry) | Out-Null }
            if ($Pkcs11Matrix.Count -gt 0) {
                Add-Result -Name 'PKCS11-SETUP' -Status 'Pass' -Detail "Loaded $($Pkcs11Matrix.Count) PKCS#11 test certificate(s) from $Pkcs11Library."
            }
        }
    }

    # 1. Start the PKIX-SSH Docker container
    # Check Docker availability
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $DockerCmd) { throw 'Docker is not installed or not in PATH.' }

    $DockerInfo = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('info', '--format', '{{.OSType}}') -IgnoreExitCode
    if ($DockerInfo.ExitCode -ne 0) { throw "Docker daemon is not running: $($DockerInfo.StdErr)" }

    if (-not (Test-Path -LiteralPath $PkixDockerfile -PathType Leaf)) {
        throw "PKIX-SSH Dockerfile not found at $PkixDockerfile"
    }

    # Build PKIX-SSH Docker image (cached after first build)
    Write-Host 'Building PKIX-SSH Docker image (cached after first build)...'
    $BuildCtx = Split-Path -Parent $PkixDockerfile
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'build', '-t', $PkixImageName, $BuildCtx
    ) | Out-Null

    # Prepare combined authorized_keys for the container
    $PkixAuthKeysPath = Join-Path $script:Paths.Run 'authorized_keys'
    $AuthKeysLines = [List[string]]::new()
    foreach ($Case in $Matrix.Positive) {
        $AuthKeysLines.Add((Get-OpenSshKeyLine -Certificate $Case.Cert))
        if ($Case.KeyType -eq 'RSA') {
            $AuthKeysLines.Add((Get-X509v3SshRsaKeyLine -Certificate $Case.Cert))
            $AuthKeysLines.Add((Get-X509v3Rsa2048Sha256KeyLine -Certificate $Case.Cert))
        }
        if ($Case.KeyType -eq 'ECDSA') {
            if ($Case.Bits -eq 256) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp256KeyLine -Certificate $Case.Cert)) }
            elseif ($Case.Bits -eq 384) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp384KeyLine -Certificate $Case.Cert)) }
            elseif ($Case.Bits -eq 521) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp521KeyLine -Certificate $Case.Cert)) }
        }
    }
    foreach ($Case in $Pkcs11Matrix) {
        $AuthKeysLines.Add($Case.AuthorizedKey)
        if ($Case.KeyType -eq 'RSA') {
            $AuthKeysLines.Add((Get-X509v3SshRsaKeyLine -Certificate $Case.Cert))
            $AuthKeysLines.Add((Get-X509v3Rsa2048Sha256KeyLine -Certificate $Case.Cert))
        }
        if ($Case.KeyType -eq 'ECDSA') {
            if ($Case.Bits -eq 256) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp256KeyLine -Certificate $Case.Cert)) }
            elseif ($Case.Bits -eq 384) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp384KeyLine -Certificate $Case.Cert)) }
            elseif ($Case.Bits -eq 521) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp521KeyLine -Certificate $Case.Cert)) }
        }
    }
    if ($Matrix.ChainCase) {
        # These authorization blobs intentionally contain only the leaf. The
        # issuing intermediate must arrive from the client during authentication.
        $AuthKeysLines.Add((Get-X509v3SshRsaKeyLine -Certificate $Matrix.ChainCase.Leaf))
        $AuthKeysLines.Add((Get-X509v3Rsa2048Sha256KeyLine -Certificate $Matrix.ChainCase.Leaf))
    }
    Set-Content -LiteralPath $PkixAuthKeysPath -Value $AuthKeysLines -Encoding ascii

    # Remove any leftover container from a previous run
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'rm', '-f', $PkixContainerName
    ) -IgnoreExitCode | Out-Null

    # Start the container in detached mode (using the container filesystem only, with no bind mounts)
    Write-Host "Starting PKIX-SSH Docker container on port $Port..."
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'run', '-d',
        '--name', $PkixContainerName,
        '-p', "$($Port):$Port",
        $PkixImageName
    ) | Out-Null

    # Copy the generated authorized_keys file directly into the container's isolated filesystem
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'cp', $PkixAuthKeysPath, "${PkixContainerName}:/authorized_keys"
    ) | Out-Null

    # Wait for sshd to start listening
    $Listening = $false
    $Timeout = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $Timeout) {
        if (Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue) {
            $Listening = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $Listening) {
        $Logs = (Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('logs', $PkixContainerName) -IgnoreExitCode).StdOut
        throw "PKIX-SSH container sshd failed to listen on port $Port.`nLogs:`n$Logs"
    }

    # Extract host key fingerprints from the container
    $SshKeyGen = Get-CommandPath (Join-Path $script:Paths.OpenSSH 'ssh-keygen.exe')
    $script:Paths.PkixHostKeys = Join-Path $script:Paths.Run 'pkix_hostkeys'
    New-Directory $script:Paths.PkixHostKeys | Out-Null
    foreach ($KeyType in @('rsa', 'ecdsa', 'ed25519')) {
        $PubKeyContent = (Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $PkixContainerName, 'cat', "/etc/pkixssh/ssh_host_${KeyType}_key.pub"
        )).StdOut
        $PubKeyFile = Join-Path $script:Paths.PkixHostKeys "ssh_host_${KeyType}_key.pub"
        Set-Content -LiteralPath $PubKeyFile -Value $PubKeyContent -Encoding ascii
    }

    $PubKeys = Get-ChildItem -LiteralPath $script:Paths.PkixHostKeys -Filter 'ssh_host_*_key.pub' -File
    $HostKeys = @($(foreach ($Key in $PubKeys) {
        $Output = Invoke-Native -FilePath $SshKeyGen -ArgumentList @('-lf', $Key.FullName)
        if ($Output.StdOut -match '^\S+\s+(\S+)\s+') { $Matches[1] }
    }) | Where-Object { $_ } | Select-Object -Unique)

    Add-Result -Name 'PKIX-SSH-SETUP' -Status 'Pass' -Detail 'Successfully compiled and started Dockerized PKIX-SSH server for all testings.'

    Install-PkixChainTrust -ChainCase $Matrix.ChainCase

    # Configure the server globally once to accept all required key types to avoid rapid SIGHUP restarts
    $AllAcceptedAlgorithms = 'rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519'
    Set-AcceptedAlgorithms -CustomAlgorithm $AllAcceptedAlgorithms
    Start-Sleep -Milliseconds 300

    # Explicitly validate SHA-384/SHA-512 algorithm variants for supported key types
    $VariantCases = @($Matrix.Positive) + @($Pkcs11Matrix)
    Test-ShaVariantAlgorithms -Cases $VariantCases -HostKeys $HostKeys -RestoreAlgorithm $AllAcceptedAlgorithms

    # Intentionally mismatch auth once to verify the test harness catches expected auth failures
    $MismatchCase = $Matrix.Positive | Where-Object KeyType -eq 'RSA' | Select-Object -First 1
    if (-not $MismatchCase) { $MismatchCase = $Matrix.Positive | Select-Object -First 1 }
    Test-PkixAuthMismatch -Case $MismatchCase -HostKeys $HostKeys -RestoreAlgorithm $AllAcceptedAlgorithms

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
    if ($AgentTestCase) {
        Invoke-PageantAgentTest -Name $AgentTestCase.Name -CertId $AgentTestCase.CertId -HostKeys $HostKeys
    }

    # Exercise the same raw public keys against Dropbear. Unlike PKIX-SSH,
    # Dropbear is not derived from OpenSSH, so this catches assumptions that
    # happen to work only within the OpenSSH protocol implementation family.
    $DropbearCases = @($Matrix.Positive) + @($Pkcs11Matrix)
    $DropbearUnauthorizedCase = $Matrix.Negative |
        Where-Object Name -eq 'NEG-UNTRUSTED' |
        Select-Object -First 1
    Test-DropbearInteroperability -Cases $DropbearCases `
        -AgentTestCase $AgentTestCase -UnauthorizedCase $DropbearUnauthorizedCase

    # Test -allowanycert functional behavior with an untrusted certificate
    $UntrustedNeg = $Matrix.Negative | Where-Object Name -eq 'NEG-UNTRUSTED' | Select-Object -First 1
    Test-AllowAnyCert -UntrustedCase $UntrustedNeg -HostKeys $HostKeys

    # Test X.509v3 certificate authentication (negotiation)
    if ($AgentTestCase) {
        # AuthX509 is now a global setting (shared by PuTTY and Pageant) read from
        # the base PuTTY registry key rather than a per-session option.
        $X509RegPath = 'HKCU:\Software\SimonTatham\PuTTY'
        try {
            if (-not (Test-Path -LiteralPath $X509RegPath)) {
                New-Item -Path $X509RegPath -Force | Out-Null
            }
            # Enable AuthX509 globally
            New-ItemProperty -LiteralPath $X509RegPath -Name 'AuthX509' -PropertyType DWord -Value 1 -Force | Out-Null

            Test-X509ChainEncoding -ChainCase $Matrix.ChainCase
            Test-X509ChainAuthentication -ChainCase $Matrix.ChainCase -HostKeys $HostKeys
            $X509UntrustedCase = $Matrix.Negative |
                Where-Object Name -eq 'NEG-UNTRUSTED' |
                Select-Object -First 1
            Test-WolfSshX509Interoperability -ChainCase $Matrix.ChainCase `
                -UntrustedCase $X509UntrustedCase
            Test-AsyncSshX509Interoperability -ChainCase $Matrix.ChainCase `
                -UntrustedCase $X509UntrustedCase

            # PKIX-SSH 18.x does not recognize id-kp-secureShellClient as a
            # client-auth EKU. Keep that certificate in the raw-key and Pageant
            # coverage above, but do not use it for PKIX X.509 interoperability.
            $X509RsaCases = @($Matrix.Positive | Where-Object {
                $_.KeyType -eq 'RSA' -and $_.Name -ne 'RSA-2048-SSH-EKU'
            })

            # 1. Verify compatibility when both RSA X.509 algorithms are enabled.
            # Do not infer which algorithm won from key size alone; report the
            # server's debug-log observation when it is available.
            Set-AcceptedAlgorithms -CustomAlgorithm 'x509v3-rsa2048-sha256,x509v3-ssh-rsa'
            Start-Sleep -Milliseconds 300

            foreach ($RsaCase in $X509RsaCases) {
                $LogSnapshot = Get-PkixServerLogs
                Invoke-PlinkTest -Name "X509v3-Negotiation-Dual-$($RsaCase.Name)" -CertId $RsaCase.CertId -HostKeys $HostKeys
                $ObservedAlgorithm = Get-ObservedX509RsaAlgorithm -LogText (Get-NewPkixServerLogs -Before $LogSnapshot)

                $Detail = if ($ObservedAlgorithm) {
                    "Authenticated with $($RsaCase.Bits)-bit key while both RSA X.509 algorithms were enabled; the server log recorded $ObservedAlgorithm."
                }
                else {
                    "Authenticated with $($RsaCase.Bits)-bit key while both RSA X.509 algorithms were enabled. Algorithm selection is verified by the exclusive-policy cases below, not inferred here."
                }
                Add-Result -Name "PKIX-X509V3-DUAL-$($RsaCase.Name)" -Status 'Pass' -Detail $Detail
            }

            # 2. Test with ONLY x509v3-rsa2048-sha256 enabled. A successful
            # connection is therefore direct evidence of SHA-256 negotiation.
            Set-AcceptedAlgorithms -CustomAlgorithm 'x509v3-rsa2048-sha256'
            Start-Sleep -Milliseconds 300

            foreach ($RsaCase in $X509RsaCases) {
                if ($RsaCase.Bits -ge 2048) {
                    $LogSnapshot = Get-PkixServerLogs
                    Invoke-PlinkTest -Name "X509v3-Negotiation-SHA256-Only-Succeed-$($RsaCase.Name)" -CertId $RsaCase.CertId -HostKeys $HostKeys
                    $ObservedAlgorithm = Get-ObservedX509RsaAlgorithm -LogText (Get-NewPkixServerLogs -Before $LogSnapshot)
                    if ($ObservedAlgorithm -and $ObservedAlgorithm -ne 'x509v3-rsa2048-sha256') {
                        throw "Server log recorded '$ObservedAlgorithm' while configured exclusively for x509v3-rsa2048-sha256."
                    }

                    $Observation = if ($ObservedAlgorithm) { ' The server debug log recorded the same algorithm.' } else { '' }
                    Add-Result -Name "PKIX-X509V3-SHA256-Only-Succeed-$($RsaCase.Name)" -Status 'Pass' -Detail "Authenticated with $($RsaCase.Bits)-bit key while the verified server policy accepted only x509v3-rsa2048-sha256.$Observation"
                } else {
                    # A short key must be rejected. Keep the assertion outside any
                    # catch block so an unexpected success cannot satisfy the test.
                    $ArgList = @('-batch', '-ssh', '-P', $Port.ToString(), '-l', $UserName) +
                    ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
                    @('-i', $RsaCase.CertId, $HostName, 'whoami')
                    $Result = Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $ArgList -IgnoreExitCode

                    if ($Result.ExitCode -eq 0) {
                        throw "Expected $($RsaCase.Bits)-bit key to fail x509v3-rsa2048-sha256-only authentication, but plink exited successfully."
                    }

                    $FailureText = "$($Result.StdOut)`n$($Result.StdErr)"
                    if ($FailureText -notmatch '(?i)(authenticat|public[ -]?key|publickey)') {
                        throw "Short-RSA test failed for a reason unrelated to authentication: $FailureText"
                    }

                    Add-Result -Name "X509v3-Negotiation-SHA256-Only-Rejected-$($RsaCase.Name)" -Status 'Pass' -Detail "Server configured exclusively for x509v3-rsa2048-sha256 rejected the too-short $($RsaCase.Bits)-bit RSA key."
                }
            }

            # 3. Advertise generic RSA SHA-256 but only the legacy X.509 RSA
            # variant. This directly guards against treating rsa-sha2-256 as
            # permission to use x509v3-rsa2048-sha256.
            Set-AcceptedAlgorithms -CustomAlgorithm 'rsa-sha2-256,x509v3-ssh-rsa'
            Start-Sleep -Milliseconds 300

            foreach ($RsaCase in $X509RsaCases) {
                $LogSnapshot = Get-PkixServerLogs
                Invoke-PlinkTest -Name "X509v3-Negotiation-SHA1-Only-$($RsaCase.Name)" -CertId $RsaCase.CertId -HostKeys $HostKeys
                $ObservedAlgorithm = Get-ObservedX509RsaAlgorithm -LogText (Get-NewPkixServerLogs -Before $LogSnapshot)
                if ($ObservedAlgorithm -and $ObservedAlgorithm -ne 'x509v3-ssh-rsa') {
                    throw "Server log recorded '$ObservedAlgorithm' while configured exclusively for x509v3-ssh-rsa."
                }

                $Observation = if ($ObservedAlgorithm) { ' The server debug log recorded the same algorithm.' } else { '' }
                Add-Result -Name "PKIX-X509V3-SHA1-Only-$($RsaCase.Name)" -Status 'Pass' -Detail "Authenticated with $($RsaCase.Bits)-bit key while generic rsa-sha2-256 was advertised but x509v3-ssh-rsa was the only accepted X.509 RSA algorithm.$Observation"
            }

            # 4. Test X.509 ECDSA negotiation variants (SHA-256/384/512)
            $X509EcdsaVariants = @(
                [PSCustomObject]@{ Bits = 256; Algorithm = 'x509v3-ecdsa-sha2-nistp256'; HashName = 'SHA256' }
                [PSCustomObject]@{ Bits = 384; Algorithm = 'x509v3-ecdsa-sha2-nistp384'; HashName = 'SHA384' }
                [PSCustomObject]@{ Bits = 521; Algorithm = 'x509v3-ecdsa-sha2-nistp521'; HashName = 'SHA512' }
            )

            foreach ($Variant in $X509EcdsaVariants) {
                Set-AcceptedAlgorithms -CustomAlgorithm $Variant.Algorithm
                Start-Sleep -Milliseconds 300

                $VariantCases = $Matrix.Positive | Where-Object { $_.KeyType -eq 'ECDSA' -and $_.Bits -eq $Variant.Bits }
                if (-not $VariantCases) {
                    Add-Result -Name "PKIX-X509V3-$($Variant.HashName)" -Status 'Skip' -Detail "No ECDSA $($Variant.Bits)-bit test certificate available for $($Variant.Algorithm)."
                    continue
                }

                foreach ($EcdsaCase in $VariantCases) {
                    Invoke-PlinkTest -Name "X509v3-Negotiation-$($Variant.HashName)-$($EcdsaCase.Name)" -CertId $EcdsaCase.CertId -HostKeys $HostKeys
                    Add-Result -Name "PKIX-X509V3-$($Variant.HashName)-$($EcdsaCase.Name)" -Status 'Pass' -Detail "Successfully authenticated with $($EcdsaCase.Name) using $($Variant.Algorithm)."
                }
            }
        }
        finally {
            Remove-ItemProperty -LiteralPath $X509RegPath -Name 'AuthX509' -Force -ErrorAction SilentlyContinue
        }
    }

    Test-PageantFilters -Positive $Matrix.Positive -Negative $Matrix.Negative -SmartCardLogon $Matrix.SmartCardLogon

    Test-RegistryFlags
}
catch {
    $Message = $_.Exception.Message
    Add-Result -Name 'UNHANDLED' -Status 'Fail' -Detail $Message
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($DockerCmd) {
        $Logs = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('logs', $PkixContainerName) -IgnoreExitCode
        Write-Host "Container Logs on Failure (Stdout):`n$($Logs.StdOut)"
        Write-Host "Container Logs on Failure (Stderr):`n$($Logs.StdErr)"
    }
}
finally {
    Stop-Pageants

    # Stop and remove the Docker container
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($DockerCmd) {
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('rm', '-f', $PkixContainerName) -IgnoreExitCode | Out-Null
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('rm', '-f', $WolfSshContainerName) -IgnoreExitCode | Out-Null
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('rm', '-f', $AsyncSshContainerName) -IgnoreExitCode | Out-Null
    }

    # Clean up temporary files
    if ($PkixAuthKeysPath -and (Test-Path -LiteralPath $PkixAuthKeysPath)) { Remove-Item -LiteralPath $PkixAuthKeysPath -Force -ErrorAction SilentlyContinue }
    if ($script:Paths.PkixHostKeys -and (Test-Path -LiteralPath $script:Paths.PkixHostKeys)) { Remove-Item -LiteralPath $script:Paths.PkixHostKeys -Recurse -Force -ErrorAction SilentlyContinue }
    if ($script:Paths.PkixChainRoot -and (Test-Path -LiteralPath $script:Paths.PkixChainRoot)) { Remove-Item -LiteralPath $script:Paths.PkixChainRoot -Force -ErrorAction SilentlyContinue }

    Restore-PuTTYRegistry
    Remove-TestCertificates

    Write-Summary
}
