#Requires -Version 7.0
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ServerRoot = 'C:\Program Files (x86)\SSH Communications Security\SSH Tectia\SSH Tectia Server',
    [string]$ServiceName = 'SSHTectiaServer',
    [ValidateRange(1024, 65532)]
    [int]$BasePort = 2230,
    [string]$CaDirectory = (Join-Path $env:ProgramData 'PuTTYCAC-Test\Tectia'),
    [switch]$Restore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ConfigPath = Join-Path $ServerRoot 'ssh-server-config.xml'
$ControlPath = Join-Path $ServerRoot 'ssh-server-ctl.exe'
$BackupPath = Join-Path $CaDirectory 'ssh-server-config.original.xml'
$RollbackPath = Join-Path $CaDirectory 'ssh-server-config.rollback.xml'
$CandidatePath = Join-Path $CaDirectory 'ssh-server-config.candidate.xml'
$CaPath = Join-Path $CaDirectory 'puttycac-tectia-test-root.cer'
$CaSubject = 'CN=PuTTYCAC Tectia Test Root'
$CaFriendlyName = 'PuTTYCAC Tectia Test Root'
$CaProfileName = 'puttycac-test-root'

$Algorithms = @(
    [PSCustomObject]@{ Name = 'rsa-sha256'; Algorithm = 'x509v3-rsa2048-sha256'; Port = $BasePort }
    [PSCustomObject]@{ Name = 'ecdsa-p256'; Algorithm = 'x509v3-ecdsa-sha2-nistp256'; Port = $BasePort + 1 }
    [PSCustomObject]@{ Name = 'ecdsa-p384'; Algorithm = 'x509v3-ecdsa-sha2-nistp384'; Port = $BasePort + 2 }
    [PSCustomObject]@{ Name = 'ecdsa-p521'; Algorithm = 'x509v3-ecdsa-sha2-nistp521'; Port = $BasePort + 3 }
)

function Assert-Path([string]$Path, [string]$Description) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description was not found: $Path"
    }
}

function Test-CertificateAuthority([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
    $Extension = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.19' } |
        Select-Object -First 1
    if (-not $Extension) { return $false }
    $BasicConstraints = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$Extension
    return $BasicConstraints.CertificateAuthority
}

function Get-OrCreateTestRoot {
    $Now = Get-Date
    $Root = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object {
            $_.Subject -eq $CaSubject -and
            $_.FriendlyName -eq $CaFriendlyName -and
            $_.HasPrivateKey -and
            $_.NotBefore -le $Now -and
            $_.NotAfter -gt $Now.AddDays(30) -and
            (Test-CertificateAuthority $_)
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $Root) {
        $Root = New-SelfSignedCertificate `
            -Type Custom `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -Subject $CaSubject `
            -FriendlyName $CaFriendlyName `
            -Provider 'Microsoft Software Key Storage Provider' `
            -KeyAlgorithm RSA `
            -KeyLength 3072 `
            -HashAlgorithm SHA256 `
            -KeyUsage CertSign, CRLSign `
            -TextExtension @('2.5.29.19={critical}{text}ca=true&pathlength=0') `
            -NotBefore $Now.AddMinutes(-5) `
            -NotAfter $Now.AddYears(2)
    }

    Export-Certificate -Cert $Root -FilePath $CaPath -Type CERT -Force | Out-Null
    return $Root
}

function New-Element([xml]$Document, [string]$Name, [hashtable]$Attributes) {
    $Element = $Document.CreateElement($Name)
    foreach ($Key in $Attributes.Keys) {
        $Element.SetAttribute([string]$Key, [string]$Attributes[$Key])
    }
    return $Element
}

function Assert-ValidTectiaXml([string]$Path) {
    $ValidationErrors = [Collections.Generic.List[string]]::new()
    $Settings = [Xml.XmlReaderSettings]::new()
    $Settings.DtdProcessing = [Xml.DtdProcessing]::Parse
    $Settings.ValidationType = [Xml.ValidationType]::DTD
    $Settings.XmlResolver = [Xml.XmlUrlResolver]::new()
    $Settings.add_ValidationEventHandler({
            param($Sender, $EventArgs)
            $ValidationErrors.Add($EventArgs.Message) | Out-Null
        })

    $Reader = [Xml.XmlReader]::Create($Path, $Settings)
    try {
        while ($Reader.Read()) { }
    }
    finally {
        $Reader.Dispose()
    }

    if ($ValidationErrors.Count -gt 0) {
        throw "Tectia rejected the generated XML model: $($ValidationErrors -join '; ')"
    }
}

function Save-Xml([xml]$Document, [string]$Path) {
    $Settings = [Xml.XmlWriterSettings]::new()
    $Settings.Encoding = [Text.UTF8Encoding]::new($false)
    $Settings.Indent = $true
    $Settings.NewLineChars = "`r`n"
    $Settings.NewLineHandling = [Xml.NewLineHandling]::Replace
    $Writer = [Xml.XmlWriter]::Create($Path, $Settings)
    try {
        $Document.Save($Writer)
    }
    finally {
        $Writer.Dispose()
    }
}

function Wait-TectiaListeners {
    $Deadline = (Get-Date).AddSeconds(30)
    do {
        $Listening = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -in @('127.0.0.1', '0.0.0.0') }).LocalPort
        $Missing = @($Algorithms.Port | Where-Object { $_ -notin $Listening })
        if ($Missing.Count -eq 0) { return }
        Start-Sleep -Milliseconds 500
    }
    while ((Get-Date) -lt $Deadline)

    throw "Tectia did not open test listener port(s): $($Missing -join ', ')."
}

Assert-Path -Path $ConfigPath -Description 'Tectia server configuration'
Assert-Path -Path $ControlPath -Description 'Tectia server control utility'
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    throw "The Tectia Windows service '$ServiceName' is not installed."
}

New-Item -ItemType Directory -Path $CaDirectory -Force | Out-Null

if ($Restore) {
    Assert-Path -Path $BackupPath -Description 'PuTTY-CAC Tectia configuration backup'
    if ($PSCmdlet.ShouldProcess($ConfigPath, 'Restore the pre-PuTTY-CAC Tectia configuration')) {
        Copy-Item -LiteralPath $BackupPath -Destination $ConfigPath -Force
        Restart-Service -Name $ServiceName -Force
        Write-Host "Restored Tectia configuration from $BackupPath"
    }
    return
}

if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
    Copy-Item -LiteralPath $ConfigPath -Destination $BackupPath
}
Copy-Item -LiteralPath $ConfigPath -Destination $RollbackPath -Force

$Root = Get-OrCreateTestRoot

[xml]$Document = Get-Content -LiteralPath $ConfigPath -Raw
$Document.PreserveWhitespace = $false
$Params = $Document.SelectSingleNode('/secsh-server/params')
$AuthenticationMethods = $Document.SelectSingleNode('/secsh-server/authentication-methods')
if (-not $Params -or -not $AuthenticationMethods) {
    throw 'The Tectia configuration must contain params and authentication-methods elements.'
}

foreach ($Node in @($Params.SelectNodes("listener[starts-with(@id, 'puttycac-')]"))) {
    [void]$Params.RemoveChild($Node)
}
foreach ($Node in @($AuthenticationMethods.SelectNodes("authentication[starts-with(@name, 'puttycac-')]"))) {
    [void]$AuthenticationMethods.RemoveChild($Node)
}

$CertificateValidation = $Params.SelectSingleNode('cert-validation')
if (-not $CertificateValidation) {
    $CertificateValidation = New-Element -Document $Document `
        -Name 'cert-validation' -Attributes @{}
    [void]$Params.AppendChild($CertificateValidation)
}
foreach ($Node in @($CertificateValidation.SelectNodes("ca-certificate[@name='$CaProfileName']"))) {
    [void]$CertificateValidation.RemoveChild($Node)
}
$CaElement = New-Element -Document $Document -Name 'ca-certificate' -Attributes @{
    name = $CaProfileName
    file = $CaPath
    'disable-crls' = 'yes'
    trusted = 'yes'
}
[void]$CertificateValidation.AppendChild($CaElement)

$AuthenticationAnchor = $AuthenticationMethods.FirstChild
foreach ($Entry in $Algorithms) {
    $ListenerId = "puttycac-$($Entry.Name)"
    $Listener = New-Element -Document $Document -Name 'listener' -Attributes @{
        id = $ListenerId
        address = '127.0.0.1'
        port = $Entry.Port
    }
    [void]$Params.AppendChild($Listener)

    # Tectia evaluates certificate selectors only after auth-publickey has
    # completed.  Use a parent block to select the listener and perform the
    # authentication, then authorize the validated certificate in a child.
    $Authentication = New-Element -Document $Document -Name 'authentication' -Attributes @{
        name = "$ListenerId-policy"
    }
    $Selector = New-Element -Document $Document -Name 'selector' -Attributes @{}
    [void]$Selector.AppendChild((New-Element -Document $Document -Name 'interface' -Attributes @{
                id = $ListenerId
                'allow-undefined' = 'no'
            }))
    [void]$Authentication.AppendChild($Selector)
    [void]$Authentication.AppendChild((New-Element -Document $Document -Name 'auth-publickey' -Attributes @{
                'require-dns-match' = 'no'
                'signature-algorithms' = $Entry.Algorithm
            }))

    $Allow = New-Element -Document $Document -Name 'authentication' -Attributes @{
        name = "$ListenerId-allow"
        action = 'allow'
    }
    $AllowSelector = New-Element -Document $Document -Name 'selector' -Attributes @{}
    [void]$AllowSelector.AppendChild((New-Element -Document $Document -Name 'certificate' -Attributes @{
                field = 'ca-list'
                pattern = $CaProfileName
            }))
    [void]$Allow.AppendChild($AllowSelector)

    $Deny = New-Element -Document $Document -Name 'authentication' -Attributes @{
        name = "$ListenerId-deny"
        action = 'deny'
    }
    [void]$Authentication.AppendChild($Allow)
    [void]$Authentication.AppendChild($Deny)

    if ($AuthenticationAnchor) {
        [void]$AuthenticationMethods.InsertBefore($Authentication, $AuthenticationAnchor)
    }
    else {
        [void]$AuthenticationMethods.AppendChild($Authentication)
    }
}

Save-Xml -Document $Document -Path $CandidatePath
Assert-ValidTectiaXml -Path $CandidatePath

if (-not $PSCmdlet.ShouldProcess($ConfigPath, 'Install the PuTTY-CAC Tectia test configuration and restart Tectia')) {
    return
}

try {
    Copy-Item -LiteralPath $CandidatePath -Destination $ConfigPath -Force
    Restart-Service -Name $ServiceName -Force
    Wait-TectiaListeners
}
catch {
    Copy-Item -LiteralPath $RollbackPath -Destination $ConfigPath -Force
    Restart-Service -Name $ServiceName -Force
    throw "Tectia setup failed and the previous configuration was restored: $($_.Exception.Message)"
}

[PSCustomObject]@{
    Product = (& $ControlPath --version 2>&1 | Select-Object -First 1)
    Service = $ServiceName
    Configuration = $ConfigPath
    Backup = $BackupPath
    RootThumbprint = $Root.Thumbprint
    RootCertificate = $CaPath
    User = "$env:COMPUTERNAME\$env:USERNAME"
    Listeners = $Algorithms
} | Format-List
