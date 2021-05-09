# this file is used for making keypairs for testing

$Certificates = @()
$HostName = Read-Host -Prompt 'Enter Host Name'
$KeyProvider = 'Microsoft Software Key Storage Provider'
If ((Read-Host -Prompt 'Create On Smart Card (Y/N)') -eq 'Y') {
    $KeyProvider = 'Microsoft Smart Card Key Storage Provider'
}

$KeyLengths = (1024,2048,4096)
ForEach ($KeyLength in $KeyLengths)
{
    $Certificates += New-SelfSignedCertificate -KeyUsageProperty Sign -KeyUsage DigitalSignature `
        -CertStoreLocation 'Cert:\CurrentUser\My' -Provider $KeyProvider `
        -KeyLength $KeyLength -KeyAlgorithm RSA -HashAlgorith SHA256 `
        -FriendlyName "Soft RSA $KeyLength" -Subject "CN=Soft RSA $KeyLength"
}   

$AlgTypes = @('ECDSA_nistP256','ECDSA_nistP384','ECDSA_nistP521')
ForEach ($AlgType in $AlgTypes) 
{
    $Certificates += New-SelfSignedCertificate -KeyUsageProperty Sign -KeyUsage DigitalSignature `
        -CertStoreLocation 'Cert:\CurrentUser\My' -Provider $KeyProvider `
        -KeyAlgorithm $AlgType -CurveExport CurveName -HashAlgorithm SHA256 `
        -FriendlyName "Soft $AlgType" -Subject "CN=Soft $AlgType"
}

# create base registry keys
New-Item -Path 'HKCU:SOFTWARE\SimonTatham' -Force | Out-Null 
New-Item -Path 'HKCU:SOFTWARE\SimonTatham\PuTTY' -Force | Out-Null
New-Item -Path 'HKCU:SOFTWARE\SimonTatham\PuTTY\Sessions' -Force | Out-Null

$CertIdList = @();
ForEach ($Certificate in $Certificates)
{
    $CertIdList += 'CAPI:' + $Certificate.Thumbprint.ToLower()
    $SessionKey = ('HKCU:SOFTWARE\SimonTatham\PuTTY\Sessions\' + `
        ($Certificate.FriendlyName -replace ' ','%20'))
    New-Item -Path $SessionKey -Force | Out-Null
    New-ItemProperty -Path $SessionKey  -Force `
        -Name 'CAPICertID' -Value $CertIdList[-1] `
        -PropertyType ([Microsoft.Win32.RegistryValueKind]::String)
    New-ItemProperty -Path $SessionKey  -Force `
        -Name 'AuthCAPI' -Value 1 `
        -PropertyType ([Microsoft.Win32.RegistryValueKind]::DWord)
    New-ItemProperty -Path $SessionKey  -Force `
        -Name 'AgentFwd' -Value 1 `
        -PropertyType ([Microsoft.Win32.RegistryValueKind]::DWord)
    New-ItemProperty -Path $SessionKey  -Force `
        -Name 'HostName' -Value $HostName `
        -PropertyType ([Microsoft.Win32.RegistryValueKind]::String)      
}

New-ItemProperty -Path 'HKCU:SOFTWARE\SimonTatham\PuTTY' `
    -Name 'SaveCertListEnabled' -Value 1  -Force `
    -PropertyType ([Microsoft.Win32.RegistryValueKind]::DWord)
New-ItemProperty -Path 'HKCU:SOFTWARE\SimonTatham\PuTTY' `
    -Name 'SaveCertList' -Value $CertIdList -Force `
    -PropertyType ([Microsoft.Win32.RegistryValueKind]::MultiString)