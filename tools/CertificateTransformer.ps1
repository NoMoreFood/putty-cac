<#
.SYNOPSIS

CertificateTransformer is a small collection of functions to query and tranform
certificates from Active Directory or Windows Certificate Authorites and save
them to a file or create a string that can be used in SSH key files.

.HISTORY

1.0.0.0 - Initial Public Release 
1.1.0.0 - Added PEM Processing
1.2.0.0 - Added functions Get-CertificatesFromMyCertificationStore, Print-CertificateDetailsPrettyFormatted 

.NOTES

For transform operations, this script requires .Net Frametwork 4.6.1 or later. 

Author: Bryan Berns (Bryan.Berns@gmail.com).  

#>

#Requires -Version 3
Set-StrictMode -Version 2.0

# sanity check
Try
{
    [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions].GetType() | Out-Null
}
Catch
{
    Write-Host -ForegroundColor Yellow 'Warning: .NET Framework 4.6.1 or later is not installed. Some functionality may not be available.'
}

# internal use only - converts a variety of inputs to a certificate object
Function Script:Get-NormalizedCertificateObject
{
	[CmdletBinding()]
	Param
    (
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)][object] $Certificate,
        [object] $Password = $null
	)

    $CertificatePath = $null
    $CreationArgs = @()
    If ($Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate])
    {
        $CreationArgs = @($Certificate)
    } `
    ElseIf ($Certificate -is [byte[]])
    {
        $CreationArgs = @(,$Certificate)
    } `
    ElseIf ($Certificate -is [System.IO.FileSystemInfo])
    {
        # extract full path from information object
        $CertificatePath = $Certificate.FullName
        $CreationArgs = @($CertificatePath)
    } `
    ElseIf ($Certificate -is [string])
    {
        If (-not (Test-Path $Certificate -PathType Leaf))
        {
            Throw 'Certificate file does not exist.'
        }

        # expand to absolute path
        $CertificatePath = @(Resolve-Path $Certificate | Select-Object -ExpandProperty Path)
        $CreationArgs = @($CertificatePath)      
    } `
    Else
    {
        Throw 'Object type not supported.'
    }

    # check to see if file is in pem format and, if so, convert to byte array
    If ($CertificatePath -ne $null) 
    {
        $FileData = (Get-Content $CertificatePath) -join '' 
        If ($FileData -match '-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----')
        {
            $CreationArgs = @(,[System.Convert]::FromBase64String($Matches[1]))
        }
    }

    # append password to argument list if specified
    If ($Password -ne $null)
    {
        $CreationArgs += $Password
    }

    Return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $CreationArgs
}

<#
.SYNOPSIS

This function prints the key string for a given certificate that can be used
in an authorized_keys file.

.PARAMETER Certificate

The -Certificate specifies the certificate for which the key string will be 
generated.  This can be a certificate object, a path to a file, a file system
information entry, or a byte array of raw certificate data.

.PARAMETER Password

The -Password is an optional argument that specifies the password for a 
protected certificate in PFX format.

.EXAMPLE

Get-ADUser 'MyAccount' | Get-CertificateFromActiveDirectory | Get-CertificateKeyString
Get-ChildItem 'Cert:\CurrentUser\My' | Get-CertificateKeyString
Get-CertificateKeyString -Certificate 'My Certificate.cer'

#>
Function Global:Get-CertificateKeyString 
{
	[CmdletBinding()]
	Param
    (
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)][object] $Certificate,
        [object] $Password = $null
	)

	Process
    {
        # convert the input to a normalized x509 format
        $CertObject = Get-NormalizedCertificateObject -Certificate $Certificate -Password $Password

        # create a stream on which to build the keystring
        $Stream = New-Object System.IO.MemoryStream
        $Writer = New-Object System.IO.BinaryWriter($Stream)

        If ($CertObject.PublicKey.Oid.FriendlyName -eq 'RSA')
        {
            $PublicKey = $CertObject.PublicKey.Key

            $KeyType = 'ssh-rsa'
            $Params = $PublicKey.ExportParameters($False)
            $Header = [System.Text.ASCIIEncoding]::ASCII.GetBytes($KeyType)

            $Writer.Write([System.Net.IPAddress]::HostToNetworkOrder($Header.Length))
            $Writer.Write($Header)

            $Writer.Write([System.Net.IPAddress]::HostToNetworkOrder($Params.Exponent.Length))
            $Writer.Write($Params.Exponent)

            $Writer.Write([System.Net.IPAddress]::HostToNetworkOrder($Params.Modulus.Length + 1))
            $Writer.Write([byte]0x0)
            $Writer.Write($Params.Modulus)

        } `
        ElseIf ($CertObject.PublicKey.Oid.FriendlyName -eq 'ECC')
        {
            $PublicKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($CertObject)
        
            $Params = $PublicKey.ExportParameters($False)
            $CurveName = $Params.Curve.Oid.FriendlyName.ToLower()
            $KeyType = 'ecdsa-sha2-' + $CurveName

            $Header = [System.Text.ASCIIEncoding]::ASCII.GetBytes($KeyType)
            $SubHeader = [System.Text.ASCIIEncoding]::ASCII.GetBytes($CurveName)

            $Writer.Write([System.Net.IPAddress]::HostToNetworkOrder($Header.Length))
            $Writer.Write($Header)

            $Writer.Write([System.Net.IPAddress]::HostToNetworkOrder($SubHeader.Length))
            $Writer.Write($SubHeader)

            $Writer.Write([System.Net.IPAddress]::HostToNetworkOrder( `
                1 + $Params.Q.X.Length + $Params.Q.Y.Length))

            $Writer.Write([byte]0x4)
            $Writer.Write($Params.Q.X)
            $Writer.Write($Params.Q.Y)
        } `
        Else 
        {
            Throw 'Certificate type not supported.'
        }

        $Writer.Flush()
        $Writer.Close()

        $Stream.Flush()
        $KeyType + ' ' + [System.Convert]::ToBase64String($Stream.ToArray())
        $Stream.Dispose()
    }
}

<#
.SYNOPSIS

This function queries all issued certificate from a certificate authority.

.PARAMETER Server

The -ServerName parameter specifies the server name that holds the CA.

.PARAMETER Authority

The -Authority parameter specifies the the name of the CA.

.PARAMETER IncludeExpired

The -IncludeExpired switch causes all certificates which are expired or are not
active yet (i.e. issues to a future date) to be included in the output.  By 
default, these types of certificates not included.

.PARAMETER IncludeRevoked

The -IncludeRevoked switch causes all certificates which are revoked to be 
included in the output.  By default, these types of certificates not included.

.PARAMETER IncludeAllUsages

The -IncludeAllUsages switch causes all certificates to be returned.  If you do
not specify this flag, only smart card logon type certificates are returned.

.PARAMETER Authority

The -Authority parameter specifies the the name of the CA.

.EXAMPLE

Get-CertificatesFromAuthority -Server 'CA-SERVER' -Authority 'CA' | Get-CertificateKeyString

#>
Function Global:Get-CertificatesFromAuthority 
{
	[CmdletBinding()]
	Param
    (
		[Parameter(Mandatory=$True)][object] $Server,
        [Parameter(Mandatory=$True)][object] $Authority,
        [switch] $IncludeExpired,
        [switch] $IncludeRevoked,
        [switch] $IncludeAllUsages
	)

    # establish connection to certificate authority
    $View = New-Object -ComObject CertificateAuthority.View
    $View.OpenConnection($Server + '\' + $Authority)

    # setup data to query
    $View.SetResultColumnCount(1)
    $View.SetResultCOlumn($View.GetColumnIndex($False,'RawCertificate'))

    # setup view to enumerate
    $ViewRow = $View.OpenView()
    $ViewRow.Reset()

    # setup constants for comparison operators
    Set-Variable -Name 'CVR_SEEK_NONE' -Option Constant -Value (0x0)
    Set-Variable -Name 'CVR_SEEK_EQ' -Option Constant -Value (0x1)
    Set-Variable -Name 'CVR_SEEK_LT' -Option Constant -Value (0x2)
    Set-Variable -Name 'CVR_SEEK_LE' -Option Constant -Value (0x4)
    Set-Variable -Name 'CVR_SEEK_GE' -Option Constant -Value (0x8)
    Set-Variable -Name 'CVR_SEEK_GT' -Option Constant -Value (0x10)

    # only provide certificate that have not expires
    If (-not $IncludeExpired)
    {
        $Now = [DateTime]::UtcNow
        $View.SetRestriction($View.GetColumnIndex($False,'NotBefore'),$CVR_SEEK_LE,0,$Now)
        $View.SetRestriction($View.GetColumnIndex($False,'NotAfter'),$CVR_SEEK_GT,0,$Now)
    }

    # only provide certificate that have not been revoked
    If (-not $IncludeRevoked)
    {
        Set-Variable -Name 'DB_DISP_ISSUED' -Option Constant -Value (20)
        Set-Variable -Name 'DB_DISP_REVOKED' -Option Constant -Value (21)

        $View.SetRestriction($View.GetColumnIndex($False,'Request.Disposition'),$CVR_SEEK_EQ,0,$DB_DISP_ISSUED)
    }

    # constant for detecting smart card certificates
    $SmartCardOid = (New-Object System.Security.Cryptography.Oid("Smart Card Logon")).Value

    # enumerate certificates
    While ($ViewRow.Next() -ne -1)
    {
        $ViewColumn = $ViewRow.EnumCertViewColumn()
        While ($ViewColumn.Next() -ne -1)
        {
            # get the turn the raw certificate into a x509 struct
            $CertData = $ViewColumn.GetValue(1)
            $CertObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
                -ArgumentList @(,([System.Convert]::FromBase64String($CertData)))

            # only include smart card logon types 
            If (-not $IncludeAllUsages)
            {
                If (@($CertObject | Select-Object -ExpandProperty Extensions -ErrorAction SilentlyContinue | `
                    Select-Object -ExpandProperty EnhancedKeyUsages -ErrorAction SilentlyContinue | `
                    Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue) -notcontains $SmartCardOid)
                {
                    Continue
                }
            }

            # return object to caller
            $CertObject
        }
    }

    # close the connection
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($View) | Out-Null
}

<#
.SYNOPSIS

This function saves a certificate to a file.

.PARAMETER Certificate

The -Certificate specifies the certificate to save to a file. This can be a 
certificate object or a byte array of raw certificate data.

.PARAMETER Format

The -Format specifies the format of the output file.  In not specified, a 
standard DER-encoded format will be used.  See X509ContentType for other 
types.

.EXAMPLE

Get-ADUser 'MyAccount' | Get-CertificateFromActiveDirectory | Save-Certificate -File Out.cer
Get-ChildItem 'Cert:\CurrentUser\My' | Save-Certificate -File Out.cer

#>
Function Global:Save-Certificate
{
	[CmdletBinding()]
	Param
    (
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)][object] $Certificate,
        [Parameter(Mandatory=$True)][string] $File,
        [System.Security.Cryptography.X509Certificates.X509ContentType] $Format = `
            ([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
	)

    $CertObject = Get-NormalizedCertificateObject -Certificate $Certificate
    [System.IO.File]::WriteAllBytes($File,$CertObject.Export($Format))
}

<#
.SYNOPSIS

This function converts a certificate to PEM format.

.PARAMETER Certificate

The -Certificate specifies the certificate to convert to a PEM string. This can
be a certificate object, a path to a file, a file system information entry, or
a byte array of raw certificate data.

#>
Function Global:Convert-CertificateToPem
{
	[CmdletBinding()]
	Param
    (
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)][object] $Certificate
	)

    $NewLine = ([System.Environment]::NewLine)
    $CertObject = Get-NormalizedCertificateObject -Certificate $Certificate
    $CertData = [System.Convert]::ToBase64String($CertObject.RawData)
    Return `
        '-----BEGIN CERTIFICATE-----' + $NewLine + `
        ($CertData -replace '(.{64})',('${1}' + $NewLine)) + $NewLine + `
        '-----END CERTIFICATE-----'
}

<#
.SYNOPSIS

This function perform a simple expansion of an AD user object to grab the the
certificate data.

.PARAMETER Identity

The -Identity parameter specifies the AD object from which to get certificates.

.EXAMPLE

Get-ADUser 'MyAccount' | Get-CertificateFromActiveDirectory

#>
Function Global:Get-CertificateFromActiveDirectory()
{
	[CmdletBinding()]
	Param
    (
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)][Microsoft.ActiveDirectory.Management.ADAccount] $Identity
	)
 
    Process
    {
        $Identity | Get-ADUser -Properties 'Certificates' | Select-Object -ExpandProperty 'Certificates'
    }
}


<#
.SYNOPSIS

Smartcard certificates are also available via Windows Certification Store.
This function gets all My certificates which have a valid date and
have the X509v3 Clientauth Extension (OID: 1.3.6.1.5.5.7.3.2) enabled 
from the Windows Certification Store.

.EXAMPLE

Get-CertificatesFromMyCertificationStore | Get-CertificateKeyString

#>
Function Global:Get-CertificatesFromMyCertificationStore 
{
    Process
    {
		[System.Security.Cryptography.X509Certificates.X509Certificate2[]]$aAllValidCertificatesWithClientAuthExtension=@()
		
		$aAllValidCertificates=Get-item Cert:\CurrentUser\My\* | where-object{$_.NotAfter -gt (Get-date) -and $_.NotBefore -lt (get-date)} 
		
		$aAllValidCertificatesWithClientAuthExtension=$aAllValidCertificates | where-object{$_.EnhancedKeyUsageList | where-object {$_.ObjectID -eq "1.3.6.1.5.5.7.3.2"}}
		
		return $aAllValidCertificatesWithClientAuthExtension
	}
}

<#
.SYNOPSIS

This function prints the Common Name, Thumbprint, Issuer "pretty" formatted and
the SSH public key in paagent style format and can copy the public key to the
windows clipboard for further usage.

.PARAMETER Certificate

The -Certificate specifies the certificate for which the details will be shown.
This must be a certificate object.

.PARAMETER CopyPublicKeyToClipboard

If -CopyPublicKeyToClipboard is set the ssh public key is copied to the Windows Clipboard.
Note: This is only working on newer powershell releases. To get this working
on older powershell versions the powershell has to start as a single thread
application by powershell.exe -sta

.EXAMPLE

Get-CertificatesFromMyCertificationStore | Print-CertificateDetailsPrettyFormatted
Get-CertificatesFromMyCertificationStore | Print-CertificateDetailsPrettyFormatted -CopyPublicKeyToClipboard

#>
Function Global:Print-CertificateDetailsPrettyFormatted
{
	[CmdletBinding()]
	Param
    (
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [switch] $CopyPublicKeyToClipboard = $false
	)
	Process {
	
		write-host -foregroundcolor green ([string]::Format("{0,16} : {1}","Common name",$Certificate.SubjectName.Name))
		write-host -foregroundcolor yellow ([string]::Format("{0,16} : {1}","Thumbprint",$Certificate.Thumbprint))
		write-host -foregroundcolor Cyan ([string]::Format("{0,16} : {1}","Issuer",$Certificate.issuer))
		write-host ""
		
		$PublicKeyString=$Certificate|Get-CertificateKeyString

		$PublicKeyString+=" CAPI:"+$Certificate.Thumbprint + " " +$Certificate.SubjectName.Name
		
		write-host -foregroundcolor Magenta $PublicKeyString
		
		if($CopyPublicKeyToClipboard)
		{
			try {
				[Reflection.Assembly]::LoadWithPartialName("System.Windows")|out-null
				Add-Type -Assembly PresentationCore|out-null
				[System.Windows.Clipboard]::SetText($PublicKeyString);
				write-host "`r`nSSH public key successfully copied to clipboard`r`n"
			}
			catch [Exception] {}
		}
	}
}

