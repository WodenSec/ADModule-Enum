########################################
#                                      #
#            Initialization            #
#                                      #
########################################
# Unicorn puke (<3 Dewalt)
function Write-Cyan {
    param (
        [string]$message
    )
    Write-Host -ForegroundColor Cyan $message
}
function Write-Yellow {
    param (
        [string]$message
    )
    Write-Host -ForegroundColor Yellow $message
}
function Write-Green {
    param (
        [string]$message
    )
    Write-Host -ForegroundColor Green $message
}
function Write-Red {
    param (
        [string]$message
    )
    Write-Host -ForegroundColor Red $message
}

function Check-ADModule {
    # Check if an AD command is available
    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
        Write-Green "[+] Active Directory module is available."
    } else {
        Write-Yellow "[*] AD module not found. Attempting to import Microsoft.ActiveDirectory.Management.dll..."
        
        # Attempt to import the DLL from the current directory
        $dllPath = Join-Path -Path (Get-Location) -ChildPath "Microsoft.ActiveDirectory.Management.dll"
        if (Test-Path $dllPath) {
            try {
                Import-Module $dllPath
                Write-Green "[+] Successfully imported Microsoft.ActiveDirectory.Management.dll."
            } catch {
                Write-Red "[-] Failed to import Microsoft.ActiveDirectory.Management.dll. AD commands are unavailable."
                exit 1
            }
        } else {
            Write-Red "[-] Microsoft.ActiveDirectory.Management.dll not found in the current directory. AD commands are unavailable."
            exit 1
        }
    }
}
Check-ADModule

# Get current user and domain
$currentUser = $env:USERNAME
$currentDomain = $env:USERDNSDOMAIN
$domainSID = (Get-ADDomain).DomainSID.Value

# Mapping of GUIDs to permissions
$guidMapping = @{
    "ab721a53-1e2f-11d0-9819-00aa0040529b" = "User-Change-Password"
    "bf967a68-0de6-11d0-a285-00aa003049e2" = "User-Account-Control"
    "00000000-0000-0000-0000-000000000000" = "All"
    # Need to add more mappings
}

########################################
#                                      #
#    Utility Functions Declaration     #
#                                      #
########################################

# Output formatting to remove unnecessary line breaks
function Format-Output {
    param (
        [string]$input,
        [bool]$AddSeparators = $true
    )
    if ([string]::IsNullOrWhiteSpace($input)) {
        Write-Red "[-] No data found."
        return ""
    } else {
        if ($AddSeparators) {
            return $input -replace "(\r?\n){2,}", "`n------------------------------`n"
        } else {
            return $input -replace "(\r?\n){2,}", "`n"
        }
    }
}

# Function to get group membership recursively
function Get-ADPrincipalGroupMembershipRecursive {
    param (
        [string]$SamAccountName
    )

    # FOR VERBOSE:
    # Write-Yellow "[+] Getting group membership recursively for: $SamAccountName"
    $groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName | Select -ExpandProperty DistinguishedName)
    $groups
    if ($groups.Count -gt 0) {
        foreach ($group in $groups) {
            Get-ADPrincipalGroupMembershipRecursive -SamAccountName $group
        }
    }
}

# Function to get group members recursively (if a group is member of a group)
function Get-GroupMembersRecursive {
    param (
        [string]$groupDN
    )

    # FOR VERBOSE:
    # Write-Yellow "[+] Getting group members recursively for: $groupDN"
    $members = Get-ADGroupMember -Identity $groupDN
    foreach ($member in $members) {
        if ($member.objectClass -eq "user") {
            Get-ADUser -Identity $member.SamAccountName -Properties * | Select SamAccountName, Enabled, PasswordLastSet | Format-List
        } elseif ($member.objectClass -eq "group") {
            Get-GroupMembersRecursive -groupDN $member.DistinguishedName
        }
    }
}

# Function to validate if a user exists
function Validate-User {
    param (
        [string]$username
    )
    try {
        $user = Get-ADUser -Identity $username -ErrorAction Stop
        Write-Green "[+] User $username found in AD."
        return $true
    } catch {
        Write-Red "[-] User $username does not exist in AD."
        return $false
    }
}

# Function to resolve GUIDs using the provided mapping
function Resolve-GUID {
    param (
        [string]$guid
    )
    if ($guidMapping.ContainsKey($guid)) {
        return $guidMapping[$guid]
    } else {
        return $guid
    }
}

# Function to get Identity Reference Class
function Get-IdentityReferenceClass {
    param (
        [string]$identityReference
    )

    if ($identityReference -like '*\*') {
        $samAccountName = $identityReference.Split('\')[1]
    } else {
        $samAccountName = $identityReference
    }

    # FOR VERBOSE:
    # Write-Yellow "[+] Getting Identity Reference Class for: $samAccountName"

    if (Get-ADUser -Filter {SamAccountName -eq $samAccountName} -ErrorAction SilentlyContinue) {
        return "user"
    } elseif (Get-ADGroup -Filter {SamAccountName -eq $samAccountName} -ErrorAction SilentlyContinue) {
        return "group"
    } else {
        return "unknown"
    }
}

# Function to get and translate ACLs for a given AD object
function Get-TranslatedACLs {
    param (
        [string]$objectDN
    )

    Write-Green "[+] Getting ACLs for object: $objectDN"
    $acls = (Get-Acl "AD:$objectDN").Access

    $translatedAcls = @()
    foreach ($acl in $acls) {
        $resolvedObjectType = Resolve-GUID -guid $acl.ObjectType.ToString()
        
        $translatedAcls += [PSCustomObject]@{
            ObjectDN               = $objectDN
            AccessControlType      = $acl.AccessControlType
            ActiveDirectoryRights  = $acl.ActiveDirectoryRights
            ObjectAceType          = $resolvedObjectType
            IdentityReference      = $acl.IdentityReference
            IdentityReferenceClass = Get-IdentityReferenceClass -identityReference $acl.IdentityReference
        }
    }
    return $translatedAcls
}

########################################
#                                      #
#     Targeted Enumeration Sub-Menu    #
#                                      #
########################################

function Show-TargetedEnumerationMenu {
    Write-Host "Targeted Enumeration Sub-Menu:"
    Write-Host "1. Enumerate current user"
    Write-Host "2. Enumerate specific user"
    $choice = Read-Host "Enter your choice (1/2)"
    
    switch ($choice) {
        1 {
            # Enumerate current user
            if (Validate-User -username $currentUser) {
                $targetUser = $currentUser
                Write-Yellow "[*] Enumerating current user: $targetUser"
                Run-TargetedEnumeration -targetUser $targetUser
            } else {
                Write-Red "[-] Current user $currentUser does not exist in AD (probably a local user)."
                Write-Yellow "[*] Exiting..."
            }
        }
        2 {
            # Enumerate specific user
            $specificUser = Read-Host "Enter the username of the specific user"
            if (Validate-User -username $specificUser) {
                $targetUser = $specificUser
                Write-Yellow "Enumerating specific user: $targetUser"
                Run-TargetedEnumeration -targetUser $targetUser
            } else {
                Write-Yellow "[*] Exiting..."
            }
        }
        default {
            Write-Host "Invalid choice. Returning to main menu."
            Show-MainMenu
        }
    }
}

########################################
#                                      #
#         Targeted Enumeration         #
#                                      #
########################################

function Run-TargetedEnumeration {
    param (
        [string]$targetUser
    )

    Write-Cyan "[*] Starting targeted enumeration for user: $targetUser"
    $targetDN = (Get-ADUser -Identity $targetUser | Select DistinguishedName).DistinguishedName

    # Get detailed information about the target user
    Write-Green "[+] Detailed information about $targetUser :"
    Get-ADUser -Identity $targetUser -Properties * | Select SamAccountName, Name, EmailAddress, DistinguishedName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired | Format-List | Out-String | Format-Output | Write-Host

    # Get group memberships recursively
    Write-Green "[+] Recursive group membership for $targetUser :"
    Get-ADPrincipalGroupMembershipRecursive -SamAccountName $targetUser | Format-List | Out-String | Format-Output | Write-Host

    Write-Green "[+] ACLs for $targetUser :"
    Get-TranslatedACLs -objectDN $targetDN | Format-List | Out-String | Format-Output | Write-Host
}


########################################
#                                      #
#      Get General AD Information      #
#                                      #
########################################

function Get-GeneralADInformation {
    Write-Cyan "[*] General AD Information."
    Write-Yellow "[*] Fetching General AD Information..."

    Write-Green "[*] Current domain information:"
    Get-ADDomain | Select DistinguishedName, DomainMode, DNSRoot, NetBIOSName, InfrastructureMaster, DomainSID | Format-List | Out-String | Format-Output | Write-Host

    Write-Green "[*] Current forest information:"
    Get-ADForest | Select Domains, DomainNamingMaster, ForestMode | Format-List | Out-String | Format-Output | Write-Host

    Write-Green "[*] Trust information:"
    Get-ADTrust -Filter * | Select Direction, Name, Source, Target | Format-List | Out-String | Format-Output | Write-Host
}




########################################
#                                      #
#        Get AD User Information       #
#                                      #
########################################

function Get-ADUsersInformation {
    Write-Cyan "[*] AD Users Information."
    Write-Yellow "[*] Fetching AD Users Information..."

    Write-Green "[*] All users (for password spray):"
    (Get-ADUser -Filter * | Select SamAccountName).samAccountName | Format-List | Out-String | Format-Output -AddSeparators $false | Write-Host

    Write-Green "[*] Users with description (look for passwords):"
    Get-ADUser -Filter * -Properties Description | Where-Object { $_.Description } | Select SamAccountName, Description, Enabled | Format-List | Out-String | Format-Output | Write-Host

    Write-Green "[*] Users with non-expiring passwords:"
    Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties * | Select SamAccountName, Name, PasswordLastSet, Enabled | Format-List | Out-String | Format-Output | Write-Host

    Write-Green "[*] Users with 'Password Not Required' set:"
    Get-ADUser -Filter {userAccountControl -band 0x20} -Properties * |  Select SamAccountName, Name, PasswordLastSet, Enabled |  Format-List | Out-String | Format-Output | Write-Host

}


########################################
#                                      #
#       Get AD Admin Information       #
#                                      #
########################################

function Get-ADAdminInformation {
    Write-Cyan "[*] AD Admin Information."
    Write-Yellow "[*] Fetching AD Admin Information..."

    Write-Green "[*] Domain administrators (including shadow admins):"
    Get-ADUser -Filter {AdminCount -eq 1} | Select SamAccountName,Enabled | Format-List | Out-String | Format-Output | Write-Host

    Write-Green "[*] Domain Admins group members:"
    $domainAdminDN = (Get-ADGroup -Filter "SID -eq '$domainSID-512'").DistinguishedName
    Get-GroupMembersRecursive -groupDN $domainAdminDN | Format-List | Out-String | Format-Output | Write-Host
}

########################################
#                                      #
#          Kerberos Settings           #
#                                      #
########################################

function Get-KerberosEnumeration {
    Write-Cyan "[*] Kerberos Enumeration."
    Write-Yellow "[*] Fetching Kerberos Information..."

    Write-Green "[*] SPNs for Kerberoasting:"
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, PasswordLastSet | Select SamAccountName, ServicePrincipalName, PasswordLastSet, Enabled | Format-List | Out-String | Format-Output | Write-Host
    
    Write-Green "[*] AS-REP roastable users:"
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth, PasswordLastSet | Select SamAccountName, PasswordLastSet, Enabled | Format-List | Out-String | Format-Output | Write-Host

    Write-Green "[*] Unconstrained delegation (computers):"
    Get-ADComputer -Filter {TrustedForDelegation -eq $True} | Select DNSHostName | Format-List | Out-String | Format-Output | Write-Host

    Write-Green "[*] Unconstrained delegation (users):"
    Get-ADUser -Filter {TrustedForDelegation -eq $True} | Select SamAccountName | Format-List | Out-String | Format-Output | Write-Host

    Write-Green "[*] Constrained delegation information:"
    Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | Select DistinguishedName, sAMAccountName, ObjectClass, msDS-AllowedToDelegateTo | Format-List | Out-String | Format-Output | Write-Host
}

########################################
#                                      #
#           Password Policy            #
#                                      #
########################################

function Get-PasswordPolicy {
    Write-Cyan "[*] Starting Password Policy Checkup."

    Write-Green "[+] Default Domain Password Policy:"
    Get-ADDefaultDomainPasswordPolicy | Format-List | Out-String | Format-Output -AddSeparators $false | Write-Host

    Write-Green "[+] Fine-Grained Password Policies:"
    Get-ADFineGrainedPasswordPolicy -Filter *  | Format-List | Out-String | Format-Output | Write-Host

    Write-Green "[+] Fine-Grained Password Policy Subjects:"
    Get-ADFineGrainedPasswordPolicy -Filter * | ForEach-Object {
        Write-Yellow "[*] Policy: $($_.Name)"
        $subjects = Get-ADFineGrainedPasswordPolicySubject -Identity $_.Name | Format-List | Out-String | Format-Output -AddSeparators $false
        Write-Host $subjects

        # Process each subject (group) to enumerate members recursively
        $subjectObjects = Get-ADFineGrainedPasswordPolicySubject -Identity $_.Name
        foreach ($subject in $subjectObjects) {
            $identityClass = Get-IdentityReferenceClass -identityReference $subject.SamAccountName

            if ($identityClass -eq "group") {
                Write-Yellow "[*] Enumerating members of group: $($subject.SamAccountName)"
                Get-GroupMembersRecursive -groupDN $subject.DistinguishedName | Format-List | Out-String | Format-Output | Write-Host
            }
        }
    }
}


########################################
#                                      #
#                gMSA                  #
#                                      #
########################################

function Get-gMSA {
    Write-Cyan "[*] Retrieving gMSAs (Group Managed Service Accounts) Information."
    Write-Yellow "[*] Fetching gMSAs details from Active Directory..."

    Get-ADServiceAccount -Filter * -Properties * | Select Name, DistinguishedName, SamAccountName, Enabled, PrincipalsAllowedToRetrieveManagedPassword | Format-List | Out-String | Format-Output | Write-Host
}


########################################
#                                      #
#           Run All Checks             #
#                                      #
########################################

function Run-AllChecks {
    Write-Cyan "[*] Running all checks."
    Get-GeneralADInformation
    Get-ADUsersInformation
    Get-ADAdminInformation
    Get-KerberosEnumeration
    Get-PasswordPolicy
    Get-gMSA
}

########################################
#                                      #
#               Main Menu              #
#                                      #
########################################

function Show-MainMenu {
    Write-Host "Main Menu:"
    Write-Host "1. Targeted Enumeration"
    Write-Host "2. General AD Information"
    Write-Host "3. AD Users Information"
    Write-Host "4. AD Admin Information"
    Write-Host "5. Kerberos Enumeration"
    Write-Host "6. Password Policy"
    Write-Host "7. Retrieve gMSAs Information"
    Write-Host "8. Run All Checks (except Targeted Enumeration)"
    $choice = Read-Host "Enter your choice (1/2/3/4/5/6/7/8)"
    return $choice
}

$mainChoice = Show-MainMenu

switch ($mainChoice) {
    1 {
        Show-TargetedEnumerationMenu
    }
    2 {
        Get-GeneralADInformation
    }
    3 {
        Get-ADUsersInformation
    }
    4 {
        Get-ADAdminInformation
    }
    5 {
        Get-KerberosEnumeration
    }
    6 {
        Get-PasswordPolicy
    }
    7 {
        Get-gMSA
    }
    8 {
        Run-AllChecks
    }
    default {
        Write-Host "Invalid choice. Exiting."
        exit
    }
}
