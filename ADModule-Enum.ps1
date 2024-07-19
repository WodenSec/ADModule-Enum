########################################
#                                      #
#            Initialization            #
#                                      #
########################################

# Get current user and domain
$currentUser = $env:USERNAME
$currentDomain = $env:USERDNSDOMAIN
$domainSID = (Get-ADDomain).DomainSID.Value

# Mapping of GUIDs to permissions
$guidMapping = @{
    "ab721a53-1e2f-11d0-9819-00aa0040529b" = "User-Change-Password"
    "bf967a68-0de6-11d0-a285-00aa003049e2" = "User-Account-Control"
    # Need to add more mappings
}

########################################
#                                      #
#    Utility Functions Declaration     #
#                                      #
########################################

# Function to write messages in yellow
function Write-Yellow {
    param (
        [string]$message
    )
    Write-Host -ForegroundColor Yellow $message
}

# Function to get group membership recursively
function Get-ADPrincipalGroupMembershipRecursive {
    param (
        [string]$SamAccountName
    )

    Write-Yellow "Getting group membership recursively for: $SamAccountName"
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

    Write-Yellow "Getting group members recursively for: $groupDN"
    $members = Get-ADGroupMember -Identity $groupDN
    foreach ($member in $members) {
        if ($member.objectClass -eq "user") {
            Get-ADUser -Identity $member.SamAccountName -Properties * | Select SamAccountName, Description, Enabled, PasswordLastSet | Format-List
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
        Write-Yellow "User $username found in AD."
        return $true
    } catch {
        Write-Yellow "User $username does not exist in AD."
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

    $samAccountName = $identityReference.Split('\')[1]
    Write-Yellow "Getting Identity Reference Class for: $samAccountName"

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

    Write-Yellow "Getting ACLs for object: $objectDN"
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
                Write-Host "Enumerating current user: $targetUser"
                Run-TargetedEnumeration -targetUser $targetUser
            } else {
                Write-Host "Current user $currentUser does not exist in AD (probably a local user)."
            }
        }
        2 {
            # Enumerate specific user
            $specificUser = Read-Host "Enter the username of the specific user"
            if (Validate-User -username $specificUser) {
                $targetUser = $specificUser
                Write-Host "Enumerating specific user: $targetUser"
                Run-TargetedEnumeration -targetUser $targetUser
            } else {
                Write-Host "User $specificUser does not exist in AD."
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

    Write-Host "Starting targeted enumeration for user: $targetUser"
    Write-Yellow "Starting targeted enumeration for user: $targetUser"
    $targetDN = (Get-ADUser -Identity $targetUser | Select DistinguishedName).DistinguishedName

    # Get detailed information about the target user
    Write-Yellow "Getting detailed information about the user: $targetUser"
    $userDetails = Get-ADUser -Identity $targetUser -Properties *
    $userDetailsOutput = $userDetails | Select SamAccountName, Name, EmailAddress, DistinguishedName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired | Format-List | Out-String
    Write-Host $userDetailsOutput

    # Get group memberships recursively
    Write-Yellow "Getting group memberships recursively for user: $targetUser"
    $groupMembershipOutput = Get-ADPrincipalGroupMembershipRecursive -SamAccountName $targetUser | Out-String
    Write-Host $groupMembershipOutput

    # Get ACLs on this user
    Write-Yellow "Getting ACLs for user: $targetUser"
    $aclOutput = Get-TranslatedACLs -objectDN $targetDN | Format-List | Out-String
    Write-Host $aclOutput
}
########################################
#                                      #
#      Get General AD Information      #
#                                      #
########################################

function Get-GeneralADInformation {
    Write-Host "General AD Information:"
    Write-Yellow "Fetching General AD Information..."
    $domainInfo = Get-ADDomain | Select DistinguishedName, DomainMode, DNSRoot, NetBIOSName, InfrastructureMaster, DomainSID | Format-List | Out-String
    Write-Host $domainInfo

    $forestInfo = Get-ADForest | Select Domains, DomainNamingMaster, ForestMode | Format-List | Out-String
    Write-Host $forestInfo

    $trustsInfo = Get-ADTrust -Filter * | Select Direction, Name, Source, Target | Format-List | Out-String
    Write-Host $trustsInfo
}

########################################
#                                      #
#        Get AD User Information       #
#                                      #
########################################

function Get-ADUsersInformation {
    Write-Host "AD Users Information:"
    Write-Yellow "Fetching AD Users Information..."

    # Get all users (for password spray)
    Write-Yellow "Fetching all users..."
    $allUsers = Get-ADUser -Filter * | Select SamAccountName | Out-String
    Write-Host $allUsers

    # Get users with description (look for passwords)
    Write-Yellow "Fetching users with description..."
    $usersWithDescription = Get-ADUser -Filter * -Properties Description | Where-Object { $_.Description } | Select SamAccountName, Description, Enabled | Format-Table -AutoSize | Out-String
    Write-Host $usersWithDescription
}

########################################
#                                      #
#       Get AD Admin Information       #
#                                      #
########################################

function Get-ADAdminInformation {
    Write-Host "AD Admin Information:"
    Write-Yellow "Fetching AD Admin Information..."

    # Look for all admins including shadow admins
    Write-Yellow "Fetching all administrators..."
    $admins = Get-ADUser -Filter {AdminCount -eq 1} | Select SamAccountName | Out-String
    Write-Host $admins

    # Get members of the Domain Admins group
    Write-Yellow "Fetching Domain Admins group members..."
    $domainAdminDN = (Get-ADGroup -Filter "SID -eq '$domainSID-512'").DistinguishedName
    $domainAdmins = Get-GroupMembersRecursive -groupDN $domainAdminDN | Out-String
    Write-Host $domainAdmins
}

########################################
#                                      #
#          Kerberos Settings           #
#                                      #
########################################

function Get-KerberosEnumeration {
    Write-Host "Kerberos Enumeration:"
    Write-Yellow "Fetching Kerberos Enumeration Information..."

    # List SPNs for Kerberoasting
    Write-Yellow "Fetching SPNs for Kerberoasting..."
    $spns = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, PasswordLastSet | Select SamAccountName, ServicePrincipalName, PasswordLastSet, Enabled | Format-List | Out-String
    Write-Host $spns
    
    # Get AS-REP roastable users
    Write-Yellow "Fetching AS-REP roastable users..."
    $asreproastableUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth, PasswordLastSet | Select SamAccountName, PasswordLastSet, Enabled | Format-List | Out-String
    Write-Host $asreproastableUsers

    # Unconstrained delegation (computer and user)
    Write-Yellow "Fetching unconstrained delegation for computers and users..."
    $unconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $True} | Select DNSHostName | Out-String
    Write-Host $unconstrainedComputers

    $unconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $True} | Out-String
    Write-Host $unconstrainedUsers

    # Constrained delegation
    Write-Yellow "Fetching constrained delegation information..."
    $constrainedDelegation = Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * | Select DistinguishedName, sAMAccountName, ObjectClass, msDS-AllowedToDelegateTo | Format-List | Out-String
    Write-Host $constrainedDelegation
}

########################################
#                                      #
#           Run All Checks             #
#                                      #
########################################

function Run-AllChecks {
    Write-Yellow "Running all checks..."
    Get-GeneralADInformation
    Get-ADUsersInformation
    Get-ADAdminInformation
    Get-KerberosEnumeration
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
    Write-Host "6. Run All Checks (except Targeted Enumeration)"
    $choice = Read-Host "Enter your choice (1/2/3/4/5/6)"
    return $choice
}

$mainChoice = Show-MainMenu

switch ($mainChoice) {
    1 {
        # Call Targeted Enumeration Sub-Menu
        Show-TargetedEnumerationMenu
    }
    2 {
        # Call General AD Information
        Get-GeneralADInformation
    }
    3 {
        # Call AD Users Information
        Get-ADUsersInformation
    }
    4 {
        # Call AD Admin Information
        Get-ADAdminInformation
    }
    5 {
        # Call Kerberos Enumeration
        Get-KerberosEnumeration
    }
    6 {
        # Run All Checks
        Run-AllChecks
    }
    default {
        Write-Host "Invalid choice. Exiting."
        exit
    }
}
