function Get-ADMap {
    param (
        [string]$domain = $env:USERDNSDOMAIN,  # Default to current domain
        [string[]]$visitedDomains = @(),        # Track visited domains to avoid loops
        [ref]$DiscoveredDomains = [ref]@(),     # Store discovered domains and DCs
        [switch]$Verbose                         # Enable or disable verbose output
    )

    # Function to handle verbose output manually
    function Write-VerboseManual {
        param ([string]$message, [string]$color)
        if ($Verbose) {
            Write-Host $message -ForegroundColor $color
        }
    }

    # If we've already visited this domain, skip it
    if ($visitedDomains -contains $domain) {
        return
    }

    # Mark this domain as visited
    $visitedDomains += $domain

    Write-VerboseManual "[*] Querying $domain" "Green"

    # Step 1: Get the current domain's info
    Write-VerboseManual "[*] Getting domain controllers for $domain" "Cyan"
    $hostname = "Unavailable"
    $ipv4 = "Unavailable"
    $domainSID = "Unavailable"
    $forest = "Unavailable"
    $netbiosName = "Unavailable"
    $trustInfo = "No trusts found"
    
    try {
        $domainInfo = Get-ADDomain -Server $domain -ErrorAction Stop
        $domainSID = $domainInfo.DomainSID.Value
        $netbiosName = $domainInfo.NetBIOSName 

        $domainControllers = Get-ADDomainController -DomainName $domain -Discover -ErrorAction Stop | Select Domain, Forest, HostName, IPv4Address, Name
        if ($domainControllers) {
            foreach ($dc in $domainControllers) {
                $hostname = $dc.HostName -join ","  # Treat hostname as a string
                $ipv4 = $dc.IPv4Address
                $forest = $dc.Forest
            }
        }
    } catch {
        Write-VerboseManual "[!] Could not retrieve information for $domain" "Red"
    }

    # Step 2: Get trusts for the current domain
    Write-VerboseManual "[*] Getting trusts for $domain" "Cyan"
    try {
        $trusts = Get-ADTrust -Server $domain -Filter * -ErrorAction Stop
        if ($trusts) {
            $trustInfo = ""
            foreach ($trust in $trusts) {
                $trustInfo += "`nDirection: $($trust.Direction), Name: $($trust.Name), Source: $($trust.Source), Target: $($trust.Target)`n"
            }
            $trustInfo = $trustInfo.TrimEnd()  # Remove last newline
        }
    } catch {
        Write-VerboseManual "[!] Could not retrieve trusts for $domain" "Red"
    }

    # Store the values in the global list
    $DiscoveredDomains.Value += [pscustomobject]@{
        Domain      = $domain
        Name        = $netbiosName
        DomainSID   = $domainSID
        Forest      = $forest
        Hostname    = $hostname
        IPv4Address = $ipv4
        Trusts      = $trustInfo
    }

    # Step 3: Process each trusted domain recursively
    $trusts | ForEach-Object {
        $trustedDomain = $_.Target
        Get-ADMap -domain $trustedDomain -visitedDomains $visitedDomains -DiscoveredDomains $DiscoveredDomains -Verbose:$Verbose
    }

    # Summary
    if ($visitedDomains.Count -eq 1) {  # Display the summary at the end of the first recursive call
        Write-Host "`n[*] Summary of discovered domains, their domain controllers, and trust relationships:" -ForegroundColor Green
        if ($DiscoveredDomains.Value.Count -gt 0) {
            $globalSpacing = "----------"
            $DiscoveredDomains.Value | ForEach-Object {
                Write-Host "$globalSpacing"
                Write-Host "Domain: $($_.Domain)"
                Write-Host "NETBIOS Name: $($_.Name)"
                Write-Host "Domain SID: $($_.DomainSID)"
                Write-Host "Forest: $($_.Forest)"
                Write-Host "DC hostname: $($_.Hostname)"
                Write-Host "DC IP: $($_.IPv4Address)"
                Write-Host "Trusts: $($_.Trusts)"
                Write-Host "$globalSpacing"
            }
        } else {
            Write-Host "No domains discovered." -ForegroundColor Yellow
        }
    }
}
