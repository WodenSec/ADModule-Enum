# Global variable to store discovered domains and their DCs
$global:DiscoveredDomains = @()

function Get-DomainTrustsAndDCs {
    param (
        [string]$domain = $env:USERDNSDOMAIN,  # Default to current domain
        [string[]]$visitedDomains = @()         # Track visited domains to avoid loops
    )

    # If we've already visited this domain, skip it
    if ($visitedDomains -contains $domain) {
        return
    }

    # Mark this domain as visited
    $visitedDomains += $domain

    Write-Host "[*] Querying $domain" -ForegroundColor Green

    # Step 1: Get the current domain's Domain Controllers
    Write-Host "[*] Getting domain controllers for $domain" -ForegroundColor Cyan
    try {
        $domainControllers = Get-ADDomainController -DomainName $domain -Discover | Select Domain, Forest, HostName, IPv4Address, Name, Site
        if ($domainControllers) {
            $domainControllers | Format-List

            # Store the domain and its domain controllers in the global list
            foreach ($dc in $domainControllers) {
                $global:DiscoveredDomains += [pscustomobject]@{
                    Domain          = $domain
                    Hostname        = $dc.HostName
                    IPv4Address     = $dc.IPv4Address
                }
            }
        } else {
            Write-Host "[!] No domain controllers found for $domain" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Could not retrieve domain controllers for $domain" -ForegroundColor Red
        return
    }

    # Step 2: Get trusts for the current domain
    Write-Host "[*] Getting trusts for $domain" -ForegroundColor Cyan
    try {
        $trusts = Get-ADTrust -Server $domain -Filter * | Select Direction, Name, Source, Target
        if ($trusts) {
            $trusts | Format-List
        } else {
            Write-Host "[!] No trusts found for $domain" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Could not retrieve trusts for $domain" -ForegroundColor Red
        return
    }

    # Step 3: Process each trusted domain recursively
    $trusts | ForEach-Object {
        $trustedDomain = $_.Target
        Get-DomainTrustsAndDCs -domain $trustedDomain -visitedDomains $visitedDomains
    }
}

# Start the script for the current domain
Get-DomainTrustsAndDCs

# Final Summary of Discovered Domains and their Domain Controllers
Write-Host "`n[*] Final Summary of Discovered Domains and their Domain Controllers:" -ForegroundColor Green
if ($global:DiscoveredDomains.Count -gt 0) {
    $global:DiscoveredDomains | Format-Table Domain, Hostname, IPv4Address -AutoSize
} else {
    Write-Host "No domains discovered." -ForegroundColor Yellow
}
