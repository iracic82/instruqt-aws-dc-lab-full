# DNS Restore Script
# Supports: NS, A, AAAA, CNAME, MX, PTR, TXT, SPF, SRV (SOA excluded)
# Automatically creates reverse DNS zones for A records (based on /24)

param(
    [switch]$DryRun
)

# Logs a message with a timestamp to the console
function Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$timestamp - $Message"
}

# Logs a message with a timestamp to the debug log file
$logPath = "dns_restore_debug_$(Get-Date -Format yyyyMMdd_HHmmss).log"
function DebugLog {
    param([string]$Message)
    Add-Content -Path $logPath -Value "$((Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) - $Message"
}

# Define input paths
$zoneListPath = "zone_list.txt"
$zoneDir = "."
$zones = Get-Content $zoneListPath

# Initialize counters and reverse zone tracker
$recordCounters = @{ "NS"=0; "A"=0; "AAAA"=0; "CNAME"=0; "MX"=0; "PTR"=0; "TXT"=0; "SRV"=0 }
$skippedLines = 0
$createdReverseZones = @{}

# Process each DNS zone
foreach ($zone in $zones) {
    $zoneFile = Join-Path $zoneDir "$zone.dns"
    if (-Not (Test-Path $zoneFile)) {
        Log "Zone file not found: $zoneFile"
        continue
    }

    # Create zone if missing
    if (-Not (Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue)) {
        Log "Creating missing zone: $zone"
        if (-Not $DryRun) {
            Add-DnsServerPrimaryZone -Name $zone -ReplicationScope Domain
        }
    }

    Log "Processing zone: $zone"
    $lines = Get-Content $zoneFile
    $lineNum = 0

    foreach ($line in $lines) {
        $lineNum++
        $line = ($line -replace "\t+", " ") -replace "\s{2,}", " "
        $line = $line.Trim()
        if ($line -match "^\s*$" -or $line -match "^;.*") { continue }

        try {
            # NS record
            if ($line -match "^\s*(\S+)\s+(?:(\d+)\s+)?(?:IN\s+)?NS\s+(\S+)") {
                $name, $target = $matches[1], $matches[3]
                $recordCounters["NS"]++
                if (-Not $DryRun) {
                    if (-Not (Get-DnsServerResourceRecord -ZoneName $zone -Name $name -RRType "NS" -ErrorAction SilentlyContinue)) {
                        try { Add-DnsServerResourceRecord -ZoneName $zone -NS -Name $name -NameServer $target -ErrorAction Stop }
                        catch { DebugLog ("Error adding NS [$name -> $target] in ${zone}: {0}" -f $_.Exception.Message) }
                    }
                }
            }

            # A record with PTR + reverse zone creation
            elseif ($line -match "^\s*(\S+)\s+(?:(\d+)\s+)?(?:IN\s+)?A\s+(\d+\.\d+\.\d+\.\d+)") {
                $name, $ip = $matches[1], $matches[3]
                $recordCounters["A"]++
                $ipParts = $ip.Split('.')
                if ($ipParts.Count -ne 4) { DebugLog "Invalid IP format [$ip] at line $lineNum"; continue }
                $reverseZone = "$($ipParts[2]).$($ipParts[1]).$($ipParts[0]).in-addr.arpa"
                $ptrName = $ipParts[3]
                $addARecordSuccess = $true
                $lastError = $null

                if (-Not $DryRun) {
                    try {
                        if (-Not (Get-DnsServerResourceRecord -ZoneName $zone -Name $name -RRType "A" -ErrorAction SilentlyContinue)) {
                            Add-DnsServerResourceRecordA -ZoneName $zone -Name $name -IPv4Address $ip -ErrorAction Stop
                        }
                    } catch {
                        $addARecordSuccess = $false
                        $lastError = $_.Exception.Message
                        if ($lastError -like "*already exists*") {
                            DebugLog ("A record [$name -> $ip] in ${zone} already exists")
                        } else {
                            DebugLog ("Error adding A record [$name -> $ip] in ${zone}: {0}" -f $lastError)
                        }
                    }

                    # Reverse zone creation
                    if (-Not $createdReverseZones.ContainsKey($reverseZone)) {
                        if (-Not (Get-DnsServerZone -Name $reverseZone -ErrorAction SilentlyContinue)) {
                            try {
                                $network = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).0/24"
                                Add-DnsServerPrimaryZone -NetworkId $network -ReplicationScope Domain -ErrorAction Stop
                                $createdReverseZones[$reverseZone] = $true
                            } catch {
                                DebugLog ("Error creating reverse zone ${reverseZone}: {0}" -f $_.Exception.Message)
                            }
                        } else {
                            $createdReverseZones[$reverseZone] = $true
                        }
                    }

                    # PTR creation
                    if ($addARecordSuccess -or ($lastError -like "*already exists*")) {
                        if (-Not (Get-DnsServerResourceRecord -ZoneName $reverseZone -Name $ptrName -RRType "PTR" -ErrorAction SilentlyContinue)) {
                            try {
                                Add-DnsServerResourceRecordPtr -Name $ptrName -ZoneName $reverseZone -PtrDomainName "$name.$zone." -ErrorAction Stop
                                $recordCounters["PTR"]++
                            } catch {
                                DebugLog ("Error adding PTR [$ptrName -> $name.$zone] in ${reverseZone}: {0}" -f $_.Exception.Message)
                            }
                        } else {
                            DebugLog ("PTR record [$ptrName -> $name.$zone] already exists in ${reverseZone}")
                        }
                    }
                }
            }

            # SRV record with fallback
            elseif ($line -match "^\s*(\S+)\s+(?:(\d+)\s+)?(?:IN\s+)?SRV\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)") {
                $name, $priority, $weight, $port, $target = $matches[1], [int]$matches[3], [int]$matches[4], [int]$matches[5], $matches[6]
                $recordCounters["SRV"]++
                if (-Not $DryRun) {
                    try {
                        Add-DnsServerResourceRecordSrv -ZoneName $zone -Name $name -DomainName $target -Priority $priority -Weight $weight -Port $port -ErrorAction Stop
                    } catch {
                        DebugLog ("Fallback to dnscmd for SRV [$name -> $target] in ${zone}")
                        Invoke-Expression "dnscmd $env:COMPUTERNAME /RecordAdd $zone $name SRV $priority $weight $port $target"
                    }
                }
            }

        } catch {
            DebugLog ("Exception on line [$lineNum] in ${zoneFile}: {0}" -f $_.Exception.Message)
        }
    }

    if (-Not $DryRun) {
        try {
            Log "Reloading zone: $zone"
            Invoke-Expression "dnscmd /ZoneReload $zone"
        } catch {
            DebugLog ("Zone reload failed for ${zone}: {0}" -f $_.Exception.Message)
        }
    }
}

# Final summary output
Log "===== DNS Restore Summary ====="
Log ("Zones Processed    : {0}" -f $zones.Count)
Log ("Records Processed  : {0}" -f ($recordCounters.Values | Measure-Object -Sum | Select-Object -ExpandProperty Sum))
foreach ($type in $recordCounters.Keys) { Log ("{0}: {1}" -f $type, $recordCounters[$type]) }
Log ("Skipped Lines      : {0}" -f $skippedLines)
Log "==============================="
