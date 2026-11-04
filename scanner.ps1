param([Parameter(Mandatory=$true)][string]$Subnet, [string]$Server = 'http://localhost', [string]$Token = $env:INGEST_TOKEN, [switch]$Once)
$ErrorActionPreference = 'Stop'
if (!$Token) {
    $envFile = Join-Path $PSScriptRoot '.env'
    if (Test-Path $envFile) { $Token = ((Get-Content $envFile | Where-Object { $_ -match '^INGEST_TOKEN=' }) -replace '^INGEST_TOKEN=', '').Trim() }
}
if (!$Token) { throw 'Set INGEST_TOKEN or create .env first.' }
# Accept comma-separated /24 networks; collect one combined snapshot per minute.
$prefixes = @(foreach ($network in ($Subnet -split ',' | Select-Object -Unique)) {
    $network = $network.Trim()
    if ($network -notmatch '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.0/24$') { throw "Use a /24 subnet: $network" }
    $prefix = $Matches[1]
    $octets = ([System.Net.IPAddress]::Parse("$prefix.0")).GetAddressBytes()
    if (!(($octets[0] -eq 10) -or ($octets[0] -eq 192 -and $octets[1] -eq 168) -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31))) { throw 'Use private home network subnets.' }
    $prefix
})
if ($prefixes.Count -gt 8) { throw 'At most eight /24 subnets are supported.' }
while ($true) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $hostsFound = @()
    $scanError = $null
    try {
        $pings = @(foreach ($prefix in $prefixes) { 1..254 | ForEach-Object {
            $ping = [System.Net.NetworkInformation.Ping]::new()
            [pscustomobject]@{ IPAddress="$prefix.$_"; Ping=$ping; Task=$ping.SendPingAsync("$prefix.$_",700) }
        } })
        foreach ($entry in $pings) { try { $null = $entry.Task.GetAwaiter().GetResult() } finally { $entry.Ping.Dispose() } }
        $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 | Where-Object { (($_.IPAddress -replace '\.\d+$','') -in $prefixes) -and $_.State -in @('Reachable','Stale','Delay','Probe','Permanent') -and $_.LinkLayerAddress -notmatch '^(00-|FF-)' })
        $local = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { (($_.IPAddress -replace '\.\d+$','') -in $prefixes) } | ForEach-Object {
            $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex
            [pscustomobject]@{ IPAddress=$_.IPAddress; LinkLayerAddress=$adapter.MacAddress }
        })
        $responders = @(foreach ($entry in $pings) {
            if ($entry.Task.Status -eq 'RanToCompletion' -and $entry.Task.Result.Status -eq 'Success') {
                [pscustomobject]@{ IPAddress=$entry.IPAddress; LinkLayerAddress='' }
            }
        })
        $byIP = @{}
        foreach ($n in @($responders + $neighbors + $local)) { $byIP[$n.IPAddress] = $n }
        foreach ($n in $byIP.Values) {
            $name = ''
            try {
                $dns = [System.Net.Dns]::GetHostEntryAsync($n.IPAddress)
                if ($dns.Wait(200)) { $name = $dns.Result.HostName }
            } catch { }
            $hostsFound += @{ ip=$n.IPAddress; hostname=$name; mac=$n.LinkLayerAddress.Replace('-',':') }
        }
    } catch { $scanError = $_.Exception.Message }
    try {
        # Combine both network sweeps and router inventory into a single snapshot.
        $networkHosts = @($hostsFound)
        $deco = $null

        # Deco is optional. Timeouts, auth failures, and disabled support must not
        # prevent the network scan from being recorded.
        try {
            $raw = & docker compose --project-directory $PSScriptRoot exec -T homescan python deco.py 2>$null
            if ($LASTEXITCODE -ne 0) { throw 'Deco helper unavailable' }
            $deco = ($raw -join "`n") | ConvertFrom-Json
            if ($deco.enabled -and $deco.available) {
                $merged = @{}
                foreach ($hostEntry in $hostsFound) { $merged[$hostEntry.ip] = $hostEntry }
                foreach ($client in @($deco.hosts)) {
                    if ($null -eq $client -or -not $client.ip) { continue }
                    $existing = $merged[$client.ip]
                    $merged[$client.ip] = @{
                        ip = $client.ip
                        hostname = $(if ($client.hostname) { $client.hostname } elseif ($existing) { $existing.hostname } else { '' })
                        mac = $(if ($client.mac) { $client.mac } elseif ($existing) { $existing.mac } else { '' })
                    }
                }
                $hostsFound = @($merged.Values)
            }
        } catch { $deco = $null }

        $sources = @(@{source='network';hosts=@($networkHosts);error=$scanError})
        if ($deco -and $deco.enabled -and $deco.available) {
            $sources += @{source='deco';hosts=@($deco.hosts | Where-Object { $_ -and $_.ip });error=$null}
        }
        $payload = @{hosts=@($hostsFound);sources=@($sources);error=$scanError;warning=$null} | ConvertTo-Json -Depth 4 -Compress
        Invoke-RestMethod -Method Post -Uri "$Server/api/scan" -Headers @{Authorization="Bearer $Token"} -ContentType 'application/json' -Body $payload -TimeoutSec 10 | Out-Null
        Write-Host "$(Get-Date -Format s) Recorded $($hostsFound.Count) devices. $scanError"
    } catch { Write-Warning $_.Exception.Message }
    if ($Once) { break }
    $remaining = 60000 - $timer.ElapsedMilliseconds
    if ($remaining -gt 0) { Start-Sleep -Milliseconds $remaining }
}

