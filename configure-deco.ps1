param([string]$HostAddress = '192.168.86.233', [switch]$Disabled)
$ErrorActionPreference = 'Stop'
Write-Host 'Configure Deco support for HomeScan (stored in the app data volume).'
$password = ''
if (!$Disabled) {
    Write-Host "Enter the password for the local Deco web interface at http://$HostAddress."
    $secure = Read-Host 'Deco owner password (hidden)' -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        if (!$password) { throw 'Password cannot be empty.' }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        $secure = $null
    }
}
$payload = @{enabled=(-not $Disabled);host=$HostAddress;username='admin';password=$password} | ConvertTo-Json -Compress
$raw = $payload | & docker compose --project-directory $PSScriptRoot exec -T homescan node lib/deco.js save
if ($LASTEXITCODE -ne 0) { throw (($raw -join "`n")) }
$result = ($raw -join "`n") | ConvertFrom-Json
Write-Host ($(if ($result.enabled) { "Deco enabled for $($result.host)." } else { 'Deco support turned off.' }))
if ($result.enabled) {
    & docker compose --project-directory $PSScriptRoot exec -T homescan node lib/deco.js | Out-Host
    Write-Host 'The next one-minute scan will import clients if the connection test succeeded.'
}
$password = $null; $payload = $null
