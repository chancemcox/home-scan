param([switch]$LocalDnsOnly, [string]$Suffix = '')
$ErrorActionPreference = 'Stop'
Write-Host 'Cloudflare setup for HomeScan'
Write-Host 'Token permissions: Zone Read, DNS Edit; Cloudflare Tunnel Edit for tunnels; D1 Edit for shared DB.'
$secure = Read-Host 'Cloudflare API token (hidden)' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    if (!$plain) { throw 'Token cannot be empty.' }
    $body = @{api_token=$plain;tunnel=(!$LocalDnsOnly);d1=$true}
    if ($Suffix) { $body.suffix = $Suffix }
    $payload = $body | ConvertTo-Json -Compress
    $raw = $payload | & docker compose --project-directory $PSScriptRoot exec -T homescan python cloudflare_sync.py setup
    if ($LASTEXITCODE -ne 0) { throw (($raw -join "`n") | ConvertFrom-Json).error }
    $result = ($raw -join "`n") | ConvertFrom-Json
    if ($result.error) { throw $result.error }
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    $plain=$null; $payload=$null; $secure=$null
}
if ($result.tunnel_configured) {
    & docker compose --project-directory $PSScriptRoot --profile cloudflare up -d cloudflared
    if ($LASTEXITCODE -ne 0) { throw 'Cloudflare is configured, but the tunnel connector could not start.' }
}
Write-Host "Connected to $($result.zone). Saved routes will sync automatically within a minute."
Write-Host 'Set your base domain in Settings if needed. Deep tunnel HTTPS names need matching certificate coverage.'
