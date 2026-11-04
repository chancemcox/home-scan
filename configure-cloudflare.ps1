param([switch]$LocalDnsOnly)
$ErrorActionPreference = 'Stop'
Write-Host 'Cloudflare setup for *.house.chancecox.com'
Write-Host 'Token permissions: Zone Read, DNS Edit; plus Cloudflare Tunnel Edit for tunnels.'
$secure = Read-Host 'Cloudflare API token (hidden)' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    if (!$plain) { throw 'Token cannot be empty.' }
    $payload = @{api_token=$plain;tunnel=(!$LocalDnsOnly)} | ConvertTo-Json -Compress
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
Write-Host 'Tunnel HTTPS for *.house.chancecox.com requires matching Cloudflare certificate coverage.'
