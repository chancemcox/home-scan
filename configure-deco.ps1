param([string]$HostAddress = '192.168.86.233')
$ErrorActionPreference = 'Stop'
$secretDir = Join-Path $PSScriptRoot '.secrets'
New-Item -ItemType Directory -Force -Path $secretDir | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $secretDir /inheritance:r /grant:r "${identity}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the credential folder.' }
Write-Host "Enter the password for the local Deco web interface at http://$HostAddress."
$password = Read-Host 'Deco owner password (hidden)' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    if (!$plain) { throw 'Password cannot be empty.' }
    $config = @{host=$HostAddress;username='admin';password=$plain} | ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $secretDir 'deco.json'), $config, [Text.UTF8Encoding]::new($false))
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    $plain=$null; $config=$null
}
& docker compose --project-directory $PSScriptRoot exec -T homescan python -c "from pathlib import Path; Path('/data/deco-auth-retry').unlink(missing_ok=True)"
& docker compose --project-directory $PSScriptRoot exec -T homescan python deco.py
Write-Host 'Deco configured. The next one-minute scan will import clients if the connection test succeeded.'