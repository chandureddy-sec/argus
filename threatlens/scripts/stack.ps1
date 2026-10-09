<#
ThreatLens stack helper for Windows. Run it through tl.cmd from the threatlens folder:

    .\tl up        start everything (starts Docker Desktop if needed)
    .\tl up --build   same, rebuilding the image after code changes
    .\tl down      stop everything (data is kept)
    .\tl status    containers and readiness
    .\tl logs      follow worker and API logs (Ctrl+C to stop)
    .\tl key NAME [viewer|analyst|admin]   create an API key
    .\tl <anything else>   runs the threatlens CLI inside the stack,
                           e.g.  .\tl sources   .\tl collect nvd   .\tl keys list

It finds docker.exe even when the terminal was opened before Docker was
installed (stale PATH), and creates .env with a random database password on
first use.
#>
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)][string[]]$Rest = @()
)

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$DesktopExe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'

function Find-Docker {
    $cmd = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $exe = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    if (Test-Path $exe) {
        $env:Path = (Split-Path $exe) + ';' + $env:Path   # helpers (compose, credential store) live here too
        return $exe
    }
    Write-Host 'Docker Desktop is not installed. Install it with:' -ForegroundColor Red
    Write-Host '  winget install -e --id Docker.DockerDesktop'
    exit 1
}

function Test-Engine([string]$Docker) {
    cmd /c "`"$Docker`" info >nul 2>&1"
    return ($LASTEXITCODE -eq 0)
}

function Start-Engine([string]$Docker) {
    if (Test-Engine $Docker) { return }
    if (-not (Get-Process 'Docker Desktop' -ErrorAction SilentlyContinue)) {
        if (-not (Test-Path $DesktopExe)) { Write-Host "Docker Desktop not found at $DesktopExe" -ForegroundColor Red; exit 1 }
        Write-Host 'Starting Docker Desktop...'
        Start-Process $DesktopExe
    }
    Write-Host -NoNewline 'Waiting for the Docker engine'
    for ($i = 0; $i -lt 90; $i++) {
        if (Test-Engine $Docker) { Write-Host ' ready.'; return }
        Write-Host -NoNewline '.'
        Start-Sleep -Seconds 2
    }
    Write-Host ''
    Write-Host 'The Docker engine did not start within 3 minutes. Open Docker Desktop and check for a prompt (licence, WSL update).' -ForegroundColor Red
    exit 1
}

function New-Secret {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Initialize-Env {
    if (Test-Path '.env') { return }
    $lines = Get-Content '.env.example' | ForEach-Object {
        if ($_ -like 'POSTGRES_PASSWORD=*') { "POSTGRES_PASSWORD=$(New-Secret)" } else { $_ }
    }
    [IO.File]::WriteAllLines((Join-Path $Root '.env'), [string[]]$lines)   # UTF-8 without BOM
    Write-Host 'Created .env with a random database password (git-ignored).'
}

function Show-Ready {
    try {
        $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/readyz' -TimeoutSec 5
        $checks = ($r.checks.PSObject.Properties | ForEach-Object { "$($_.Name)=$(if ($_.Value.ok) {'ok'} else {'FAIL'})" }) -join ', '
        Write-Host "API: $($r.status) ($checks)  http://127.0.0.1:8000/docs" -ForegroundColor Green
    } catch {
        Write-Host 'API: not answering on http://127.0.0.1:8000 yet' -ForegroundColor Yellow
    }
}

function Invoke-Compose([string]$Docker, [string[]]$Arguments) {
    & $Docker compose @Arguments
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

switch ($Command) {
    { $_ -in 'help', '-h', '--help', '/?' } {
        $text = Get-Content $PSCommandPath -Raw
        Write-Host $text.Substring(2, $text.IndexOf('#>') - 2).Trim()
        exit 0
    }
    'up' {
        $docker = Find-Docker
        Initialize-Env
        Start-Engine $docker
        $build = if ($Rest -contains '--build') { @('--build') } else { @() }
        Write-Host 'Starting the stack (first run builds the image: a few minutes)...'
        Invoke-Compose $docker (@('--progress', 'quiet', 'up', '-d', '--wait', '--wait-timeout', '300') + $build)
        Invoke-Compose $docker @('ps', '--format', 'table {{.Service}}\t{{.Status}}')
        Show-Ready
        Write-Host "Next: .\tl key me admin   (prints an API key)   .\tl sources   .\tl logs"
    }
    'down' {
        $docker = Find-Docker
        if (-not (Test-Engine $docker)) { Write-Host 'Docker is not running; nothing to stop.'; exit 0 }
        Invoke-Compose $docker @('down')
    }
    'status' {
        $docker = Find-Docker
        if (-not (Test-Engine $docker)) { Write-Host 'Docker engine: not running  (start everything with: .\tl up)' -ForegroundColor Yellow; exit 0 }
        Invoke-Compose $docker @('ps', '-a', '--format', 'table {{.Service}}\t{{.Status}}')
        Show-Ready
    }
    'logs' {
        $docker = Find-Docker
        $services = if ($Rest.Count) { $Rest } else { @('worker', 'api') }
        & $docker compose logs -f --tail 50 @services
    }
    'key' {
        $docker = Find-Docker
        if (-not $Rest.Count) { Write-Host 'usage: .\tl key NAME [viewer|analyst|admin]'; exit 2 }
        $role = if ($Rest.Count -ge 2) { $Rest[1] } else { 'viewer' }
        Invoke-Compose $docker @('exec', '-T', 'worker', 'threatlens', 'keys', 'create', $Rest[0], '--role', $role)
    }
    default {
        # Anything else is a threatlens CLI command, run inside the worker container.
        $docker = Find-Docker
        if (-not (Test-Engine $docker)) { Write-Host 'The stack is not running. Start it with: .\tl up' -ForegroundColor Yellow; exit 1 }
        Invoke-Compose $docker (@('exec', '-T', 'worker', 'threatlens', $Command) + $Rest)
    }
}
