<#
.SYNOPSIS
  Instala o actualiza en Windows las herramientas que necesita SecureFin (y Claude Code).

.DESCRIPTION
  Idempotente: instala lo que falta y actualiza lo que ya existe con winget. Un paquete que falla
  no detiene el resto; al final se muestra un resumen. No toca el repositorio ni los secretos.

  Herramientas: Git, Docker Desktop, Node.js LTS, Python 3.12, VS Code, Claude Code (CLI) y su
  extensión de VS Code, GitHub CLI y, opcionalmente, Wireshark (evidencia E9 de la demo).

.PARAMETER CheckOnly
  Solo informa de qué está instalado y en qué versión; no instala ni actualiza nada.

.PARAMETER SkipWireshark
  No instala Wireshark (solo hace falta para la demo de captura de tráfico).

.EXAMPLE
  # PowerShell COMO ADMINISTRADOR, desde la raíz del repositorio:
  powershell -ExecutionPolicy Bypass -File scripts\setup\install-tools.ps1
  powershell -ExecutionPolicy Bypass -File scripts\setup\install-tools.ps1 -CheckOnly
#>
[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$SkipWireshark
)

$ErrorActionPreference = "Continue"

$packages = @(
    @{ Id = "Git.Git";                       Name = "Git";             Cmd = "git";    Args = "--version" },
    @{ Id = "Docker.DockerDesktop";          Name = "Docker Desktop";  Cmd = "docker"; Args = "--version" },
    @{ Id = "OpenJS.NodeJS.LTS";             Name = "Node.js LTS";     Cmd = "node";   Args = "--version" },
    @{ Id = "Python.Python.3.12";            Name = "Python 3.12";     Cmd = "python"; Args = "--version" },
    @{ Id = "Microsoft.VisualStudioCode";    Name = "VS Code";         Cmd = "code";   Args = "--version" },
    @{ Id = "Anthropic.ClaudeCode";          Name = "Claude Code";     Cmd = "claude"; Args = "--version" },
    @{ Id = "GitHub.cli";                    Name = "GitHub CLI";      Cmd = "gh";     Args = "--version" }
)
if (-not $SkipWireshark) {
    $packages += @{ Id = "WiresharkFoundation.Wireshark"; Name = "Wireshark (opcional)"; Cmd = $null; Args = $null }
}

function Write-Step($text) { Write-Host "`n» $text" -ForegroundColor Cyan }
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Update-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machine;$user"
}
function Get-ToolVersion($pkg) {
    if (-not $pkg.Cmd) { return $null }
    $cmd = Get-Command $pkg.Cmd -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    try { return ((& $pkg.Cmd $pkg.Args 2>$null) | Select-Object -First 1) } catch { return "instalado" }
}
function Test-WingetInstalled($id) {
    $out = winget list --id $id -e --accept-source-agreements --disable-interactivity 2>$null | Out-String
    return $out -match [regex]::Escape($id)
}

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "No se encontró winget. Instala 'App Installer' desde Microsoft Store y vuelve a ejecutar." -ForegroundColor Red
    exit 1
}
if (-not $CheckOnly -and -not (Test-Admin)) {
    Write-Host "Ejecuta este script en PowerShell COMO ADMINISTRADOR (Docker Desktop, WSL y el archivo hosts lo necesitan)." -ForegroundColor Yellow
    exit 1
}

$summary = @()
foreach ($pkg in $packages) {
    Write-Step $pkg.Name
    $installed = Test-WingetInstalled $pkg.Id
    if ($CheckOnly) {
        $v = Get-ToolVersion $pkg
        $state = if ($installed) { "instalado" } elseif ($v) { "en PATH (no gestionado por winget)" } else { "FALTA" }
        $summary += [pscustomobject]@{ Herramienta = $pkg.Name; Estado = $state; Version = $v }
        continue
    }
    $existing = Get-ToolVersion $pkg
    if ($installed) {
        winget upgrade --id $pkg.Id -e --silent --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-Host
        $action = "actualizado (o ya estaba al día)"
    } elseif ($existing) {
        # Instalado por otra vía (instalador oficial, npm...): no se duplica con winget.
        $action = "ya instalado fuera de winget: se omite (actualízalo con su propio instalador)"
    } else {
        winget install --id $pkg.Id -e --silent --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-Host
        $action = if ($LASTEXITCODE -eq 0) { "instalado" } else { "ERROR al instalar (código $LASTEXITCODE)" }
    }
    Update-SessionPath
    $summary += [pscustomobject]@{ Herramienta = $pkg.Name; Estado = $action; Version = (Get-ToolVersion $pkg) }
}

if (-not $CheckOnly) {
    Write-Step "Extensión de Claude Code para VS Code"
    if (Get-Command code -ErrorAction SilentlyContinue) {
        code --install-extension anthropic.claude-code --force | Out-Host
    } else {
        Write-Host "VS Code aún no está en el PATH de esta sesión: abre VS Code e instala la extensión 'Claude Code' (anthropic.claude-code)." -ForegroundColor Yellow
    }

    Write-Step "WSL 2 (lo necesita Docker Desktop)"
    $wsl = wsl --status 2>$null | Out-String
    if ($LASTEXITCODE -ne 0 -or -not $wsl) {
        wsl --install --no-distribution | Out-Host
        Write-Host "WSL instalado: REINICIA el equipo antes de abrir Docker Desktop." -ForegroundColor Yellow
    } else {
        wsl --update | Out-Host
    }

    Write-Step "Archivo hosts: 127.0.0.1 securefin.local"
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Select-String -Path $hosts -Pattern '^\s*127\.0\.0\.1\s+securefin\.local' -Quiet) {
        Write-Host "Ya estaba." -ForegroundColor Green
    } else {
        Add-Content -Path $hosts -Value "`r`n127.0.0.1 securefin.local"
        Write-Host "Añadido." -ForegroundColor Green
    }
}

Write-Step "Resumen"
$summary | Format-Table -AutoSize | Out-Host
if (-not $CheckOnly) {
    Write-Host "Pasos manuales:" -ForegroundColor Yellow
    Write-Host "  1. Reinicia el equipo si se instaló WSL o Docker Desktop por primera vez."
    Write-Host "  2. Abre Docker Desktop una vez y acepta los términos (deja 'Use WSL 2 based engine' activado)."
    Write-Host "  3. Wireshark: si la captura en loopback no aparece, instala Npcap desde https://npcap.com con"
    Write-Host "     'Support loopback traffic' activado."
    Write-Host "  4. Abre una terminal NUEVA para que el PATH incluya las herramientas instaladas."
}
