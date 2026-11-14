<#
.SYNOPSIS
  Instala las skills de diseño de Claude Code que usa SecureFin, fijadas al commit que se revisó.

.DESCRIPTION
  Cada repositorio se descarga EXACTAMENTE en el commit auditado el 2026-11-13 (se verifica el SHA;
  si no coincide, esa skill no se instala). Solo se copian las carpetas de la skill a
  ~/.claude/skills. No se ejecuta ningún script de los repositorios.

  Notas de seguridad (detalle en CLAUDE.md):
  - impeccable descarga y ejecuta su motor nativo (impeccable.exe) en el primer uso, verificado por
    SHA-256; autorizado por el usuario.
  - huashu-design y design-taste-frontend tienen scripts que usan red (fotos de stock, TTS de
    ByteDance solo con --yes); sus plantillas cargan Google Fonts: no copiar a SecureFin (CSP).

  Las skills de Spec Kit (speckit-*) ya viajan con el repositorio en .claude/skills.

.PARAMETER Destination
  Carpeta de skills de destino. Por defecto, $HOME\.claude\skills.

.PARAMETER Force
  Reemplaza skills que ya existan con contenido (por defecto se omiten).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\setup\install-claude-skills.ps1
#>
[CmdletBinding()]
param(
    [string]$Destination = (Join-Path $HOME ".claude\skills"),
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Repositorio, commit auditado y qué carpetas copiar (origen relativo → nombre de la skill).
# Origen "*" bajo una carpeta = cada subcarpeta es una skill. Origen "." = el repositorio entero.
$sources = @(
    @{ Url = "https://github.com/nextlevelbuilder/ui-ux-pro-max-skill.git"; Sha = "6ae86f61f520d6ca229d2f40e070410638c908c5"
       Map = @(@{ From = ".claude/skills/ui-ux-pro-max"; To = "ui-ux-pro-max" }) },
    @{ Url = "https://github.com/emilkowalski/skills.git"; Sha = "0f2e23b32bb1265e84cff8d3e75785fec953fb1b"
       Map = @(@{ From = "skills/*"; To = "*" }) },
    @{ Url = "https://github.com/alchaincyf/huashu-design.git"; Sha = "e8d1148a80d5a281d4247cffe320add3df017928"
       Map = @(@{ From = "."; To = "huashu-design" }) },
    @{ Url = "https://github.com/pbakaus/impeccable.git"; Sha = "acb4cfe14470b1fdf51e855431af618d936b7db8"
       Map = @(@{ From = ".claude/skills/impeccable"; To = "impeccable" }) },
    @{ Url = "https://github.com/Leonxlnx/taste-skill.git"; Sha = "f6b76575f949707b4e3c37cd86cb44b0b98643e8"
       Map = @(@{ From = "skills/taste-skill"; To = "design-taste-frontend" }) }
)

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "Falta git: ejecuta antes scripts\setup\install-tools.ps1" }
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
$work = Join-Path ([IO.Path]::GetTempPath()) ("securefin-skills-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$report = @()

function Copy-Skill([string]$from, [string]$name) {
    $target = Join-Path $Destination $name
    $hasContent = (Test-Path $target) -and (Get-ChildItem -Path $target -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($hasContent -and -not $Force) { return "omitida (ya existe con contenido; usa -Force)" }
    if ($hasContent) { Remove-Item -Recurse -Force $target }
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    Get-ChildItem -Path $from -Force | Where-Object { $_.Name -ne ".git" } |
        ForEach-Object { Copy-Item -Path $_.FullName -Destination $target -Recurse -Force }
    $n = (Get-ChildItem -Path $target -Recurse -File -Force | Measure-Object).Count
    return "instalada ($n archivos)"
}

try {
    foreach ($src in $sources) {
        $repoName = ($src.Url -split "/")[-1] -replace "\.git$", ""
        Write-Host "`n» $repoName @ $($src.Sha.Substring(0, 7))" -ForegroundColor Cyan
        $dir = Join-Path $work $repoName
        git init -q $dir
        git -C $dir remote add origin $src.Url
        git -C $dir -c advice.detachedHead=false fetch -q --depth 1 origin $src.Sha
        if ($LASTEXITCODE -ne 0) { $report += [pscustomobject]@{ Skill = $repoName; Resultado = "ERROR: no se pudo descargar el commit fijado" }; continue }
        git -C $dir -c advice.detachedHead=false checkout -q FETCH_HEAD
        $head = (git -C $dir rev-parse HEAD).Trim()
        if ($head -ne $src.Sha) { $report += [pscustomobject]@{ Skill = $repoName; Resultado = "ERROR: SHA distinto ($head); no se instala" }; continue }

        foreach ($m in $src.Map) {
            if ($m.From -like "*/[*]") {
                $parent = Join-Path $dir ($m.From.TrimEnd("*").TrimEnd("/"))
                foreach ($sub in Get-ChildItem -Path $parent -Directory) {
                    $report += [pscustomobject]@{ Skill = $sub.Name; Resultado = (Copy-Skill $sub.FullName $sub.Name) }
                }
            } else {
                $from = if ($m.From -eq ".") { $dir } else { Join-Path $dir $m.From }
                $report += [pscustomobject]@{ Skill = $m.To; Resultado = (Copy-Skill $from $m.To) }
            }
        }
    }
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

Write-Host "`n» Resumen (destino: $Destination)" -ForegroundColor Cyan
$report | Format-Table -AutoSize | Out-Host
Write-Host "Reinicia Claude Code (o abre una sesión nueva) para que cargue las skills." -ForegroundColor Yellow
