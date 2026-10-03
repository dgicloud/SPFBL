param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$OutputDir = Join-Path $Root ".audit\cpanel-bundle"

if (-not $Version) {
    $Version = (& git -C $Root rev-parse --short HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $Version) {
        throw "Informe -Version quando o checkout não tiver um commit Git."
    }
    if ((& git -C $Root status --porcelain) -and $LASTEXITCODE -eq 0) {
        $Version = "$Version-working"
    }
}
if ($Version -notmatch '^[A-Za-z0-9._-]+$') {
    throw "Versão inválida: use somente letras, números, ponto, hífen e sublinhado."
}

$Tar = (Get-Command tar.exe -ErrorAction Stop).Source
$BundleName = "had-antispam-cpanel-$Version"
$Archive = Join-Path $OutputDir "$BundleName.tar.gz"
if (Test-Path -LiteralPath $Archive) {
    throw "O pacote já existe e não será sobrescrito: $Archive"
}

$RequiredFiles = @(
    "licence.txt",
    "docs\CPANEL-COLLECTOR-INSTALL.md",
    "integrations\common\spfbl_client.py",
    "integrations\common\technical_signals.py",
    "integrations\cpanel\README.md",
    "integrations\cpanel\exim\acl-data-header-monitor.conf",
    "integrations\cpanel\exim\acl-rcpt-monitor.conf",
    "integrations\cpanel\had-antispam-client.service",
    "integrations\cpanel\had_antispam_client.py",
    "integrations\cpanel\had_antispam_feedback.py",
    "integrations\cpanel\healthcheck.sh",
    "integrations\cpanel\install-client.sh",
    "integrations\cpanel\install-exim-cpanel.sh",
    "integrations\cpanel\install.sh",
    "integrations\cpanel\manage_exim_acl.py",
    "integrations\cpanel\manage_exim_data_acl.py",
    "integrations\cpanel\rollback-client.sh",
    "integrations\cpanel\uninstall.sh",
    "integrations\cpanel\update-client.sh",
    "integrations\cpanel\update.sh"
)
foreach ($RelativePath in $RequiredFiles) {
    $Path = Join-Path $Root $RelativePath
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Arquivo necessário ausente: $RelativePath"
    }
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString("N"))
$TempRootFull = [System.IO.Path]::GetFullPath($TempRoot)
$TempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
if (-not $TempRootFull.StartsWith($TempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Diretório temporário fora da pasta temporária do sistema: $TempRootFull"
}
$Stage = Join-Path $TempRoot $BundleName
try {
    foreach ($RelativePath in $RequiredFiles) {
        $Destination = Join-Path $Stage $RelativePath
        $DestinationDir = Split-Path -Parent $Destination
        New-Item -ItemType Directory -Force -Path $DestinationDir | Out-Null
        $Text = [System.IO.File]::ReadAllText((Join-Path $Root $RelativePath))
        [System.IO.File]::WriteAllText($Destination, $Text.Replace("`r`n", "`n"), [System.Text.UTF8Encoding]::new($false))
    }
    Set-Content -LiteralPath (Join-Path $Stage "VERSION") -Value $Version -NoNewline -Encoding ascii
    $Launcher = "#!/usr/bin/env bash`nset -euo pipefail`nHERE=`$(cd -- `"`$(dirname -- `"`$0`")`" && pwd)`nexec bash `"`$HERE/integrations/cpanel/install-exim-cpanel.sh`" `"`$@`"`n"
    [System.IO.File]::WriteAllText((Join-Path $Stage "install.sh"), $Launcher, [System.Text.UTF8Encoding]::new($false))
    Copy-Item -LiteralPath (Join-Path $Stage "docs\CPANEL-COLLECTOR-INSTALL.md") -Destination (Join-Path $Stage "README.md")
    New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null
    & $Tar -czf $Archive -C $TempRoot $BundleName
    if ($LASTEXITCODE -ne 0) {
        Remove-Item -LiteralPath $Archive -Force -ErrorAction SilentlyContinue
        throw "tar.exe falhou ao criar o bundle cPanel."
    }
    $Hash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText("$Archive.sha256", "$Hash  $([System.IO.Path]::GetFileName($Archive))`n", [System.Text.Encoding]::ASCII)
    Write-Output "Pacote: $Archive"
    Write-Output "SHA-256: $Hash"
}
finally {
    if (Test-Path -LiteralPath $TempRoot) {
        Remove-Item -LiteralPath $TempRoot -Recurse -Force
    }
}
