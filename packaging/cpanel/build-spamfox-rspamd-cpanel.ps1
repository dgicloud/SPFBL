param(
    [string]$Version = "0.1.11-pilot"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$OutputDir = Join-Path $Root "packaging\cpanel\releases"
$Tar = (Get-Command tar.exe -ErrorAction Stop).Source
$BundleName = "spamfox-rspamd-cpanel-$Version"
$Archive = Join-Path $OutputDir "$BundleName.tar.gz"

if ($Version -notmatch '^[A-Za-z0-9._-]+$') {
    throw "Versão inválida: use somente letras, números, ponto, hífen e sublinhado."
}
if (Test-Path -LiteralPath $Archive) {
    throw "O pacote já existe e não será sobrescrito: $Archive"
}

$RequiredFiles = @(
    "licence.txt",
    "docs\CPANEL-SPAMFOX-RSPAMD-INSTALL.md",
    "integrations\content_scan\scan_client.py",
    "integrations\cpanel\exim\sysfilter-content-scan.conf",
    "integrations\cpanel\exim\transport-content-scan.conf",
    "integrations\cpanel\exim\acl-data-header-monitor.conf",
    "integrations\cpanel\manage_exim_acl.py",
    "integrations\cpanel\manage_exim_data_acl.py",
    "integrations\cpanel\install-content-scan.sh",
    "integrations\cpanel\spamfox-rspamd.cpanel.sh"
)
foreach ($RelativePath in $RequiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $Root $RelativePath) -PathType Leaf)) {
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
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
        $Text = [System.IO.File]::ReadAllText((Join-Path $Root $RelativePath))
        [System.IO.File]::WriteAllText($Destination, $Text.Replace("`r`n", "`n"), [System.Text.UTF8Encoding]::new($false))
    }
    Set-Content -LiteralPath (Join-Path $Stage "VERSION") -Value $Version -NoNewline -Encoding ascii
    Copy-Item -LiteralPath (Join-Path $Stage "docs\CPANEL-SPAMFOX-RSPAMD-INSTALL.md") -Destination (Join-Path $Stage "README.md")
    & $Tar -czf $Archive -C $TempRoot $BundleName
    if ($LASTEXITCODE -ne 0) {
        Remove-Item -LiteralPath $Archive -Force -ErrorAction SilentlyContinue
        throw "tar.exe falhou ao criar o pacote SpamFox Rspamd cPanel."
    }
    $Hash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText("$Archive.sha256", "$Hash  $([System.IO.Path]::GetFileName($Archive))`n", [System.Text.Encoding]::ASCII)
    Write-Output "Pacote: $Archive"
    Write-Output "Tamanho: $((Get-Item -LiteralPath $Archive).Length) bytes"
    Write-Output "SHA-256: $Hash"
}
finally {
    if (Test-Path -LiteralPath $TempRoot) {
        Remove-Item -LiteralPath $TempRoot -Recurse -Force
    }
}
