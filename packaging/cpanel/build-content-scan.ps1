param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$OutputDir = Join-Path $Root ".audit\content-scan-cpanel"

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
$BundleName = "had-content-scan-cpanel-$Version"
$Archive = Join-Path $OutputDir "$BundleName.tar.gz"
if (Test-Path -LiteralPath $Archive) {
    throw "O pacote já existe e não será sobrescrito: $Archive"
}

$RequiredFiles = @(
    "licence.txt",
    "docs\CPANEL-RSPAMD-CONTENT-SCAN.md",
    "integrations\content_scan\scan_client.py",
    "integrations\cpanel\exim\sysfilter-content-scan.conf",
    "integrations\cpanel\install-content-scan.sh"
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
    Copy-Item -LiteralPath (Join-Path $Stage "docs\CPANEL-RSPAMD-CONTENT-SCAN.md") -Destination (Join-Path $Stage "README.md")
    & $Tar -czf $Archive -C $TempRoot $BundleName
    if ($LASTEXITCODE -ne 0) {
        Remove-Item -LiteralPath $Archive -Force -ErrorAction SilentlyContinue
        throw "tar.exe falhou ao criar o add-on."
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
