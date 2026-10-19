param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Out = Join-Path $Root ".audit\native-bundle"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
if (-not $Version) {
    $Version = (& git -C $Root rev-parse --short HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $Version) { throw "Informe -Version quando o checkout não tiver um commit Git." }
}
$Version = $Version -replace '[^A-Za-z0-9._-]', '-'
$Image = "eclipse-temurin:8-jdk@sha256:6f9f640cdc1a35e64b77daf1f48fcf7527953d9aa804916c8557e1aae954ecd5"
$SourceMount = "type=bind,src=$Root,dst=/source,readonly"
$OutputMount = "type=bind,src=$Out,dst=/output"
& docker run --rm --network none --mount $SourceMount --mount $OutputMount $Image bash /source/packaging/native/build-bundle.sh $Version /source /output
if ($LASTEXITCODE -ne 0) { throw "Falha no build do bundle nativo." }
Write-Output (Join-Path $Out "spamfox-$Version.tar.gz")
