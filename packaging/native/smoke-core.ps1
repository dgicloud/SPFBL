param(
    [Parameter(Mandatory = $true)][string]$BundleDirectory,
    [string]$BayesCorpusDirectory = "",
    [switch]$EmptyData,
    [switch]$LoadTest,
    [ValidateRange(1, 60)][int]$LoadDurationSeconds = 5
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Bundle = (Resolve-Path $BundleDirectory).Path
$Suffix = "{0}-{1}" -f $PID, (Get-Random -Minimum 1000 -Maximum 9999)
$Network = "had-native-smoke-net-$Suffix"
$Container = "had-native-smoke-core-$Suffix"
$LoadContainer = "had-native-smoke-load-$Suffix"
$TestRoot = Join-Path $Root ".audit\native-smoke-$Suffix"
if (-not $TestRoot.StartsWith((Join-Path $Root ".audit") + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Smoke target escaped the workspace audit directory."
}

New-Item -ItemType Directory -Path $TestRoot | Out-Null
$Runtime = Join-Path $Bundle "release"
foreach ($item in @("SPFBL.jar", "licence.txt", "lib", "web", "template")) {
    Copy-Item -LiteralPath (Join-Path $Runtime $item) -Destination $TestRoot -Recurse
}
foreach ($directory in @("data", "history", "logs")) {
    New-Item -ItemType Directory -Path (Join-Path $TestRoot $directory) | Out-Null
}
if (-not $EmptyData) {
    Copy-Item -Path (Join-Path $Runtime "data-seed\*") -Destination (Join-Path $TestRoot "data") -Recurse
}
if ($BayesCorpusDirectory) {
    $CorpusRoot = (Resolve-Path $BayesCorpusDirectory).Path
    foreach ($label in @("spam", "ham")) {
        $TrainSource = Join-Path $CorpusRoot "train\$label"
        $TestSource = Join-Path $CorpusRoot "test\$label"
        if (-not (Test-Path -LiteralPath $TrainSource -PathType Container) -or
                -not (Test-Path -LiteralPath $TestSource -PathType Container)) {
            throw "Bayes corpus must contain train/$label and test/$label directories."
        }
        $TrainTarget = Join-Path $TestRoot "learn\$label"
        $TestTarget = Join-Path $TestRoot "learn\test"
        New-Item -ItemType Directory -Force -Path $TrainTarget, $TestTarget | Out-Null
        Get-ChildItem -LiteralPath $TrainSource -Filter "*.eml" -File | Copy-Item -Destination $TrainTarget
        Get-ChildItem -LiteralPath $TestSource -Filter "*.eml" -File | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $TestTarget ("$label-" + $_.Name))
        }
    }
}
if ($BayesCorpusDirectory -and $EmptyData) {
    # Give the SPAMD wire smoke test one deterministic, locally trusted SMTP
    # identity so content classification is reached without seeding production
    # reputation data or depending on external DNS.
    Copy-Item -LiteralPath (Join-Path $Runtime "data-seed\tld.set") -Destination (Join-Path $TestRoot "data\tld.set")
    $NowMillis = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $CoreTime = [int][Math]::Floor($NowMillis / 4294967296.0)
    "PUT example.net 1577836800000 true $CoreTime" | Set-Content -Encoding ascii -Path (Join-Path $TestRoot "data\domain.txt")
    "PUT 8.8.8.8 mail.example.net $CoreTime" | Set-Content -Encoding ascii -Path (Join-Path $TestRoot "data\fqdn.txt")
}
$Config = Get-Content -Raw (Join-Path $Bundle "native\spfbl.conf")
$Config = $Config.Replace("/var/log/spfbl/", "/work/logs/")
# Keep the isolated smoke test offline: don't start public HTTP or P2P services.
$Config = [regex]::Replace($Config, "(?m)^\s*hostname=.*(?:\r?\n|$)", "")
$Config = [regex]::Replace($Config, "(?m)^\s*http_port=.*(?:\r?\n|$)", "")
Set-Content -NoNewline -Path (Join-Path $TestRoot "spfbl.conf") -Value $Config

try {
    docker network create --internal --subnet 198.18.250.0/24 $Network | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create the isolated smoke network." }
    docker run --detach --name $Container --network $Network --ip 198.18.250.10 `
        --mount "type=bind,src=$TestRoot,dst=/work" --workdir /work `
        eclipse-temurin:17-jre java -Xms512m -Xmx2048m -cp '/work/SPFBL.jar:/work/lib/*' net.spfbl.core.Core | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not start the native core smoke container." }
    $ContainerIp = "198.18.250.10"
    Write-Output "Isolated core address: $ContainerIp"
    # Prime the unknown-client cache; the later SPAMD test registers this same
    # address and verifies that the core notices the client-table update.
    docker run --rm --network $Network --ip 198.18.250.2 `
        --mount "type=bind,src=$Root,dst=/source,readonly" `
        --entrypoint python python:3.12-slim /source/packaging/native/wait-core.py $ContainerIp 9877 60
    if ($LASTEXITCODE -ne 0) { throw "Native core did not become ready." }
    if ($BayesCorpusDirectory) {
        $BayesSmokeOutput = docker run --rm --network "container:$Container" `
            --mount "type=bind,src=$Root,dst=/source,readonly" `
            --mount "type=bind,src=$TestRoot,dst=/work,readonly" `
            --entrypoint python python:3.12-slim /source/packaging/native/bayes-admin-smoke.py 127.0.0.1 9875 --train-corpus
    } else {
        $BayesSmokeOutput = docker run --rm --network "container:$Container" `
            --mount "type=bind,src=$Root,dst=/source,readonly" `
            --entrypoint python python:3.12-slim /source/packaging/native/bayes-admin-smoke.py 127.0.0.1 9875
    }
    $BayesExitCode = $LASTEXITCODE
    $BayesSmokeOutput | ForEach-Object { Write-Output $_ }
    $BayesCandidate = $null
    if ($BayesCorpusDirectory) {
        $CandidateLine = $BayesSmokeOutput | Where-Object { $_ -match '^SPAMD_CANDIDATE=' } | Select-Object -Last 1
        if ($CandidateLine -match '^SPAMD_CANDIDATE=(spam-[A-Za-z0-9._-]+\.eml)$') {
            $BayesCandidate = $Matches[1]
        } else {
            throw "Native Bayes smoke did not return a safe SPAMD positive-control filename."
        }
    }
    if ($BayesExitCode -ne 0) { throw "Native Bayes ADMIN protocol smoke failed." }
    if ($BayesCorpusDirectory) {
        docker run --rm --network $Network --ip 198.18.250.2 `
            --mount "type=bind,src=$Root,dst=/source,readonly" `
            --mount "type=bind,src=$TestRoot,dst=/work,readonly" `
            --entrypoint python python:3.12-slim /source/packaging/native/bayes-spamd-smoke.py `
            $ContainerIp 9877 "/work/learn/test/$BayesCandidate" /work/learn/test
        if ($LASTEXITCODE -ne 0) { throw "Native Bayes SPAMD protocol smoke failed." }
        docker run --rm --network "container:$Container" `
            --mount "type=bind,src=$Root,dst=/source,readonly" `
            --entrypoint python python:3.12-slim /source/packaging/native/bayes-admin-smoke.py 127.0.0.1 9875 --cleanup
        if ($LASTEXITCODE -ne 0) { throw "Native Bayes SPAMD test cleanup failed." }
    }
    docker run --rm --network $Network `
        --mount "type=bind,src=$Root,dst=/source,readonly" `
        --entrypoint python python:3.12-slim /source/packaging/native/query-smoke.py $ContainerIp 9877
    if ($LASTEXITCODE -ne 0) { throw "Native core protocol smoke failed." }

    if ($LoadTest) {
        $StatsPath = Join-Path $TestRoot "load-container-stats.csv"
        "sampled_at_utc,cpu_percent,memory_usage" | Set-Content -Path $StatsPath
        docker run --detach --name $LoadContainer --network $Network `
            --mount "type=bind,src=$Root,dst=/source,readonly" `
            --entrypoint python python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f `
            -u /source/packaging/native/load-smoke.py --host $ContainerIp --port 9877 `
            --rates 100,500,1000 --duration $LoadDurationSeconds
        if ($LASTEXITCODE -ne 0) { throw "Could not start the isolated native load test." }

        do {
            $Sample = docker stats --no-stream --format "{{.CPUPerc}},{{.MemUsage}}" $Container 2>$null
            if ($LASTEXITCODE -eq 0 -and $Sample) {
                $Timestamp = (Get-Date).ToUniversalTime().ToString("o")
                Add-Content -Path $StatsPath -Value ($Timestamp + "," + $Sample)
            }
            $Running = docker inspect --format '{{.State.Running}}' $LoadContainer 2>$null
            if ($LASTEXITCODE -ne 0) { throw "Could not inspect the isolated load runner." }
            if ($Running -eq "true") { Start-Sleep -Seconds 1 }
        } while ($Running -eq "true")

        $LoadExitCode = docker inspect --format '{{.State.ExitCode}}' $LoadContainer
        if ($LASTEXITCODE -ne 0) { throw "Could not read the isolated load-test exit status." }
        $LoadOutput = docker logs $LoadContainer 2>&1
        $LoadOutput | Set-Content -Path (Join-Path $TestRoot "load-results.json")
        $LoadOutput | Select-Object -Last 80
        if ([int]$LoadExitCode -ne 0) { throw "Native load test did not meet its throughput/error criteria." }
    }
}
catch {
    docker container inspect $Container *> $null
    if ($LASTEXITCODE -eq 0) {
        $PreviousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        docker exec $Container kill -3 1 *> $null
        $DockerLogs = docker logs $Container 2>&1 | ForEach-Object { $_.ToString() }
        $DockerLogs | Set-Content -Path (Join-Path $TestRoot "docker.log")
        Get-Content (Join-Path $TestRoot "docker.log") | Select-Object -Last 40
        $ErrorActionPreference = $PreviousErrorActionPreference
    }
    throw
}
finally {
    docker rm --force $LoadContainer 2>$null | Out-Null
    docker rm --force $Container 2>$null | Out-Null
    docker network rm $Network 2>$null | Out-Null
}
