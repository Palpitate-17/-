param(
    [string]$ApiKey = "local-demo-key",
    [int]$ApiPort = 18000,
    [int]$LabPort = 18001
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    throw "缺少 .venv，请先按 README 安装依赖。"
}

$Runtime = Join-Path $RepoRoot ".runtime"
New-Item -ItemType Directory -Force -Path $Runtime | Out-Null
$Database = Join-Path $Runtime ("demo-" + [guid]::NewGuid().ToString("N") + ".db")
$previousLabMode = $env:HENGXUN_ALLOW_LAB_MODE
$previousApiKey = $env:HENGXUN_API_KEY
$previousDatabase = $env:HENGXUN_DATABASE_PATH

try {
    $lab = Start-Process -FilePath $Python -ArgumentList @(
        "-m", "uvicorn", "test_site.app:app", "--host", "127.0.0.1", "--port", $LabPort
    ) -WorkingDirectory $RepoRoot -WindowStyle Hidden -PassThru

    $env:HENGXUN_ALLOW_LAB_MODE = "true"
    $env:HENGXUN_API_KEY = $ApiKey
    $env:HENGXUN_DATABASE_PATH = $Database
    $api = Start-Process -FilePath $Python -ArgumentList @(
        "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", $ApiPort
    ) -WorkingDirectory $RepoRoot -WindowStyle Hidden -PassThru

    $health = "http://127.0.0.1:$ApiPort/health"
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        try {
            Invoke-RestMethod -Uri $health -TimeoutSec 2 | Out-Null
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }

    $headers = @{"X-API-Key" = $ApiKey}
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$LabPort/__test__/phase/before" | Out-Null
    $payload = @{
        target_url = "http://127.0.0.1:$LabPort/"
        authorization_confirmed = $true
        allowed_hosts = @("127.0.0.1")
        allowed_paths = @("/")
        denied_paths = @("/__test__")
        max_pages = 20
        max_depth = 2
        rate_limit_rps = 5
        timeout_seconds = 5
        lab_mode = $true
        external_link_blocklist = @("malicious.example.invalid")
    } | ConvertTo-Json -Depth 8

    function Wait-DemoScan([string]$ScanId) {
        for ($attempt = 0; $attempt -lt 80; $attempt++) {
            $detail = Invoke-RestMethod -Headers $headers -Uri "http://127.0.0.1:$ApiPort/api/v1/scans/$ScanId"
            if ($detail.status -in @("completed", "failed")) { return $detail }
            Start-Sleep -Milliseconds 250
        }
        throw "巡检等待超时"
    }

    $first = Invoke-RestMethod -Method Post -Headers $headers -ContentType "application/json" -Body $payload -Uri "http://127.0.0.1:$ApiPort/api/v1/scans"
    $firstDetail = Wait-DemoScan $first.scan_id
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$LabPort/__test__/phase/after" | Out-Null
    $second = Invoke-RestMethod -Method Post -Headers $headers -ContentType "application/json" -Body $payload -Uri "http://127.0.0.1:$ApiPort/api/v1/scans"
    $secondDetail = Wait-DemoScan $second.scan_id
    $findings = (Invoke-RestMethod -Headers $headers -Uri "http://127.0.0.1:$ApiPort/api/v1/scans/$($second.scan_id)/findings").items
    $target = $findings | Where-Object {
        $_.rule_id -eq "EXTERNAL_LINK_ADDED" -and $_.metadata.added_url -like "*malicious.example.invalid*"
    } | Select-Object -First 1
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$LabPort/__test__/phase/before" | Out-Null
    $retest = Invoke-RestMethod -Method Post -Headers $headers -Uri "http://127.0.0.1:$ApiPort/api/v1/findings/$($target.finding_id)/retest"

    [pscustomobject]@{
        first_scan = $first.scan_id
        first_status = $firstDetail.status
        first_pages = $firstDetail.pages_scanned
        first_findings = $firstDetail.findings_count
        second_scan = $second.scan_id
        second_status = $secondDetail.status
        second_pages = $secondDetail.pages_scanned
        second_findings = $secondDetail.findings_count
        categories = @($findings.category | Sort-Object -Unique)
        retested_finding = $target.finding_id
        retest_status = $retest.status
    } | ConvertTo-Json -Depth 6
} finally {
    if ($api -and -not $api.HasExited) { Stop-Process -Id $api.Id }
    if ($lab -and -not $lab.HasExited) { Stop-Process -Id $lab.Id }
    $env:HENGXUN_ALLOW_LAB_MODE = $previousLabMode
    $env:HENGXUN_API_KEY = $previousApiKey
    $env:HENGXUN_DATABASE_PATH = $previousDatabase
}
