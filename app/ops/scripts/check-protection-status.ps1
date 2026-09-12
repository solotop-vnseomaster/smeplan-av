<#
.SYNOPSIS
    In ra trang thai bao ve THAT cua service dang chay.

.DESCRIPTION
    Doc GET /api/status va hien thi:
      - protectionEnabled / protectionLevel
      - toan bo danh sach suy giam (degradations) kem muc do
      - diem rui ro tong hop tu /api/risk-score

    Dung de kiem chung nhanh sau khi doi cach chay service (vi du chay quyen
    LocalSystem de tang danh gia tin cay tien trinh hoat dong duoc).

    LUU Y: khi service chay bang quyen LocalSystem, AclProtection khoa
    api-token.txt chi cho SYSTEM + Administrators. Chay script nay trong mot
    PowerShell ELEVATED, neu khong se bi Access denied khi doc token.

.EXAMPLE
    .\check-protection-status.ps1
#>
[CmdletBinding()]
param(
    [string]$TokenPath = 'C:\ProgramData\AntivirusApp\data\api-token.txt',
    [string]$BaseUrl   = 'http://127.0.0.1:5270'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $TokenPath)) {
    throw "Khong tim thay file token: $TokenPath (service da chay chua?)"
}

try {
    $token = (Get-Content -LiteralPath $TokenPath -Raw).Trim()
} catch {
    throw "Khong doc duoc token: $($_.Exception.Message). Neu service chay quyen LocalSystem, hay mo PowerShell bang Run as administrator."
}

$headers = @{ 'X-Av-Token' = $token }

try {
    $status = Invoke-RestMethod -Uri "$BaseUrl/api/status" -Headers $headers
} catch {
    throw "Khong goi duoc $BaseUrl/api/status : $($_.Exception.Message). Service co dang chay khong?"
}

Write-Host ''
Write-Host '=== TRANG THAI BAO VE ===' -ForegroundColor Cyan
$levelColor = switch ($status.protectionLevel) {
    'ok'       { 'Green' }
    'degraded' { 'Yellow' }
    default    { 'Red' }
}
Write-Host ("  protectionEnabled : {0}" -f $status.protectionEnabled) -ForegroundColor $levelColor
Write-Host ("  protectionLevel   : {0}" -f $status.protectionLevel)   -ForegroundColor $levelColor

Write-Host ''
Write-Host '=== CAC TANG DANG SUY GIAM ===' -ForegroundColor Cyan
if ($status.degradations.Count -eq 0) {
    Write-Host '  (khong co - moi tang deu hoat dong)' -ForegroundColor Green
} else {
    foreach ($d in $status.degradations) {
        $c = if ($d.severity -eq 'critical') { 'Red' } else { 'Yellow' }
        Write-Host ("  [{0}] {1}" -f $d.severity, $d.id) -ForegroundColor $c
        Write-Host ("      {0}" -f $d.message) -ForegroundColor DarkGray
    }
}

try {
    $risk = Invoke-RestMethod -Uri "$BaseUrl/api/risk-score" -Headers $headers
    Write-Host ''
    Write-Host '=== DIEM RUI RO TONG HOP ===' -ForegroundColor Cyan
    $rc = if ($risk.score -ge 80) { 'Green' } elseif ($risk.score -ge 50) { 'Yellow' } else { 'Red' }
    Write-Host ("  {0} / 100  -  {1}" -f $risk.score, $risk.label) -ForegroundColor $rc
    foreach ($comp in ($risk.components | Where-Object { $_.pointsDeducted -gt 0 })) {
        Write-Host ("    -{0,-3} {1} ({2})" -f $comp.pointsDeducted, $comp.name, $comp.detail) -ForegroundColor DarkGray
    }
} catch {
    Write-Host ''
    Write-Host "  (khong doc duoc /api/risk-score: $($_.Exception.Message))" -ForegroundColor DarkGray
}

Write-Host ''
