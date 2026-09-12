<#
.SYNOPSIS
    Chay SMEPlan AV doc lap, KHONG phu thuoc vong doi phien Claude Code.

.DESCRIPTION
    Van de: khi AV duoc chay qua preview cua Claude Code (dotnet run duoi su
    quan ly cua harness), tien trinh do co vong doi RIENG cua preview server --
    harness thu hoi no sau mot khoang khong hoat dong, ke ca khi cua so chat
    van dang mo. Do KHONG phai loi cua AV: nhat ky ket thuc binh thuong, khong
    exception, Event Log sach, va thong bao cua harness ghi ro "stopped by the
    app" chu khong phai "exited with code N". Do da chay 31 phut roi 47 phut
    o hai lan lien tiep.

    Script nay publish ban Release ra mot thu muc ON DINH NGOAI repo roi chay
    tu do, tach khoi ca harness lan thu muc build:
      - Chay tu thu muc rieng nen `dotnet build` trong repo khong con khoa file
        (loi MSB3021 "being used by another process" da gap nhieu lan).
      - Tien trinh thuoc ve shell cua ban, song toi khi ban dung no.

    Dung -AsService de cai thanh Windows service that (chay LocalSystem, song
    qua reboot). Can PowerShell chay quyen Administrator cho lua chon do.

.EXAMPLE
    .\run-av-standalone.ps1
    Publish roi chay o tien trinh nen; in ra URL kem token.

.EXAMPLE
    .\run-av-standalone.ps1 -AsService
    Cai va khoi dong Windows service SmePlanAvService (can quyen Administrator).

.EXAMPLE
    .\run-av-standalone.ps1 -Stop
    Dung tien trinh dang chay (ca hai che do).
#>
[CmdletBinding()]
param(
    [switch]$AsService,
    [switch]$Stop,
    [string]$InstallDir = "$env:LOCALAPPDATA\SmePlanAv\app",
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'SmePlanAvService'
$Port = 5270

function Get-ListenerPid {
    $c = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($null -eq $c) { return $null }
    return @($c)[0].OwningProcess
}

if ($Stop) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $svc -and $svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        Write-Host "Da dung Windows service $ServiceName."
    }
    $listener = Get-ListenerPid
    if ($null -ne $listener) {
        Stop-Process -Id $listener -Force -ErrorAction SilentlyContinue
        Write-Host "Da dung tien trinh PID $listener dang giu port $Port."
    }
    if ($null -eq $svc -and $null -eq $listener) { Write-Host "Khong co gi dang chay." }
    return
}

$existing = Get-ListenerPid
if ($null -ne $existing) {
    throw "Port $Port dang bi PID $existing giu. Dung no truoc (vi du: .\run-av-standalone.ps1 -Stop), " +
          "hoac tat preview trong Claude Code neu do la tien trinh cua no."
}

$proj = Join-Path $RepoRoot 'app\service\Service\Service.csproj'
if (-not (Test-Path -LiteralPath $proj)) { throw "Khong tim thay project: $proj" }

Write-Host "Publish ban Release ra $InstallDir ..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
& dotnet publish $proj -c Release -r win-x64 --self-contained false -o $InstallDir --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "dotnet publish that bai (ma loi $LASTEXITCODE)." }

$exe = Join-Path $InstallDir 'Antivirus.Service.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "Khong thay $exe sau khi publish." }

if ($AsService) {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "-AsService can PowerShell chay quyen Administrator."
    }
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        if ($svc.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force }
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }
    & sc.exe create $ServiceName binPath= "`"$exe`"" obj= LocalSystem start= auto DisplayName= "SmePlanAv Antivirus Service" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create that bai (ma loi $LASTEXITCODE)." }
    & sc.exe start $ServiceName | Out-Null
    Start-Sleep -Seconds 4
    $svc = Get-Service -Name $ServiceName
    Write-Host "Windows service ${ServiceName}: $($svc.Status) (LocalSystem, tu khoi dong cung Windows)."
} else {
    # Tien trinh nen thuoc ve shell nay, khong thuoc harness cua Claude Code.
    Start-Process -FilePath $exe -WorkingDirectory $InstallDir -WindowStyle Hidden | Out-Null

    # Khoi dong lam kha nhieu viec truoc khi mo port: baseline snapshot cho
    # ransomware guard va quet danh sach phan mem da cai (~90 muc). Cho theo
    # kieu poll thay vi mot khoang co dinh — mot lan cho 4 giay tung bao
    # "khong len duoc port" trong khi tien trinh van dang khoi dong binh thuong.
    $listener = $null
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        $listener = Get-ListenerPid
        if ($null -ne $listener) { break }
    }
    if ($null -eq $listener) { throw "Tien trinh khong len duoc port $Port sau 30 giay -- xem Event Viewer." }
    Write-Host "Dang chay o tien trinh nen, PID $listener."
}

$tokenPath = 'C:\ProgramData\AntivirusApp\data\api-token.txt'
if (Test-Path -LiteralPath $tokenPath) {
    try {
        $t = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
        Write-Host ""
        Write-Host "Mo giao dien: http://127.0.0.1:$Port/?token=$t"
    } catch {
        Write-Host "Khong doc duoc token (chay LocalSystem thi can PowerShell elevated de doc): $tokenPath"
    }
}
