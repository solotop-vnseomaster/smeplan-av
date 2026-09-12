<#
.SYNOPSIS
  Bat che do testsigning cho moi truong DEV/TEST de nap duoc driver tu ky
  (khong dung cho production). Khop ops/08-trien-khai.md muc 3 buoc 3.

.DESCRIPTION
  Yeu cau khoi dong lai may sau khi chay. CHI dung tren may phat trien,
  KHONG chay tren may nguoi dung cuoi — testsigning lam giam bao mat he
  thong (Windows hien watermark "Test Mode" va chap nhan driver ky boi bat
  ky certificate nao trong Trusted Root/Trusted Publisher cuc bo).
#>
[CmdletBinding()]
param()

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Script nay can chay voi quyen Administrator (bcdedit yeu cau elevate)."
    exit 1
}

Write-Warning "Sap bat testsigning mode — CHI dung cho may dev/test, khong dung cho production."
bcdedit /set testsigning on

if ($LASTEXITCODE -eq 0) {
    Write-Host "Da bat testsigning. Can KHOI DONG LAI may de co hieu luc." -ForegroundColor Yellow
} else {
    Write-Error "bcdedit that bai (exit code $LASTEXITCODE)."
    exit $LASTEXITCODE
}
