<#
.SYNOPSIS
  Loai tru thu muc cai dat va tien trinh cua app khoi pham vi quet Windows
  Defender — CHI danh cho moi truong dev/test, tranh hai minifilter driver
  (Defender + app nay) tranh chap lock tren cung file khi app CHUA qua
  chuong trinh Microsoft Virus Initiative (MVI).

.DESCRIPTION
  security/09-bao-mat.md muc 4 va ops/08-trien-khai.md muc 4 deu neu ro:
  KHONG duoc yeu cau nguoi dung cuoi tu chay lenh nay cho mot app chua
  duoc cong nhan chinh thuc, vi lam vay tat mot lop bao ve that cua Windows
  ma khong co gi thay the dang tin cay tuong duong cho toi khi app da qua
  MVI. Script nay chi phuc vu may cua LAP TRINH VIEN trong qua trinh phat
  trien/test noi bo.

.PARAMETER InstallPath
  Duong dan thu muc cai dat app (mac dinh: ProgramData\AntivirusApp).

.PARAMETER ProcessNames
  Danh sach ten file thuc thi can loai tru (Antivirus.Service.exe, ...).
#>
[CmdletBinding()]
param(
    [string]$InstallPath = "$env:ProgramData\AntivirusApp",
    [string[]]$ProcessNames = @("Antivirus.Service.exe", "AntivirusApp.exe")
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Script nay can chay voi quyen Administrator."
    exit 1
}

Write-Warning "CHI dung cho may DEV/TEST noi bo. KHONG bao gio chay script nay tren may nguoi dung cuoi cho ban phat hanh chua qua MVI."

Add-MpPreference -ExclusionPath $InstallPath
foreach ($proc in $ProcessNames) {
    Add-MpPreference -ExclusionProcess $proc
}

Write-Host "Da loai tru (chi hieu luc tren may nay): $InstallPath va cac tien trinh $($ProcessNames -join ', ')" -ForegroundColor Yellow
