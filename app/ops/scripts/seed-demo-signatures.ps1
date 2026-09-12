<#
.SYNOPSIS
  Xay mot CSDL signature demo (chi chua hash EICAR) de kiem thu thu cong
  luong phat hien qua hash — dung cho TC-01/TC-02 trong tests/07-kiem-thu.md.
  KHONG phai CSDL malware that; chi phuc vu demo/dev.

.DESCRIPTION
  Goi Engine_BuildSignatureDb trong scan_engine.dll (da build qua
  app/engine/build.ps1) de tao file .avsigdb dung dinh dang data-models/04.
#>
[CmdletBinding()]
param(
    [string]$EngineDll = (Join-Path $PSScriptRoot "..\..\engine\build\Debug\scan_engine.dll"),
    [string]$OutputDb = "$env:ProgramData\AntivirusApp\signatures\signatures.avsigdb",

    # Bat buoc phai dat tuong minh de ghi de len mot CSDL da ton tai — xem
    # ghi chu ben duoi.
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $EngineDll)) {
    Write-Error "Khong tim thay scan_engine.dll tai $EngineDll — chay app/engine/build.ps1 truoc."
    exit 1
}

# [SUA LOI NGHIEM TRONG] Script DEMO nay mac dinh ghi thang len
# $env:ProgramData\AntivirusApp\signatures\signatures.avsigdb — DUNG file
# CSDL SAN XUAT. Thiet hai la VINH VIEN, khong phai tam thoi:
# UpdateClientService chi so sanh version trong update_version.json de quyet
# dinh co cap nhat hay khong, va script nay khong dung toi file do — nen may
# se dung mai voi CSDL chi co DUY NHAT mot chu ky EICAR, tin la minh dang
# cap nhat, va khong bao gio tu phuc hoi. Mot lan chay nham la mat toan bo
# kha nang phat hien theo hash.
# Sua: neu file dich da ton tai, PHAI xac nhan tuong minh bang -Force.
if ((Test-Path $OutputDb) -and (-not $Force)) {
    Write-Error @"
TU CHOI: da co CSDL signature tai $OutputDb.
Script nay chi tao CSDL DEMO chua DUY NHAT hash EICAR. Ghi de len CSDL that
se lam may mat kha nang phat hien theo hash VINH VIEN (UpdateClientService
so sanh version, khong so sanh noi dung, nen se khong tu phuc hoi).
Neu that su muon ghi de, chay lai voi -Force, hoac chon duong dan khac qua
-OutputDb.
"@
    exit 1
}

# [SUA LOI NGHIEM TRONG] $EngineDll TRUOC DAY duoc noi suy THANG vao ma
# nguon C# cua Add-Type ben duoi. Bat ky ky tu nao trong duong dan cung tro
# thanh MA NGUON — mot duong dan chua dau ngoac kep dong lai roi them cau
# lenh la thuc thi ma tuy y trong tien trinh chay script (thuong la
# PowerShell dang elevate khi seed vao ProgramData). Sua: KHONG noi suy vao
# ma nguon; truyen duong dan qua bien moi truong luc chay va tai DLL bang
# duong dan tuyet doi da resolve.
#
# [DINH CHINH GHI CHU] Cau ngay tren MO TA SAI cai da thuc su lam. $EngineDll
# VAN duoc noi suy thang vao [DllImport(@"$EngineDll")] o ben duoi — khong co
# bien moi truong nao ca. Cai THUC SU chan duoc viec thoat chuoi la ba kiem
# tra ngay sau day: (1) resolve ve duong dan tuyet doi, (2) tu choi neu duong
# dan chua ky tu co the thoat khoi chuoi verbatim @"..." (dau ngoac kep, CR,
# LF), (3) bat buoc duoi .dll. Ghi lai cho dung de nguoi doc sau khong tuong
# rang dang co mot lop phong thu khac ton tai.
$EngineDll = (Resolve-Path -LiteralPath $EngineDll).ProviderPath
# Ma nguon C# ben duoi dung chuoi verbatim @"..." — ky tu duy nhat co the
# thoat ra khoi no la dau ngoac kep, cong voi ky tu xuong dong.
$dangerous = [char[]]@([char]34, [char]10, [char]13)
if ($EngineDll.IndexOfAny($dangerous) -ge 0) {
    Write-Error "Duong dan scan_engine.dll chua ky tu co the thoat khoi chuoi ma nguon C#: $EngineDll"
    exit 1
}
if (-not $EngineDll.EndsWith('.dll', [StringComparison]::OrdinalIgnoreCase)) {
    Write-Error "Duong dan scan_engine.dll khong tro toi mot file .dll: $EngineDll"
    exit 1
}

# EICAR standard test string — chuoi test chuan cong khai cua nganh
# antivirus (khong phai malware that).
$eicarHash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

$csvPath = Join-Path $env:TEMP "avdemo_signatures.csv"
"$eicarHash,1,255" | Set-Content -Path $csvPath -Encoding ascii

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class DemoEngineNative {
    [DllImport(@"$EngineDll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    public static extern int Engine_BuildSignatureDb(string csvPath, string outDbPath);
}
"@

$outDir = Split-Path $OutputDb -Parent
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$rc = [DemoEngineNative]::Engine_BuildSignatureDb($csvPath, $OutputDb)
if ($rc -ne 0) {
    Write-Error "Engine_BuildSignatureDb that bai (rc=$rc)"
    exit 1
}

Write-Host "Da tao CSDL demo tai $OutputDb (chi chua hash EICAR, dung de test)." -ForegroundColor Green
