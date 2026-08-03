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
    [string]$OutputDb = "$env:ProgramData\AntivirusApp\signatures\signatures.avsigdb"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $EngineDll)) {
    Write-Error "Khong tim thay scan_engine.dll tai $EngineDll — chay app/engine/build.ps1 truoc."
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
