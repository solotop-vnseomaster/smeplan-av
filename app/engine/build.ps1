# Build scan_engine.dll bang MSVC (cl.exe) truc tiep, khong can msbuild/cmake.
# Chay: powershell -File build.ps1 [-Config Debug|Release]
param(
    [string]$Config = "Debug"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
$outDir = Join-Path $root "build\$Config"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$sources = Get-ChildItem -Path (Join-Path $root "src") -Filter "*.cpp" | ForEach-Object { '"' + $_.FullName + '"' }
$sourcesArg = ($sources -join " ")

$optFlags = if ($Config -eq "Release") { "/O2 /DNDEBUG" } else { "/Od /Zi /DDEBUG" }

$cmd = @"
call "$vcvars" >nul
cl.exe /nologo /std:c++17 /EHsc /W3 /MD $optFlags /I "$root\include" /I "$root\src" $sourcesArg /LD /Fe:"$outDir\scan_engine.dll" /Fo:"$outDir\\" /link /OUT:"$outDir\scan_engine.dll"
"@

$batPath = Join-Path $env:TEMP "build_scan_engine.bat"
Set-Content -Path $batPath -Value $cmd -Encoding ASCII

& cmd.exe /c $batPath
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build that bai voi exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
Write-Host "Build OK -> $outDir\scan_engine.dll"
