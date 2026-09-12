<#
.SYNOPSIS
    Build file cai dat SmePlanAvSetup.exe (bootstrapper + MSI).

.DESCRIPTION
    Lam tron bo trong mot lenh:
      1. Publish ca ba project (Service / Shell / NativeHost) dung RID va
         cau hinh ma Product.wxs mong doi.
      2. Build MSI bang WiX.
      3. Boc MSI vao mot bootstrapper Burn -> SmePlanAvSetup.exe.

    File .exe sinh ra tu xin quyen Administrator khi chay (bat buoc, vi MSI
    cai vao Program Files va dang ky Windows Service chay LocalSystem).

    YEU CAU: WiX 5 CLI.
        dotnet tool install --global wix --version 5.0.2
    KHONG dung WiX 7: ban do doi chap nhan Open Source Maintenance Fee EULA,
    la rang buoc thuong mai co the phat sinh phi - quyet dinh do thuoc ve chu
    du an, khong phai buoc build.

.PARAMETER ChromeExtensionId
    ID that cua extension Chrome (32 ky tu a-p). CHI khi co tham so nay thi
    phan native messaging host (tang chong phishing) moi duoc dong goi.
    Khong co thi phan do bi BO KHOI ban cai - xem ghi chu trong Product.wxs:
    dong goi voi ID sai nghia la cai mot tang bao ve khong bao gio chay,
    im lang tuyet doi.

.EXAMPLE
    .\build-installer.ps1

.EXAMPLE
    .\build-installer.ps1 -ChromeExtensionId abcdefghijklmnopabcdefghijklmnop
#>
[CmdletBinding()]
param(
    # Phien ban cua ban phat hanh. PHAI TANG moi lan build ra ban cai moi:
    # Windows Installer chi ghi de mot file khi phien ban file MOI HON, nen
    # giu nguyen so nay se khien ban cai "thanh cong" nhung binary tren may
    # van la ban cu. Mac dinh sinh theo ngay-gio de moi lan build deu khac
    # nhau; dat tay khi phat hanh chinh thuc.
    [string]$Version = ("1.0." + (Get-Date -Format 'MMdd') + "." + (Get-Date -Format 'HHmm')),
    [string]$ChromeExtensionId,
    [string]$Configuration = 'Release',
    [string]$Rid = 'win-x64'
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $here '..\..')).Path
$outDir = Join-Path $here 'build'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$env:PATH = "$env:PATH;$env:USERPROFILE\.dotnet\tools"
if ($null -eq (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw "Khong tim thay 'wix'. Cai bang: dotnet tool install --global wix --version 5.0.2"
}

# Hai extension bat buoc. Luu y ten: goi NuGet ten la WixToolset.Bal.wixext
# nhung DLL ben trong (va do do ten dung cho -ext) la
# WixToolset.BootstrapperApplications.wixext. Dung ten goi se bao
# "extension could not be found".
foreach ($ext in @('WixToolset.Util.wixext', 'WixToolset.BootstrapperApplications.wixext')) {
    $installed = & wix extension list -g 2>&1 | Select-String -SimpleMatch $ext
    if (-not $installed -or ($installed -match 'damaged')) {
        Write-Host "   Cai extension $ext ..."
        & wix extension add -g "$ext/5.0.2" | Out-Null
    }
}

Write-Host "Phien ban ban cai: $Version" -ForegroundColor Cyan
Write-Host "[1/4] Publish ba project..." -ForegroundColor Cyan
$projects = @(
    'app\service\Service\Service.csproj',
    'app\ui\Shell\Shell.csproj',
    'app\browser-extension\native-host\NativeHost.csproj'
)
foreach ($proj in $projects) {
    $full = Join-Path $repo $proj
    # -p:Version dat luon AssemblyVersion/FileVersion, la thu Windows
    # Installer thuc su so sanh khi quyet dinh co ghi de file hay khong.
    & dotnet publish $full -c $Configuration -r $Rid --self-contained false --nologo -v q "-p:Version=$Version"
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish that bai cho $proj" }
}

Write-Host "[2/4] Chuan bi native messaging host..." -ForegroundColor Cyan
$defines = @()
if ($ChromeExtensionId) {
    & (Join-Path $repo 'app\ops\scripts\generate-native-host-manifest.ps1') -ExtensionId $ChromeExtensionId
    $defines += "-d"; $defines += "ChromeExtensionId=$ChromeExtensionId"
    Write-Host "   Da dong goi tang chong phishing voi extension id $ChromeExtensionId"
} else {
    Write-Host "   BO QUA tang chong phishing: chua co -ChromeExtensionId." -ForegroundColor Yellow
    Write-Host "   Ban cai se KHONG chua native messaging host. Day la lua chon co y:" -ForegroundColor Yellow
    Write-Host "   dong goi voi ID sai = cai mot tang bao ve khong bao gio chay." -ForegroundColor Yellow
}

# [CONG CHAN] Doi chieu output publish voi danh sach <File> trong Product.wxs.
#
# Product.wxs liet ke tung file TUONG MINH. Do la lua chon co chu dich (xem
# ghi chu A2 trong file do), nhung no co mot che do hong rat de xay ra: them
# mot PackageReference vao .csproj ma quen cap nhat danh sach o day. Khi do
# MSI van build thanh cong, van cai duoc, roi service crash luc khoi dong voi
# FileNotFoundException -> Error 1920 -> rollback. Da xay ra dung nhu vay voi
# Microsoft.Extensions.Hosting.WindowsServices.dll.
#
# Kiem o buoc build thi sai sot lo ra ngay tai day, on ao, thay vi lo ra tren
# may nguoi dung duoi dang mot ban cai that bai khong ro nguyen nhan.
Write-Host "[2.5/4] Doi chieu file publish voi Product.wxs..." -ForegroundColor Cyan
$servicePublish = Join-Path $repo "app/service/Service/bin/$Configuration/net9.0-windows/$Rid/publish"
$wxsText = Get-Content (Join-Path $here 'Product.wxs') -Raw
# Nhung duoi khong can thiet luc chay: pdb la symbol, web.config chi danh cho
# IIS (san pham nay tu host Kestrel).
$ignore = @('.pdb', 'web.config')
$missing = @()
foreach ($f in Get-ChildItem $servicePublish -File) {
    if ($ignore | Where-Object { $f.Name -like "*$_" }) { continue }
    if ($wxsText -notmatch [regex]::Escape($f.Name)) { $missing += $f.Name }
}
if ($missing.Count -gt 0) {
    throw ("Product.wxs THIEU " + $missing.Count + " file co trong ban publish cua Service: " +
           ($missing -join ', ') + ". Them chung vao ComponentGroup ServiceComponents truoc khi build, " +
           "neu khong ban cai se hong luc khoi dong service.")
}
Write-Host "   OK - khong thieu file nao."

# [SUA LOI] wix giai cac duong dan Source tuong doi trong Product.wxs theo
# THU MUC HIEN HANH, khong theo vi tri file .wxs. Chay script tu bat ky cho
# nao khac app\installer se lam moi <File Source="..\service\..."> khong tim
# thay -> hang loat WIX0103. Truoc day loi nay con bi che vi thong bao cua
# wix khong duoc in ra, nen no trong nhu mot loi build ngau nhien.
Push-Location $here
try {

Write-Host "[3/4] Build MSI..." -ForegroundColor Cyan
$msi = Join-Path $outDir 'SmePlanAvSetup.msi'
# Dung mot mang tham so day du roi splat. Splat mot mang RONG (@defines khi
# khong co -ChromeExtensionId) vao native command tren Windows PowerShell 5.1
# khong bi bo di ma sinh ra mot doi so rong, lam wix bao loi cu phap.
# -arch x64 la BAT BUOC: khong co no, WiX build goi 32-bit va
# ProgramFiles64Folder giai ra "C:\Program Files (x86)" -- sai cho voi mot ung
# dung win-x64, va cac custom action chay o che do 32-bit.
$msiArgs = @('build', (Join-Path $here 'Product.wxs'), '-arch', 'x64',
             '-d', "ProductVersion=$Version",
             '-ext', 'WixToolset.Util.wixext') + $defines + @('-o', $msi)
# Bat output cua wix de neu that bai thi IN RA nguyen van. Ban truoc chi
# throw mot cau chung chung, lam moi lan hong deu phai chay tay lai wix moi
# biet ly do - dung kieu "nuot chan doan" ma ta vua sua o nhieu cho khac.
$msiOut = & wix @msiArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    $msiOut | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
    throw "wix build (MSI) that bai - xem thong bao ngay tren."
}

Write-Host "[4/4] Build bootstrapper EXE..." -ForegroundColor Cyan
$exe = Join-Path $outDir 'SmePlanAvSetup.exe'
$exeArgs = @('build', (Join-Path $here 'Bundle.wxs'), '-arch', 'x64',
             '-d', "ProductVersion=$Version",
             '-ext', 'WixToolset.BootstrapperApplications.wixext', '-o', $exe)
$exeOut = & wix @exeArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    $exeOut | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
    throw "wix build (bundle) that bai - xem thong bao ngay tren."
}

}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "XONG:" -ForegroundColor Green
Get-Item $msi, $exe | ForEach-Object {
    Write-Host ("  {0}  ({1:N1} MB)" -f $_.FullName, ($_.Length / 1MB))
}
Write-Host ""
Write-Host "Chay SmePlanAvSetup.exe -> Windows se hien hop thoai UAC."
Write-Host "Sau khi cai: service SmePlanAvService chay LocalSystem, tu khoi dong cung Windows."
Write-Host "CANH BAO: ban cai CHUA duoc ky so. Windows SmartScreen se canh bao nguoi dung."
