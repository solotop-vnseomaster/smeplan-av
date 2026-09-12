<#
.SYNOPSIS
    Ky mot goi CSDL chu ky bang certificate cong ty va tha vao update-drop.

.DESCRIPTION
    Kiem chung DAU-CUOI rang kenh cap nhat that su hoat dong, chu khong chi
    "khong con bao loi". Cau hinh certificate dung ma khong bao gio thu ky va
    ap mot goi that thi khong biet duoc dieu gi ngoai viec file PFX doc duoc.

    Dinh dang goi (xem UpdatePackageVerifier.Sign):
        [4 byte little-endian: do dai chu ky][chu ky RSA-SHA256][noi dung]
    Noi dung goi "full" la CSV chu ky, moi dong:
        <sha256_hex>,<threat_id>,<severity>

    LocalFolderUpdatePackageSource doc:
        manifest.json      -> { "latestVersion": N, "checksum": "" }
        full_v<N>.full     -> goi da ky

    Dat VersionBump > 30 (FullDownloadThresholdVersions) de client di nhanh
    "full download" thay vi tim chuoi goi delta.

.PARAMETER CsvPath
    File CSV chu ky de dong goi. Mac dinh: lay CSDL tich luy hien tai neu co,
    neu khong thi sinh mot file toi thieu chua hash cua chuoi test EICAR.

.EXAMPLE
    .\publish-signature-package.ps1
#>
[CmdletBinding()]
param(
    [string]$CsvPath,
    [int]$VersionBump = 50,
    [string]$DropDir = 'C:\ProgramData\AntivirusApp\update-drop'
)

$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Can quyen Administrator (doc PFX da khoa ACL va ghi vao ProgramData)."
}

$certPath = [Environment]::GetEnvironmentVariable('UpdateSigning__CertPath', 'Machine')
$pwVar    = [Environment]::GetEnvironmentVariable('UpdateSigning__CertPasswordEnvVar', 'Machine')
if ([string]::IsNullOrEmpty($certPath) -or [string]::IsNullOrEmpty($pwVar)) {
    throw "Chua cau hinh ky goi cap nhat. Chay setup-update-signing.ps1 truoc."
}
$pw = [Environment]::GetEnvironmentVariable($pwVar, 'Machine')
if ([string]::IsNullOrEmpty($pw)) { throw "Bien moi truong '$pwVar' chua duoc dat." }

Write-Host "[1/4] Chuan bi noi dung CSDL..." -ForegroundColor Cyan
if (-not $CsvPath) {
    $CsvPath = Join-Path $env:TEMP 'smeplanav-signatures.csv'
    # Hash SHA-256 cua chuoi test EICAR chuan cong khai - dung de kiem chung
    # rang CSDL moi that su duoc nap va dung de phat hien.
    $lines = @(
        '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,1,255'
    )
    Set-Content -Path $CsvPath -Value $lines -Encoding ascii
    Write-Host "   Dung CSV toi thieu (EICAR): $CsvPath"
} else {
    Write-Host "   Dung CSV: $CsvPath"
}
$payload = [System.IO.File]::ReadAllBytes($CsvPath)

Write-Host "[2/4] Ky goi bang certificate cong ty..." -ForegroundColor Cyan
# Luu y: KHONG dung X509CertificateLoader o day. Do la API cua .NET 9 (service
# dung duoc), nhung script nay chay tren Windows PowerShell 5.1 = .NET
# Framework, noi kieu do KHONG ton tai - loi bieu hien ra thanh script treo
# giua chung chu khong bao ro rang. Constructor X509Certificate2 co o ca hai.
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    $certPath, $pw, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet)
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($null -eq $rsa) { throw "Certificate khong co khoa rieng - khong ky duoc." }
$sig = $rsa.SignData($payload,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
Write-Host ("   Chu ky {0} byte, noi dung {1} byte" -f $sig.Length, $payload.Length)

Write-Host "[3/4] Ghi goi vao update-drop..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $DropDir | Out-Null

# Phien ban moi = phien ban hien tai + buoc nhay, de client luon thay "co ban
# moi hon" va di nhanh full download.
$newVersion = $VersionBump
$pkgName = "full_v$newVersion.full"
$pkgPath = Join-Path $DropDir $pkgName

$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)
$bw.Write([int]$sig.Length)   # int32 little-endian, khop BitConverter.ToInt32 phia doc
$bw.Write($sig)
$bw.Write($payload)
$bw.Flush()
[System.IO.File]::WriteAllBytes($pkgPath, $ms.ToArray())
$bw.Dispose(); $ms.Dispose()

$manifest = @{ latestVersion = $newVersion; checksum = '' } | ConvertTo-Json -Compress
Set-Content -Path (Join-Path $DropDir 'manifest.json') -Value $manifest -Encoding ascii

Write-Host ("   {0} ({1} byte) + manifest.json (latestVersion={2})" -f $pkgName, (Get-Item $pkgPath).Length, $newVersion)

Write-Host "[4/4] Yeu cau service kiem tra cap nhat ngay..." -ForegroundColor Cyan
$token = (Get-Content 'C:\ProgramData\AntivirusApp\data\api-token.txt' -Raw).Trim()
$headers = @{ 'X-Av-Token' = $token }
Invoke-RestMethod 'http://127.0.0.1:5270/api/update/check-now' -Method Post -Headers $headers -TimeoutSec 60 | Out-Null
Start-Sleep -Seconds 3

$status = Invoke-RestMethod 'http://127.0.0.1:5270/api/status' -Headers $headers
Write-Host ""
Write-Host "Ket qua:" -ForegroundColor Green
Write-Host ("  Phien ban CSDL hien tai : {0}" -f $status.updateStatus.currentVersion)
Write-Host ("  Ket qua lan cuoi        : {0}" -f $status.updateStatus.lastResult)
if ($status.updateStatus.currentVersion -eq $newVersion) {
    Write-Host "  => Kenh cap nhat HOAT DONG (goi da ky duoc xac minh va ap dung)." -ForegroundColor Green
} else {
    Write-Host "  => CHUA ap dung duoc. Xem lastResult o tren." -ForegroundColor Red
}
