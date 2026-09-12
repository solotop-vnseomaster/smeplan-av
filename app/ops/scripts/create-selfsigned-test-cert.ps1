<#
.SYNOPSIS
  Tao self-signed test certificate va dang ky vao Trusted Root/Trusted
  Publisher cuc bo de Windows chap nhan driver ky thu trong luc phat trien.
  Khop ops/08-trien-khai.md muc 3 buoc 4.

.DESCRIPTION
  CHI dung cho moi truong dev (da bat testsigning qua
  enable-dev-testsigning.ps1). KHONG dung cho ban phat hanh — ban phat
  hanh bat buoc phai dung EV Code Signing Certificate that mua qua
  Microsoft Partner Center, ky driver qua attestation/WHQL.
#>
[CmdletBinding()]
param(
    [string]$Subject = "CN=SmePlanAv Dev Test Certificate (KHONG DUNG CHO PHAT HANH)"
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Script nay can chay voi quyen Administrator."
    exit 1
}

# [SUA LOI NGHIEM TRONG] -Subject TRUOC DAY khong duoc validate gi ca, va
# certificate tao ra duoc cai VAO LocalMachine\Root (tin cay he thong). Do
# la mat xich dau cua mot chuoi leo thang len SYSTEM da duoc xac minh day du:
#   1. chay script voi -Subject "CN=Microsoft Corporation";
#   2. cert vao Trusted Root => WinVerifyTrust bao chuoi HOP LE;
#   3. AuthenticodeVerifier.IsMicrosoftPublisher so khop TEN PUBLISHER bang
#      chuoi => bao dung la Microsoft;
#   4. dat binary vao mot thu muc duoi %WINDIR% ma nguoi dung thuong ghi
#      duoc (C:\Windows\Tasks) => du ca 3 tieu chi trusted-by-default.
# (Mat xich 4 da duoc va rieng trong ProcessTrustEngine.cs; day la mat xich 1.)
#
# Sua: tu choi bat ky Subject nao mao danh nha cung cap co that. Day la
# script DEV — khong co ly do hop le nao de tao cert mang ten Microsoft,
# Google, Adobe... va cai no vao Trusted Root cua may.
$forbiddenSubjects = @(
    'microsoft', 'windows', 'google', 'mozilla', 'adobe', 'apple', 'oracle',
    'intel', 'nvidia', 'amd', 'symantec', 'verisign', 'digicert', 'sectigo',
    'globalsign', 'entrust', 'thawte', 'comodo', 'amazon', 'meta', 'ibm'
)
foreach ($forbidden in $forbiddenSubjects) {
    if ($Subject.ToLowerInvariant().Contains($forbidden)) {
        Write-Error @"
TU CHOI: -Subject chua ten nha cung cap co that ("$forbidden").
Script nay cai certificate vao LocalMachine\Root (tin cay he thong). Mot
cert tu ky mang ten mot nha cung cap that se lam moi kiem tra chu ky so
tren may nay — bao gom kiem tra trusted-by-default cua chinh san pham —
tin nham binary cua ban la cua nha cung cap do.
"@
        exit 1
    }
}

if (-not $Subject.StartsWith('CN=')) {
    Write-Error "-Subject phai bat dau bang 'CN='."
    exit 1
}

# [SUA LOI NGHIEM TRONG — GUARD CANH SAI TRUC] Danh sach $forbiddenSubjects
# o tren chan viec mao danh TEN nha cung cap. Nhung rui ro that cua script
# nay khong nam o ten tren certificate — no nam o cho: mot certificate ky ma
# co KHOA RIENG XUAT DUOC dang duoc cai vao LocalMachine\Root, tuc la mot
# trust anchor cho TOAN MAY.
# Mac dinh cua New-SelfSignedCertificate la -KeyExportPolicy
# ExportableEncrypted, nghia la bat ky ai chay duoc code duoi tai khoan da
# tao cert deu rut duoc khoa riêng ra file .pfx, roi ky BAT KY nhi phan nao
# va may se tin no. Mot Subject hoan toan "sach" nhu
# "CN=SmePlanAv Update Authority" di qua danh sach chan tren mot cach de dang
# va van cho ra dung ket qua do.
# Sua: khoa xuat khau. Khoa van dung duoc de KY (dung muc dich cua script),
# chi la khong con boc ra khoi may duoc nua.
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy NonExportable `
    -FriendlyName "SmePlanAv Dev Test Cert" `
    -NotAfter (Get-Date).AddYears(3)

Write-Host "Da tao certificate: $($cert.Thumbprint)"

$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close()

$publisherStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
$publisherStore.Open("ReadWrite")
$publisherStore.Add($cert)
$publisherStore.Close()

Write-Host "Da dang ky vao Trusted Root va Trusted Publisher (LocalMachine)." -ForegroundColor Green
Write-Host "Dung thumbprint nay de ky driver test: signtool sign /sha1 $($cert.Thumbprint) /fd SHA256 <file.sys>"
