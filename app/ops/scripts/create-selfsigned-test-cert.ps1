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

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyUsage DigitalSignature `
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
