<#
.SYNOPSIS
    Tao certificate ky goi cap nhat cua CONG TY va bat kenh cap nhat CSDL.

.DESCRIPTION
    Sau khi cai dat, service chay ngoai moi truong Development nen
    CompanyCertificateProvider TU CHOI dung certificate dev (mat khau
    hard-code trong source) - dung nhu no phai the. Ket qua la kenh cap nhat
    tat, va CSDL chu ky dong bang vinh vien o phien ban hien tai.

    Script nay dung nguoc lai tinh huong do:

      1. Tao mot self-signed code-signing certificate rieng cho SmePlanAv.
         KHONG can mua certificate: muc dich cua no khong phai de Windows tin
         tuong, ma de service CHI NHAN goi cap nhat do chinh to chuc nay ky.
         Do dung y do ghi trong CompanyCertificateProvider.cs ("certificate
         cua cong ty, khong phai ben thu ba").

      2. Xuat ra file PFX voi mat khau NGAU NHIEN manh, dat trong
         %ProgramData%\AntivirusApp\signing va khoa ACL chi cho
         SYSTEM + Administrators.

      3. Dat ba bien moi truong CAP MAY de service (chay LocalSystem) doc
         duoc qua IConfiguration:
              UpdateSigning__CertPath
              UpdateSigning__CertPasswordEnvVar
              <ten bien mat khau>
         Dung bien moi truong thay vi sua appsettings.json trong Program
         Files: cau hinh nhu vay song qua moi lan cai lai/nang cap.

    DANH DOI CAN BIET: mat khau PFX nam o bien moi truong cap may, nen moi
    tai khoan Administrator tren may deu doc duoc. Chap nhan duoc cho trien
    khai mot may / noi bo. Voi day chuyen phat hanh that, khoa ky nen nam o
    may build rieng, khong phai may chay AV.

.PARAMETER Rotate
    Tao lai certificate moi ke ca khi da co. Luu y: goi da ky bang cert cu
    se KHONG con duoc chap nhan.

.EXAMPLE
    .\setup-update-signing.ps1
#>
[CmdletBinding()]
param(
    [switch]$Rotate,
    [string]$SigningDir = 'C:\ProgramData\AntivirusApp\signing',
    [string]$PasswordEnvVarName = 'SMEPLANAV_SIGNING_PFX_PASSWORD',
    [string]$Subject = 'CN=SmePlanAv Update Signing, O=SmePlanAv'
)

$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Script nay can PowerShell chay quyen Administrator (ghi vao ProgramData va dat bien moi truong cap may)."
}

$pfxPath = Join-Path $SigningDir 'company-update-signing.pfx'

if ((Test-Path $pfxPath) -and -not $Rotate) {
    Write-Host "Da co certificate tai $pfxPath. Dung -Rotate neu muon tao lai." -ForegroundColor Yellow
} else {
    Write-Host "[1/4] Tao self-signed code-signing certificate..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $SigningDir | Out-Null

    # Cert nam trong kho cua MAY (khong phai cua user) va co the xuat khoa
    # rieng de ky goi. HashAlgorithm SHA256 khop voi UpdatePackageVerifier
    # (RSA-SHA256).
    $cert = New-SelfSignedCertificate `
        -Subject $Subject `
        -Type CodeSigningCert `
        -KeyAlgorithm RSA -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable `
        -CertStoreLocation 'Cert:\LocalMachine\My' `
        -NotAfter (Get-Date).AddYears(5)

    Write-Host "   Thumbprint: $($cert.Thumbprint)"

    Write-Host "[2/4] Xuat PFX voi mat khau ngau nhien..." -ForegroundColor Cyan
    # 32 byte ngau nhien ma hoa base64 - khong ai (ke ca nguoi chay script)
    # phai nho hay go lai mat khau nay.
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $plain = [Convert]::ToBase64String($bytes)
    $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force

    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $secure -Force | Out-Null

    # Go cert khoi kho May: khoa rieng da nam trong PFX duoc ACL bao ve; de
    # lai trong store chi tao them mot ban sao nua can canh giu.
    Remove-Item "Cert:\LocalMachine\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue

    Write-Host "[3/4] Khoa ACL cho PFX (chi SYSTEM + Administrators)..." -ForegroundColor Cyan
    # Xoa moi ACE ke thua VA moi ACE explicit co san, roi dung lai tu dau -
    # cung nguyen tac nhu AclProtection.ProtectFile trong service.
    $acl = Get-Acl $pfxPath
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    foreach ($sidType in @('LocalSystemSid', 'BuiltinAdministratorsSid')) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier(
            [System.Security.Principal.WellKnownSidType]::$sidType, $null)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, 'FullControl', 'Allow')))
    }
    Set-Acl -Path $pfxPath -AclObject $acl

    Write-Host "[4/4] Dat bien moi truong cap may..." -ForegroundColor Cyan
    [Environment]::SetEnvironmentVariable($PasswordEnvVarName, $plain, 'Machine')
    [Environment]::SetEnvironmentVariable('UpdateSigning__CertPath', $pfxPath, 'Machine')
    [Environment]::SetEnvironmentVariable('UpdateSigning__CertPasswordEnvVar', $PasswordEnvVarName, 'Machine')
}

Write-Host ""
Write-Host "Cau hinh hien tai:" -ForegroundColor Green
foreach ($n in @('UpdateSigning__CertPath', 'UpdateSigning__CertPasswordEnvVar')) {
    Write-Host ("  {0,-34} = {1}" -f $n, [Environment]::GetEnvironmentVariable($n, 'Machine'))
}
$pwName = [Environment]::GetEnvironmentVariable('UpdateSigning__CertPasswordEnvVar', 'Machine')
$pwSet = -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($pwName, 'Machine'))
Write-Host ("  {0,-34} = {1}" -f $pwName, $(if ($pwSet) { '(da dat)' } else { '(CHUA dat)' }))

Write-Host ""
Write-Host "Khoi dong lai service de nap cau hinh moi..." -ForegroundColor Cyan
$svc = Get-Service SmePlanAvService -ErrorAction SilentlyContinue
if ($null -ne $svc) {
    Restart-Service SmePlanAvService -Force
    Start-Sleep -Seconds 6
    Write-Host ("  SmePlanAvService: {0}" -f (Get-Service SmePlanAvService).Status)
} else {
    Write-Host "  (service chua duoc cai - bo qua)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Xong. Kiem tra bang: .\check-protection-status.ps1"
Write-Host "Muc 'update-channel' phai bien mat khoi danh sach suy giam."
