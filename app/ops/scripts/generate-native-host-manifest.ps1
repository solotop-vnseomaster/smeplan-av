<#
.SYNOPSIS
    Sinh native_host_manifest.json that tu file template, dien ID extension.

.DESCRIPTION
    [SUA LOI NGHIEM TRONG] TRUOC DAY app/browser-extension/native-host/
    native_host_manifest.json duoc CHECK-IN voi nguyen van placeholder
    "<EXTENSION_ID_SE_DIEN_KHI_DANG_KY_THAT>" trong allowed_origins, va
    Product.wxs dong goi CHINH file do roi ghi duong dan cua no vao
    HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts. Chrome doi chieu
    allowed_origins voi ID that cua extension dang goi; mot chuoi placeholder
    khong bao gio khop, nen Chrome TU CHOI moi ket noi native messaging.
    Toan bo tang chong phishing (extension -> native host -> service) vi the
    tat 100% tren moi may cai bang MSI -- im lang, khong loi, khong log.

    Sua theo hai lop:
      1. File check-in doi thanh *.template.json voi placeholder
         __CHROME_EXTENSION_ID__ -- khong the vo tinh dong goi nham nua.
      2. Script nay sinh ra file that va TU CHOI chay neu ID khong dung dinh
         dang ID extension cua Chrome (32 ky tu a-p).

.EXAMPLE
    .\generate-native-host-manifest.ps1 -ExtensionId abcdefghijklmnopabcdefghijklmnop
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExtensionId,

    [string]$TemplatePath = (Join-Path $PSScriptRoot '..\..\browser-extension\native-host\native_host_manifest.template.json'),
    [string]$OutputPath   = (Join-Path $PSScriptRoot '..\..\browser-extension\native-host\native_host_manifest.json')
)

$ErrorActionPreference = 'Stop'

# ID extension cua Chrome luon la 32 ky tu trong khoang 'a'..'p'. Kiem tra
# chat o day de mot gia tri sai (vi du van con placeholder, hoac ID cua ban
# unpacked bi dan nham) khong the di tiep vao ban cai.
if ($ExtensionId -notmatch '^[a-p]{32}$') {
    throw "ExtensionId khong hop le: '$ExtensionId'. Phai la dung 32 ky tu trong khoang a-p (ID extension Chrome)."
}

if (-not (Test-Path -LiteralPath $TemplatePath)) {
    throw "Khong tim thay template: $TemplatePath"
}

$content = Get-Content -LiteralPath $TemplatePath -Raw
if ($content -notmatch '__CHROME_EXTENSION_ID__') {
    throw "Template khong chua placeholder __CHROME_EXTENSION_ID__ -- kiem tra lai $TemplatePath"
}

# Thay chuoi thuan tuy: KHONG di qua ConvertFrom-Json/ConvertTo-Json, vi vong
# do se dien giai lai cac dau '' trong truong "path" cua manifest.
$content = $content.Replace('__CHROME_EXTENSION_ID__', $ExtensionId)
Set-Content -LiteralPath $OutputPath -Value $content -Encoding utf8 -NoNewline

Write-Host "Da sinh $OutputPath voi extension id $ExtensionId"
