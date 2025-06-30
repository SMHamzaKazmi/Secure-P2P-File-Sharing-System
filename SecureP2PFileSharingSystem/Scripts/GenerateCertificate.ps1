param (
    [Parameter(Mandatory = $true)]
    [string]$CertName,

    [Parameter(Mandatory = $true)]
    [string]$Password
)

$projectRoot = $PSScriptRoot
$parentOfProjectRoot = Split-Path $projectRoot -Parent
$certFolder = Join-Path $parentOfProjectRoot "Certificates\MyCertificate"

$pfxPath = Join-Path $certFolder "$CertName.pfx"
$cerPath = Join-Path $certFolder "$CertName-public.cer"

$cert = New-SelfSignedCertificate -Subject "CN=$CertName" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable

Write-Host "Certificate '$CertName' created."

Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password (ConvertTo-SecureString -String $Password -AsPlainText -Force)

Write-Host "PFX exported to: $pfxPath"

Export-Certificate -Cert $cert -FilePath $cerPath

Write-Host "CER (public cert) exported to: $cerPath"