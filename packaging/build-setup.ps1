# Build a single self-installing KartTest-Setup.exe (payload embedded as a zip
# resource). Requires dist-win\KartTest\ (run build-exe.ps1 first).
#   powershell -ExecutionPolicy Bypass -File packaging\build-setup.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist-win\KartTest'
$zip  = Join-Path $env:TEMP 'karttest-payload.zip'
$out  = Join-Path $root 'dist-win\KartTest-Setup.exe'
$csc  = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

if (-not (Test-Path $dist)) { throw "Once build-exe.ps1 calistirin ($dist yok)." }

Write-Host '== 1/2 payload zip olusturuluyor =='
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $dist '*') -DestinationPath $zip -CompressionLevel Optimal

Write-Host '== 2/2 Setup.exe derleniyor (csc, gomulu payload) =='
& $csc -nologo -target:winexe -out:$out `
  -r:System.Windows.Forms.dll -r:System.IO.Compression.dll -r:System.IO.Compression.FileSystem.dll `
  -resource:"$zip,payload.zip" `
  (Join-Path $root 'packaging\setup.cs')

Remove-Item $zip -Force
$mb = '{0:N0} MB' -f ((Get-Item $out).Length / 1MB)
Write-Host "TAMAM -> $out  ($mb)"
