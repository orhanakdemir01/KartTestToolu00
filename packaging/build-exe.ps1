# Build a standalone Windows distribution of KartTest.
#   dist-win\KartTest\
#     KartTest.exe        (C# launcher, compiled with the built-in .NET csc)
#     runtime\node.exe    (bundled Node runtime)
#     app\backend\        (server + node_modules incl. native pcsclite.node)
#     app\frontend\dist\  (built frontend)
# Run from anywhere:  powershell -ExecutionPolicy Bypass -File packaging\build-exe.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out  = Join-Path $root 'dist-win\KartTest'
$node = 'C:\Program Files\nodejs\node.exe'
$csc  = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'

Write-Host '== 1/5 frontend build =='
Push-Location (Join-Path $root 'frontend'); & npx vite build | Out-Null; Pop-Location

Write-Host '== 2/5 klasor hazirlaniyor =='
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Force -Path "$out\runtime","$out\app\backend","$out\app\frontend" | Out-Null

Write-Host '== 3/5 dosyalar kopyalaniyor =='
Copy-Item $node "$out\runtime\node.exe"
Copy-Item "$root\backend\*.js","$root\backend\*.json" "$out\app\backend\"
Copy-Item "$root\backend\node_modules" "$out\app\backend\node_modules" -Recurse
Copy-Item "$root\frontend\dist" "$out\app\frontend\dist" -Recurse

# Backend yalnizca pdfjs ile METIN cikarir (getTextContent), sayfa render etmez —
# bu yuzden canvas/render bagimliliklarini paket kopyasindan buda (~52 MB). Kaynak
# node_modules'e dokunmaz (npm reproducibility korunur). legacy/cmaps/standard_fonts kalir.
Write-Host '== 3b/5 node_modules budaniyor (kullanilmayan pdfjs render parcalari) =='
$nm = "$out\app\backend\node_modules"
$prune = @(
  "$nm\@napi-rs",                    # pdfjs canvas render (kullanilmiyor)
  "$nm\pdfjs-dist\build",            # modern build (biz legacy/build kullaniyoruz)
  "$nm\pdfjs-dist\web",              # tarayici goruntuleyici
  "$nm\pdfjs-dist\image_decoders",  # goruntu cozucu (metin icin gereksiz)
  "$nm\pdfjs-dist\types"            # TypeScript tipleri (runtime disi)
)
foreach ($p in $prune) { if (Test-Path $p) { Remove-Item $p -Recurse -Force } }

Write-Host '== 4/5 launcher derleniyor (csc) =='
& $csc -nologo -target:winexe -out:"$out\KartTest.exe" -r:System.Windows.Forms.dll "$root\packaging\launcher.cs"

Write-Host '== 5/5 OKUBENI =='
@"
KartTest - Smart Card / EMV Test Tool (Windows standalone)

Calistirmak icin: KartTest.exe dosyasina cift tiklayin.
- Bir konsol penceresi acilir (sunucu) ve tarayicinizda uygulama acilir.
- Kapatmak icin konsol penceresini kapatin.

Gereksinim: SDI011 (veya PC/SC uyumlu) kart okuyucu takili olmali.
Bu klasorun TAMAMINI birlikte tasiyin (KartTest.exe, runtime\ ve app\ birlikte gereklidir).
"@ | Set-Content -Path "$out\OKUBENI.txt" -Encoding UTF8

$size = '{0:N0} MB' -f ((Get-ChildItem $out -Recurse | Measure-Object Length -Sum).Sum / 1MB)
Write-Host "TAMAM -> $out  ($size)"
