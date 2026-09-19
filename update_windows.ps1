# Aktualizace NMAP Scanner PT Lab z GitHubu (pro prenosnou kopii bez gitu).
# Zjisti verzi na GitHubu, a je-li novejsi, stahne ZIP hlavni vetve a prepise
# programove soubory. Zachova .venv i uzivatelska data.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$owner = 'Safronus'; $repo = 'NMAPScannerPTLab'; $branch = 'main'
$rawVer = "https://raw.githubusercontent.com/$owner/$repo/$branch/nmapscanner/__init__.py"
$zipUrl = "https://github.com/$owner/$repo/archive/refs/heads/$branch.zip"
$ua = @{ 'User-Agent' = 'NMAPScanner-PTLab' }

function Get-Ver([string]$t) {
  if ($t -match 'VERSION\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"') { return $Matches[1] }
  return ''
}

Write-Host "=== Aktualizace NMAP Scanner PT Lab z GitHubu ==="
$local = ''
if (Test-Path 'nmapscanner\__init__.py') { $local = Get-Ver (Get-Content 'nmapscanner\__init__.py' -Raw) }
Write-Host "Lokalni verze: $local"

try {
  $remoteText = (Invoke-WebRequest -Uri $rawVer -UseBasicParsing -Headers $ua).Content
} catch {
  Write-Host "[CHYBA] Nepodarilo se zjistit verzi na GitHubu: $($_.Exception.Message)"
  Read-Host 'Enter pro zavreni'; exit 1
}
$remote = Get-Ver $remoteText
Write-Host "GitHub verze:  $remote"
if ([string]::IsNullOrEmpty($remote)) { Write-Host 'Nepodarilo se precist vzdalenou verzi.'; Read-Host 'Enter'; exit 1 }
if ($local -eq $remote) { Write-Host "[OK] Mas nejnovejsi verzi ($remote)."; Read-Host 'Enter pro zavreni'; exit 0 }

Write-Host "Stahuji novou verzi $remote ..."
$tmp = Join-Path $env:TEMP ("nmapscanner_upd_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$zip = Join-Path $tmp 'src.zip'
Invoke-WebRequest -Uri $zipUrl -OutFile $zip -UseBasicParsing -Headers $ua
Expand-Archive -Path $zip -DestinationPath $tmp -Force
$src = Get-ChildItem -Path $tmp -Directory | Select-Object -First 1
if (-not $src) { Write-Host '[CHYBA] Rozbaleni selhalo.'; Read-Host 'Enter'; exit 1 }

Write-Host 'Kopiruji nove soubory (zachovavam .venv a data) ...'
robocopy $src.FullName $PSScriptRoot /E /XD .venv .git windows-package NMAPScannerPTLab.app __pycache__ .preview /XF *.pyc /NFL /NDL /NJH /NJS /NP | Out-Null
$rc = $LASTEXITCODE
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
if ($rc -ge 8) { Write-Host "[CHYBA] Kopirovani selhalo (robocopy kod $rc)."; Read-Host 'Enter'; exit 1 }

Write-Host ""
Write-Host "[HOTOVO] Aktualizovano na verzi $remote. Spust run_windows.bat."
Read-Host 'Enter pro zavreni'
