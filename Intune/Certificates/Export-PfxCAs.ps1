<# =====================================================================
 Export-PfxCAs.ps1
 - Extracts CA certs (Root + Intermediates) from a .pfx/.p12 using OpenSSL
 - Writes DER .cer files for Intune "Trusted certificate" profiles
 - Self-contained: hardcoded inputs below + verbose enabled

 OUTPUT (in $OutDir):
   root.cer, root_2.cer (if multiple roots)
   intermediate_1.cer, intermediate_2.cer, ...

 REQUIREMENTS
   - OpenSSL in PATH (3.x OK). If PFX uses legacy ciphers (e.g., RC2),
     ensure legacy.dll is available and OPENSSL_MODULES points to its folder.
===================================================================== #>

# -------- Hardcoded inputs (edit here) ---------------------------------------
$PfxPath     = "C:\Abion\IntunePfxImport\PFXCerts\dominfo_admin_prod.p12"
$PfxPassword = "PASSWORD" # <— plain text; handle with care
$OutDir      = "C:\Abion\IntunePfxImport\Export"

# Always run verbose for this script
$VerbosePreference = 'Continue'

# -------- Helpers ------------------------------------------------------------
function Assert-File {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
  if ((Get-Item -LiteralPath $Path).Length -lt 32) { throw "File looks too small/corrupt: $Path" }
}

function Convert-PemToCerts {
  <# Extract all -----BEGIN/END CERTIFICATE----- blocks from a PEM string #>
  param([string]$PemString)

  $text = $PemString
  if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
  $text = $text -replace "`r`n","`n"

  # Singleline (?s) so '.' matches newlines
  $rx = [regex]'(?s)-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----'
  $matches = $rx.Matches($text)
  Write-Verbose ("Found {0} PEM block(s)." -f $matches.Count)

  $certs = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]
  foreach ($m in $matches) {
    $b64 = ($m.Groups[1].Value -replace '\s','')
    try {
      $raw = [Convert]::FromBase64String($b64)
      $certs.Add( (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $raw)) ) | Out-Null
    } catch {
      Write-Verbose "Skipping malformed PEM block."
    }
  }
  return ,$certs.ToArray()
}

function Is-CA {
  param([System.Security.Cryptography.X509Certificates.X509Certificate2]$c)
  foreach ($ext in $c.Extensions) {
    if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
      if ($ext.CertificateAuthority) { return $true }
    }
  }
  return $false
}

function Is-RootCA {
  param([System.Security.Cryptography.X509Certificates.X509Certificate2]$c)
  return (Is-CA $c) -and ($c.Subject -eq $c.Issuer)
}

# -------- Validate & prep ----------------------------------------------------
Assert-File -Path $PfxPath
if (-not (Test-Path -LiteralPath $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir | Out-Null
  Write-Verbose "Created output folder: $OutDir"
}

$ossl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $ossl) { throw "OpenSSL not found on PATH. Install OpenSSL and try again." }

# Ensure OpenSSL can find providers (legacy/default) if needed
if (-not $env:OPENSSL_MODULES) {
  $osslDir = Split-Path $ossl.Path
  $cands = @(
    (Join-Path $osslDir 'ossl-modules'),
    (Join-Path $osslDir '..\lib\ossl-modules'),
    $osslDir,
    'C:\Program Files\OpenSSL-Win64\bin',
    'C:\Program Files\OpenSSL\lib\ossl-modules'
  )
  foreach ($d in $cands) {
    if (Test-Path (Join-Path $d 'legacy.dll') -and Test-Path (Join-Path $d 'default.dll')) {
      $env:OPENSSL_MODULES = (Resolve-Path $d).Path
      Write-Verbose "OPENSSL_MODULES set to: $($env:OPENSSL_MODULES)"
      break
    }
  }
}

# -------- Extract the CA chain with OpenSSL (no keys) ------------------------
$tmp = Join-Path $env:TEMP ("pfxca_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
$chainPem = Join-Path $tmp "chain.pem"

try {
  Write-Verbose "Extracting CA chain with OpenSSL..."
  & $ossl.Path pkcs12 -legacy -in $PfxPath -passin "pass:$PfxPassword" -cacerts -nokeys -out $chainPem 2>$null
  if ($LASTEXITCODE -ne 0) {
    & $ossl.Path pkcs12 -provider-path "$env:OPENSSL_MODULES" -provider legacy -provider default `
       -in $PfxPath -passin "pass:$PfxPassword" -cacerts -nokeys -out $chainPem
  }

  if (-not (Test-Path -LiteralPath $chainPem)) {
    throw "OpenSSL did not produce a CA chain PEM. Wrong password or unsupported PFX?"
  }

  $pem = Get-Content -LiteralPath $chainPem -Raw
  $cas = Convert-PemToCerts -PemString $pem
  if (-not $cas -or $cas.Count -eq 0) { throw "No CA certificates found in chain." }

  $roots = @($cas | Where-Object { Is-RootCA $_ })
  $intermediates = @($cas | Where-Object { (Is-CA $_) -and ($_.Subject -ne $_.Issuer) })

  if ($roots.Count -eq 0) {
    Write-Warning "No self-signed CA found in chain. Will export all CA certs to 'intermediate_*.cer'."
  }

  # Export roots
  $rootCount = 0
  foreach ($r in $roots) {
    $rootCount++
    $file = if ($rootCount -eq 1) { Join-Path $OutDir "root.cer" } else { Join-Path $OutDir ("root_{0}.cer" -f $rootCount) }

    $rootPem = Join-Path $tmp ("root_{0}.pem" -f $rootCount)
    $b64 = [System.Convert]::ToBase64String($r.RawData, 'InsertLineBreaks')
@"
-----BEGIN CERTIFICATE-----
$b64
-----END CERTIFICATE-----
"@ | Set-Content -LiteralPath $rootPem -Encoding ascii

    & $ossl.Path x509 -in $rootPem -outform DER -out $file
    if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $file)) {
      Write-Host ("Exported ROOT: {0}" -f $file) -ForegroundColor Green
      Write-Verbose ("  Subject: {0}" -f $r.Subject)
      Write-Verbose ("  Thumbprint: {0}" -f ($r.Thumbprint -replace '\s','').ToUpper())
    } else {
      Write-Warning ("Failed to write {0}" -f $file)
    }
  }

  # Export intermediates (if any) — or all CAs if no self-signed root was detected
  $intList = if ($roots.Count -gt 0) { $intermediates } else { $cas }
  $intCount = 0
  foreach ($ic in $intList) {
    $intCount++
    $file = Join-Path $OutDir ("intermediate_{0}.cer" -f $intCount)

    $intPem = Join-Path $tmp ("intermediate_{0}.pem" -f $intCount)
    $b64 = [System.Convert]::ToBase64String($ic.RawData, 'InsertLineBreaks')
@"
-----BEGIN CERTIFICATE-----
$b64
-----END CERTIFICATE-----
"@ | Set-Content -LiteralPath $intPem -Encoding ascii

    & $ossl.Path x509 -in $intPem -outform DER -out $file
    if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $file)) {
      Write-Host ("Exported INTERMEDIATE: {0}" -f $file) -ForegroundColor Green
      Write-Verbose ("  Subject: {0}" -f $ic.Subject)
      Write-Verbose ("  Thumbprint: {0}" -f ($ic.Thumbprint -replace '\s','').ToUpper())
    } else {
      Write-Warning ("Failed to write {0}" -f $file)
    }
  }

  Write-Host ""
  Write-Host "Done." -ForegroundColor Cyan
  Write-Host ("  Roots exported        : {0}" -f $rootCount) -ForegroundColor Cyan
  Write-Host ("  Intermediates exported: {0}" -f $intCount) -ForegroundColor Cyan
  Write-Host ("  Output folder         : {0}" -f $OutDir) -ForegroundColor Cyan
}
finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
}
