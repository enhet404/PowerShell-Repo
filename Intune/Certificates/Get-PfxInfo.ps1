<# =====================================================================
 Get-PfxInfo-Resilient.ps1  (hardcoded path & password)
 - Prints Subject, NotBefore/NotAfter, SHA-1 (Thumbprint), SHA-256
 - Classifies contained certs as Leaf / IntermediateCA / RootCA
 - Order of attempts:
     1) .NET (X509Certificate2Collection)
        + If no CA found, "chain top-up" via OpenSSL (extract CA chain only)
     2) If .NET import fails, OpenSSL (extract leaf + chain) -> parse via .NET
 - PS 5.1 compatible
===================================================================== #>

# --- Hardcoded inputs --------------------------------------------------------
$PfxPath       = "C:\Abion\IntunePfxImport\PFXCerts\dominfo_admin_prod.p12"
$PasswordPlain = "PASSWORD"   # <— plain text; handle with care

# ---------------------------------------------------------------------------
function Get-Sha256Hex { param([byte[]]$Bytes)
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try { -join ($sha256.ComputeHash($Bytes) | ForEach-Object { $_.ToString("X2") }) }
  finally { $sha256.Dispose() }
}

function New-CertRow {
  param(
    [string]$Source,
    [string]$Kind,
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$c,
    [Nullable[bool]]$HasPrivateKeyOverride = $null
  )
  $hasKey = if ($HasPrivateKeyOverride -ne $null) { $HasPrivateKeyOverride } else { $c.HasPrivateKey }
  [PSCustomObject]@{
    Source       = $Source
    Kind         = $Kind
    Subject      = $c.Subject
    Issuer       = $c.Issuer
    NotBefore    = $c.NotBefore
    NotAfter     = $c.NotAfter
    HasPrivateKey= $hasKey
    Thumbprint   = ($c.Thumbprint -replace '\s','').ToUpper()
    SHA256       = (Get-Sha256Hex -Bytes $c.RawData)
  }
}

function Classify-Cert {
  param([System.Security.Cryptography.X509Certificates.X509Certificate2]$c, [bool]$AssumeLeafIfUnknown = $true)
  $isCA = $false
  foreach ($ext in $c.Extensions) {
    if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
      if ($ext.CertificateAuthority) { $isCA = $true; break }
    }
  }
  $selfSigned = ($c.Subject -eq $c.Issuer)
  if ($isCA -and $selfSigned) { return 'RootCA' }
  if ($isCA) { return 'IntermediateCA' }
  if ($c.HasPrivateKey -or $AssumeLeafIfUnknown) { return 'Leaf' }
  return 'Other'
}

function Convert-PemToCerts {
  <# Robustly extracts all CERT blocks from a PEM string and returns X509Certificate2[] #>
  param([string]$PemString)

  # Normalize and strip any BOM
  $text = $PemString
  if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
  $text = $text -replace "`r`n","`n"

  # Singleline so '.' matches newlines
  $rx = [regex]'(?s)-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----'
  $matches = $rx.Matches($text)
  Write-Host ("  - Found {0} PEM certificate block(s)." -f $matches.Count) -ForegroundColor DarkGray

  $list = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]
  foreach ($m in $matches) {
    $b64 = ($m.Groups[1].Value -replace '\s','')
    try {
      $raw = [Convert]::FromBase64String($b64)
      $list.Add( (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $raw)) ) | Out-Null
    } catch {
      Write-Host "    ! Skipped one malformed block." -ForegroundColor DarkYellow
    }
  }
  return ,$list.ToArray()
}

# Safety checks
if (-not (Test-Path -LiteralPath $PfxPath)) { throw "File not found: $PfxPath" }
if ((Get-Item $PfxPath).Length -lt 32)      { throw "PFX looks too small; may be corrupt: $PfxPath" }

$securePwd = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
$rows   = @()
$loaded = $false

# --- 1) Try managed (.NET) import -------------------------------------------
$attempts = @(
  @{ Type='Collection+Secure'; Flags='MachineKeySet,EphemeralKeySet' },
  @{ Type='Collection+Secure'; Flags='UserKeySet,EphemeralKeySet'    },
  @{ Type='Single+String'   ; Flags='MachineKeySet,EphemeralKeySet'  },
  @{ Type='Single+String'   ; Flags='UserKeySet,EphemeralKeySet'     }
)
foreach ($a in $attempts) {
  try {
    if ($a.Type -eq 'Collection+Secure') {
      $coll = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
      [void]$coll.Import($PfxPath, $securePwd, $a.Flags)
      if ($coll.Count -gt 0) {
        foreach ($c in $coll) {
          $rows += (New-CertRow -Source 'ManagedImport' -Kind (Classify-Cert -c $c) -c $c -HasPrivateKeyOverride:($c.HasPrivateKey))
        }
        $loaded = $true
        break
      }
    } else {
      $plain = [Runtime.InteropServices.Marshal]::PtrToStringUni(
                 [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd))
      $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
      $cert.Import($PfxPath, $plain, $a.Flags)
      $rows += (New-CertRow -Source 'ManagedImport' -Kind (Classify-Cert -c $cert) -c $cert)
      $loaded = $true
      break
    }
  } catch { }
}

# --- 1b) If .NET succeeded but found no CA, top-up chain via OpenSSL --------
if ($loaded -and -not ($rows | Where-Object { $_.Kind -in 'IntermediateCA','RootCA' })) {
  $ossl = Get-Command openssl -ErrorAction SilentlyContinue
  if ($ossl) {
    # Ensure providers (legacy/default) are discoverable
    if (-not $env:OPENSSL_MODULES) {
      $osslDir = Split-Path $ossl.Path
      $cands = @(
        (Join-Path $osslDir 'ossl-modules'),
        (Join-Path $osslDir '..\lib\ossl-modules'),
        $osslDir
      )
      foreach ($d in $cands) {
        if (Test-Path (Join-Path $d 'legacy.dll') -and Test-Path (Join-Path $d 'default.dll')) {
          $env:OPENSSL_MODULES = (Resolve-Path $d).Path
          break
        }
      }
    }

    $tmp = Join-Path $env:TEMP ("pfxinfo_chain_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $chainPem = Join-Path $tmp "chain.pem"
    try {
      # Extract CA chain only (no keys)
      & $ossl.Path pkcs12 -legacy -in $PfxPath -passin "pass:$PasswordPlain" -cacerts -nokeys -out $chainPem 2>$null
      if ($LASTEXITCODE -ne 0) {
        & $ossl.Path pkcs12 -provider-path "$env:OPENSSL_MODULES" -provider legacy -provider default `
          -in $PfxPath -passin "pass:$PasswordPlain" -cacerts -nokeys -out $chainPem
      }

      if (Test-Path $chainPem) {
        $pem = Get-Content -LiteralPath $chainPem -Raw
        $certs = Convert-PemToCerts -PemString $pem
        foreach ($c in $certs) {
          $rows += (New-CertRow -Source 'OpenSSL' -Kind (Classify-Cert -c $c -AssumeLeafIfUnknown:$false) -c $c)
        }
      }
    } finally {
      Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    }
  }
}

# --- 2) If .NET import failed entirely, use OpenSSL for leaf+chain ----------
if (-not $loaded) {
  $ossl = Get-Command openssl -ErrorAction SilentlyContinue
  if (-not $ossl) {
    Write-Warning "OpenSSL not found on PATH; cannot parse PFX on this machine."
  } else {
    # Ensure providers (legacy/default) are discoverable
    if (-not $env:OPENSSL_MODULES) {
      $osslDir = Split-Path $ossl.Path
      $cands = @(
        (Join-Path $osslDir 'ossl-modules'),
        (Join-Path $osslDir '..\lib\ossl-modules'),
        $osslDir
      )
      foreach ($d in $cands) {
        if (Test-Path (Join-Path $d 'legacy.dll') -and Test-Path (Join-Path $d 'default.dll')) {
          $env:OPENSSL_MODULES = (Resolve-Path $d).Path
          break
        }
      }
    }

    $tmp = Join-Path $env:TEMP ("pfxinfo_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $leafPem  = Join-Path $tmp "leaf.pem"
    $chainPem = Join-Path $tmp "chain.pem"
    try {
      Write-Host "Using OpenSSL to extract PEMs..." -ForegroundColor DarkGray

      # Leaf (end-entity) — no keys
      & $ossl.Path pkcs12 -legacy -in $PfxPath -passin "pass:$PasswordPlain" -clcerts -nokeys -out $leafPem 2>$null
      if ($LASTEXITCODE -ne 0) {
        & $ossl.Path pkcs12 -provider-path "$env:OPENSSL_MODULES" -provider legacy -provider default `
          -in $PfxPath -passin "pass:$PasswordPlain" -clcerts -nokeys -out $leafPem
      }

      # Chain (CA certs) — no keys
      & $ossl.Path pkcs12 -legacy -in $PfxPath -passin "pass:$PasswordPlain" -cacerts -nokeys -out $chainPem 2>$null
      if ($LASTEXITCODE -ne 0) {
        & $ossl.Path pkcs12 -provider-path "$env:OPENSSL_MODULES" -provider legacy -provider default `
          -in $PfxPath -passin "pass:$PasswordPlain" -cacerts -nokeys -out $chainPem
      }

      if (Test-Path $leafPem) {
        $pem = Get-Content -LiteralPath $leafPem -Raw
        Write-Host ("  Leaf PEM size: {0} bytes" -f ((Get-Item $leafPem).Length)) -ForegroundColor DarkGray
        $certs = Convert-PemToCerts -PemString $pem
        foreach ($c in $certs) { $rows += (New-CertRow -Source 'OpenSSL' -Kind 'Leaf' -c $c) }
      } else {
        Write-Host "  Leaf PEM not produced." -ForegroundColor DarkYellow
      }

      if (Test-Path $chainPem) {
        $pem = Get-Content -LiteralPath $chainPem -Raw
        Write-Host ("  Chain PEM size: {0} bytes" -f ((Get-Item $chainPem).Length)) -ForegroundColor DarkGray
        $certs = Convert-PemToCerts -PemString $pem
        foreach ($c in $certs) { $rows += (New-CertRow -Source 'OpenSSL' -Kind (Classify-Cert -c $c -AssumeLeafIfUnknown:$false) -c $c) }
      } else {
        Write-Host "  Chain PEM not produced." -ForegroundColor DarkYellow
      }

      $loaded = ($rows.Count -gt 0)
    } finally {
      Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    }
  }
}

# -------------------- Output (grouped) ---------------------------------------
$leaf  = $rows | Where-Object { $_.Kind -eq 'Leaf' }
$icas  = $rows | Where-Object { $_.Kind -eq 'IntermediateCA' }
$roots = $rows | Where-Object { $_.Kind -eq 'RootCA' }
$other = $rows | Where-Object { $_.Kind -notin @('Leaf','IntermediateCA','RootCA') }

Write-Host "`n=== Leaf certificate(s) ===" -ForegroundColor Cyan
if ($leaf) {
  $leaf | Select-Object Subject,Issuer,NotAfter,HasPrivateKey,Thumbprint,SHA256 | Format-List
} else { Write-Host "None found." -ForegroundColor DarkYellow }

Write-Host "`n=== Intermediate CA certificate(s) ===" -ForegroundColor Cyan
if ($icas) {
  $icas | Select-Object Subject,Issuer,NotAfter,Thumbprint,SHA256 | Format-List
} else { Write-Host "None found." -ForegroundColor DarkYellow }

Write-Host "`n=== Root CA certificate(s) ===" -ForegroundColor Cyan
if ($roots) {
  $roots | Select-Object Subject,Issuer,NotAfter,Thumbprint,SHA256 | Format-List
} else { Write-Host "None found." -ForegroundColor DarkYellow }

if ($other) {
  Write-Host "`n=== Other entries (unclassified) ===" -ForegroundColor Cyan
  $other | Select-Object Source,Kind,Subject,Issuer,NotAfter,Thumbprint | Format-List
}
