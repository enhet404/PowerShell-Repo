<# ================================================
  Idempotent PFX upload to Intune for all users in a group
  - Uses IntunePfxImport.psd1 for upload
  - App-only Microsoft Graph auth using ClientId/Secret from the module
  - Resolves users via transitiveMembers -> microsoft.graph.user (gets nested group members too)
  - Skips users who already have the same PFX thumbprint

  App registration (Application permissions, with admin consent):
    - DeviceManagementConfiguration.ReadWrite.All
    - Group.Read.All
    - User.Read.All
================================================ #>

[CmdletBinding()]
param(
  # Provide either -GroupId OR -GroupDisplayName
  [string]$GroupId            = "16556f0a-dea0-4e02-8028-aa07e70b9ba6", # Get the Entra Security Group "Object Id"
  [string]$GroupDisplayName   = "",

  # PFX + password
  [string]$PfxPath            = "C:\Abion\IntunePfxImport\PFXCerts\dominfo_admin_prod.p12",
  [string]$PfxPasswordPlain   = "PASSWORD", # <— plain text; handle with care

  # IntunePfxImport parameters
  [string]$ProviderName       = "Microsoft Software Key Storage Provider",
  [string]$KeyName            = "PFXEncryptionKey",
  [ValidateSet("smimeEncryption","smimeSigning","vpn","wifi","unassigned")]
  [string]$IntendedPurpose    = "unassigned",

  # Path to your module manifest
  [string]$IntunePfxImportModulePath = "C:\Abion\IntunePfxImport\Release\IntunePfxImport.psd1"
)

# --- Load your module & read PrivateData (Tenant/Client/Secret) -------------
Write-Host "Loading IntunePfxImport module..." -ForegroundColor Cyan
Import-Module $IntunePfxImportModulePath -ErrorAction Stop

$moduleInfo = Get-Module | Where-Object { $_.Path -eq (Resolve-Path $IntunePfxImportModulePath).Path }
if (-not $moduleInfo) { $moduleInfo = Test-ModuleManifest -Path $IntunePfxImportModulePath }

$appCfg = $moduleInfo.PrivateData
if (-not $appCfg -or -not $appCfg.TenantId -or -not $appCfg.ClientId -or -not $appCfg.ClientSecret) {
  throw "Could not read TenantId/ClientId/ClientSecret from $IntunePfxImportModulePath PrivateData."
}

$TenantId = [string]$appCfg.TenantId
$ClientId = [string]$appCfg.ClientId
$SecSecret = ConvertTo-SecureString ([string]$appCfg.ClientSecret) -AsPlainText -Force
$AppCred   = New-Object System.Management.Automation.PSCredential ($ClientId, $SecSecret)

# Intune token for your upload cmdlets
Set-IntuneAuthenticationToken

# --- Microsoft Graph (APP-ONLY) ---------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ensure modules are available
if (-not (Get-Module Microsoft.Graph.Authentication -ListAvailable)) {
  Install-Module Microsoft.Graph.Authentication -Scope AllUsers -Force -AllowClobber
}
if (-not (Get-Module Microsoft.Graph.Groups -ListAvailable)) {
  Install-Module Microsoft.Graph.Groups -Scope AllUsers -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Groups

# App-only connect
Write-Host "Connecting to Microsoft Graph (app-only)..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $AppCred -NoWelcome

# --- Helpers -----------------------------------------------------------------
function Get-ThumbprintFromPfx {
  param([string]$Path, [securestring]$Password)
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  $cert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
  $cert.Import($bytes, $Password, "MachineKeySet,EphemeralKeySet")
  return ($cert.Thumbprint -replace '\s','').ToUpperInvariant()
}

# NEW: Enumerate transitive user members, returns UPNs (handles nested groups)
function Get-GroupUsersUpn {
  param([string]$GroupId, [string]$GroupDisplayName)

  # Resolve GroupId if only display name provided
  if (-not $GroupId) {
    $grp = Get-MgGroup -Filter "displayName eq '$GroupDisplayName'" -All | Select-Object -First 1
    if (-not $grp) { throw "Group '$GroupDisplayName' not found." }
    $GroupId = $grp.Id
  }

  $upns = New-Object System.Collections.Generic.List[string]
  $uri  = "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=userPrincipalName&`$top=999"

  while ($uri) {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
    foreach ($u in $resp.value) {
      if ($u.userPrincipalName) { $upns.Add($u.userPrincipalName) | Out-Null }
    }
    $uri = $resp.'@odata.nextLink'
  }

  return ($upns | Sort-Object -Unique)
}

# Try module getter first; else call Graph /beta for userPfxCertificates
function Get-ExistingUserPfxThumbprints {
  param([string]$Upn)

  $thumbs = @()

  $getCmd = Get-Command -Name Get-UserPFXCertificate -ErrorAction SilentlyContinue
  if ($getCmd) {
    try {
      $existing = Get-UserPFXCertificate -Upn $Upn -ErrorAction Stop
      foreach ($e in $existing) {
        if ($e.Thumbprint) { $thumbs += ($e.Thumbprint -replace '\s','').ToUpperInvariant() }
      }
      return ($thumbs | Sort-Object -Unique)
    } catch {
      Write-Verbose ("Get-UserPFXCertificate failed for {0}: {1}" -f $Upn, $_.Exception.Message)
    }
  }

  try {
    $filter = "userPrincipalName eq '$Upn'"
    $uri    = "https://graph.microsoft.com/beta/deviceManagement/userPfxCertificates?`$filter=" + [System.Web.HttpUtility]::UrlEncode($filter)
    $resp   = Invoke-MgGraphRequest -Method GET -Uri $uri
    foreach ($item in $resp.value) {
      if ($item.thumbprint) { $thumbs += ($item.thumbprint -replace '\s','').ToUpperInvariant() }
    }
  } catch {
    Write-Warning ("Graph lookup for existing PFX on {0} failed: {1}" -f $Upn, $_.Exception.Message)
  }

  return ($thumbs | Sort-Object -Unique)
}

# --- Prep --------------------------------------------------------------------
$securePfxPassword = ConvertTo-SecureString -String $PfxPasswordPlain -AsPlainText -Force
$targetThumbprint  = Get-ThumbprintFromPfx -Path $PfxPath -Password $securePfxPassword
Write-Host "Target PFX thumbprint: $targetThumbprint" -ForegroundColor Cyan

$users = Get-GroupUsersUpn -GroupId $GroupId -GroupDisplayName $GroupDisplayName
if (-not $users -or $users.Count -eq 0) { throw "No user members found in the specified group." }
Write-Host ("Users to evaluate: {0}" -f ($users -join ", ")) -ForegroundColor Gray

# --- Run ---------------------------------------------------------------------
$added   = New-Object System.Collections.Generic.List[string]
$skipped = New-Object System.Collections.Generic.List[string]
$failed  = New-Object System.Collections.Generic.List[string]

foreach ($upn in $users) {
  try {
    $existingThumbs = Get-ExistingUserPfxThumbprints -Upn $upn
    if ($existingThumbs -contains $targetThumbprint) {
      Write-Host ("[{0}] Already has target PFX (thumbprint match). Skipping." -f $upn) -ForegroundColor DarkYellow
      $skipped.Add($upn) | Out-Null
      continue
    }

    $userPFXObject = New-IntuneUserPfxCertificate `
      -PathToPfxFile  $PfxPath `
      -PfxPassword    $securePfxPassword `
      -Upn            $upn `
      -ProviderName   $ProviderName `
      -KeyName        $KeyName `
      -IntendedPurpose $IntendedPurpose

    Import-IntuneUserPfxCertificate -CertificateList $userPFXObject

    Write-Host ("[{0}] Uploaded PFX." -f $upn) -ForegroundColor Green
    $added.Add($upn) | Out-Null
  }
  catch {
    $msg = $_.Exception.Message
    Write-Warning ("[{0}] Failed: {1}" -f $upn, $msg)
    $failed.Add("$upn`t$msg") | Out-Null
  }
}

# --- Summary -----------------------------------------------------------------
Write-Host "`n================ Summary ================" -ForegroundColor Cyan
Write-Host (" Added : {0}"  -f $added.Count)   -ForegroundColor Green
Write-Host (" Skipped: {0}" -f $skipped.Count) -ForegroundColor Yellow
Write-Host (" Failed : {0}" -f $failed.Count)  -ForegroundColor Red

if ($added.Count)   { Write-Host ("  -> " + ($added   -join ", ")) -ForegroundColor Green }
if ($skipped.Count) { Write-Host ("  -> " + ($skipped -join ", ")) -ForegroundColor Yellow }
if ($failed.Count)  { 
  Write-Host "  -> Failures:" -ForegroundColor Red
  $failed | ForEach-Object { Write-Host ("     " + $_) -ForegroundColor Red }
}

Write-Host "=========================================" -ForegroundColor Cyan
