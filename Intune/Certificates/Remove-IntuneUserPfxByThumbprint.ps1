<# =====================================================================
  Remove-IntuneUserPfxByThumbprint.ps1
  - Removes a specific userPFXCertificate (by thumbprint) from all users
    in a given Entra security group (handles nested groups)
  - Primary: Remove-IntuneUserPfxCertificate (module)
  - Fallback: Direct Graph DELETE on /beta/deviceManagement/userPfxCertificates/{id}
  - Uses IntunePfxImport.psd1 for Intune auth + app-only Graph auth
  - Verifies after each phase
  - PS 5.1 compatible
===================================================================== #>

[CmdletBinding()]
param(
  # Provide either -GroupId OR -GroupDisplayName
  [string]$GroupId            = "e06efa01-5ea3-431d-8596-cf16f429a5a0",  # Get the Entra Security Group "Object Id"
  [string]$GroupDisplayName   = "",

  # Thumbprint to remove (any case/spacing ok)
  [string]$ThumbprintToRemove = "E09EC94E86A7CADF57E1F978D7CEA1AFC5A31A5D",

  # Path to your module manifest (contains TenantId/ClientId/ClientSecret)
  [string]$IntunePfxImportModulePath = "C:\Abion\IntunePfxImport\Release\IntunePfxImport.psd1",

  # Preview only (no changes)
  [switch]$DryRun,

  # Max items per remove call (sane batching)
  [int]$BatchSize = 50
)

# --- Normalize & validate target thumbprint ----------------------------------
if ([string]::IsNullOrWhiteSpace($ThumbprintToRemove)) {
  throw "ThumbprintToRemove is empty. Set it in the param block (or pass -ThumbprintToRemove)."
}
$TP_UPPER = ($ThumbprintToRemove -replace '\s','').ToUpperInvariant()
$TP_LOWER = $TP_UPPER.ToLowerInvariant()  # Graph IDs typically use lowercase in the Id suffix

# --- Load your module & read PrivateData (Tenant/Client/Secret) -------------
Write-Host "Loading IntunePfxImport module..." -ForegroundColor Cyan
Import-Module $IntunePfxImportModulePath -ErrorAction Stop

$resolvedManifestPath = (Resolve-Path $IntunePfxImportModulePath).Path
$moduleInfo = Get-Module | Where-Object { $_.Path -eq $resolvedManifestPath }
if (-not $moduleInfo) { $moduleInfo = Test-ModuleManifest -Path $resolvedManifestPath }

$appCfg = $moduleInfo.PrivateData
if (-not $appCfg -or -not $appCfg.TenantId -or -not $appCfg.ClientId -or -not $appCfg.ClientSecret) {
  throw "Could not read TenantId/ClientId/ClientSecret from $resolvedManifestPath PrivateData."
}

$TenantId  = [string]$appCfg.TenantId
$ClientId  = [string]$appCfg.ClientId
$SecSecret = ConvertTo-SecureString ([string]$appCfg.ClientSecret) -AsPlainText -Force
$AppCred   = New-Object System.Management.Automation.PSCredential ($ClientId, $SecSecret)

# Intune token for module cmdlets
Set-IntuneAuthenticationToken

# --- Microsoft Graph (APP-ONLY) ---------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ensure Graph submodules
if (-not (Get-Module Microsoft.Graph.Authentication -ListAvailable)) {
  Install-Module Microsoft.Graph.Authentication -Scope AllUsers -Force -AllowClobber
}
if (-not (Get-Module Microsoft.Graph.Groups -ListAvailable)) {
  Install-Module Microsoft.Graph.Groups -Scope AllUsers -Force -AllowClobber
}
if (-not (Get-Module Microsoft.Graph.Users -ListAvailable)) {
  Install-Module Microsoft.Graph.Users -Scope AllUsers -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Users

Write-Host "Connecting to Microsoft Graph (app-only)..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $AppCred -NoWelcome

# --- Helpers -----------------------------------------------------------------

# Enumerate transitive user members; return UPNs (handles nested groups)
function Get-GroupUsersUpn {
  param([string]$GroupId, [string]$GroupDisplayName)

  if ([string]::IsNullOrWhiteSpace($GroupId)) {
    $grp = Get-MgGroup -Filter "displayName eq '$GroupDisplayName'" -All | Select-Object -First 1
    if (-not $grp) { throw "Group '$GroupDisplayName' not found." }
    $GroupId = $grp.Id
  }

  $upns = New-Object System.Collections.Generic.List[string]
  $uri  = "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=userPrincipalName&`$top=999"

  while ($uri) {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
    foreach ($u in $resp.value) {
      if ($u.userPrincipalName) { [void]$upns.Add($u.userPrincipalName) }
    }
    $uri = $resp.'@odata.nextLink'
  }

  return ($upns | Sort-Object -Unique)
}

# Map UPN -> User ObjectId (GUID)
function Get-UserIdFromUpn {
  param([string]$Upn)
  try {
    $u = Get-MgUser -UserId $Upn -Property Id,UserPrincipalName
    return $u.Id
  } catch {
    $u = Get-MgUser -All -Filter ("userPrincipalName eq '{0}'" -f $Upn) | Select-Object -First 1 -Property Id,UserPrincipalName
    if ($u) { return $u.Id }
    throw "Could not resolve ObjectId for UPN '$Upn'."
  }
}

# Safely get a user's existing PFX entries via module
function Get-UserPfxEntries {
  param([string]$Upn)
  try {
    Get-IntuneUserPfxCertificate -UserList $Upn -ErrorAction Stop
  } catch {
    Write-Warning ("Get-IntuneUserPfxCertificate failed for {0}: {1}" -f $Upn, $_.Exception.Message)
    @()
  }
}

# Create a UserThumbprint object: properties are 'User' and 'Thumbprint'
# User must be the OBJECT ID (GUID), not the UPN
function New-UserThumbprintObject {
  param([string]$UserObjectId, [string]$ThumbprintLower)
  $obj = New-Object Microsoft.Management.Powershell.PFXImport.Cmdlets.UserThumbprint
  $obj.User       = $UserObjectId
  $obj.Thumbprint = $ThumbprintLower
  return $obj
}

# Convenience: Graph list of a user's userPfxCertificates (beta) and return matches
function Get-UserPfxGraphMatches {
  param([string]$Upn, [string]$ThumbprintUpper)
  $matches = @()
  try {
    $filter = "userPrincipalName eq '$Upn'"
    $uri    = "https://graph.microsoft.com/beta/deviceManagement/userPfxCertificates?`$filter=" + [System.Web.HttpUtility]::UrlEncode($filter)
    $resp   = Invoke-MgGraphRequest -Method GET -Uri $uri
    foreach ($item in $resp.value) {
      $tp = (($item.thumbprint) -replace '\s','')
      if ($tp -and ($tp.ToUpperInvariant() -eq $ThumbprintUpper)) {
        $matches += $item
      }
    }
  } catch {
    Write-Warning ("Graph lookup for existing PFX on {0} failed: {1}" -f $Upn, $_.Exception.Message)
  }
  return $matches
}

# Graph DELETE helper
function Remove-UserPfxViaGraphId {
  param([string]$Id)
  $uri = "https://graph.microsoft.com/beta/deviceManagement/userPfxCertificates/$Id"
  Invoke-MgGraphRequest -Method DELETE -Uri $uri
}

# --- Resolve users -----------------------------------------------------------
$usersUpn = Get-GroupUsersUpn -GroupId $GroupId -GroupDisplayName $GroupDisplayName
if (-not $usersUpn -or $usersUpn.Count -eq 0) { throw "No user members found for the specified group." }
Write-Host ("Users to evaluate: {0}" -f ($usersUpn -join ", ")) -ForegroundColor Gray

# Build UPN -> ObjectId map (cache)
$userIdMap = @{}
foreach ($upn in $usersUpn) {
  try { $userIdMap[$upn] = Get-UserIdFromUpn -Upn $upn }
  catch { Write-Warning $_.Exception.Message }
}

# --- Build removal list for module call -------------------------------------
$toRemoveModule = New-Object System.Collections.Generic.List[Microsoft.Management.Powershell.PFXImport.Cmdlets.UserThumbprint]
$plannedUPNs    = New-Object System.Collections.Generic.List[string]
$skipped        = New-Object System.Collections.Generic.List[string]

foreach ($upn in $usersUpn) {
  if (-not $userIdMap.ContainsKey($upn)) { [void]$skipped.Add($upn); continue }
  $entries = Get-UserPfxEntries -Upn $upn
  if (-not $entries) { [void]$skipped.Add($upn); continue }
  $match = $entries | Where-Object { (($_.Thumbprint -replace '\s','').ToUpperInvariant()) -eq $TP_UPPER }
  if ($match) {
    $userObjId = $userIdMap[$upn]
    [void]$toRemoveModule.Add( (New-UserThumbprintObject -UserObjectId $userObjId -ThumbprintLower $TP_LOWER) )
    [void]$plannedUPNs.Add($upn)
  } else {
    [void]$skipped.Add($upn)
  }
}

Write-Host ("Found {0} user(s) with target thumbprint {1}" -f $toRemoveModule.Count, $TP_UPPER) -ForegroundColor Cyan
if ($DryRun) {
  if ($toRemoveModule.Count) {
    "Would remove (module):"; $plannedUPNs | Sort-Object | ForEach-Object { "  - $_" }
  } else { "No matches found; nothing to remove." }
  if ($skipped.Count) { "`nUsers without that thumbprint:`n  - " + (($skipped | Sort-Object) -join "`n  - ") }
  return
}

# --- Phase 1: Module removal -------------------------------------------------
$removedUPNs_Ph1 = New-Object System.Collections.Generic.List[string]
$failedBatches    = New-Object System.Collections.Generic.List[string]

if ($toRemoveModule.Count -gt 0) {
  $index = 0
  while ($index -lt $toRemoveModule.Count) {
    $take  = [Math]::Min($BatchSize, $toRemoveModule.Count - $index)
    $chunk = $toRemoveModule.GetRange($index, $take)

    try {
      [Microsoft.Management.Powershell.PFXImport.Cmdlets.UserThumbprint[]]$chunkArr = $chunk
      Remove-IntuneUserPfxCertificate -UserThumbprintList $chunkArr -ErrorAction Stop

      # Record the UPNs we *attempted* here
      $start = $index
      $end   = $index + $take - 1
      for ($i=$start; $i -le $end; $i++) {
        if ($i -lt $plannedUPNs.Count) { [void]$removedUPNs_Ph1.Add($plannedUPNs[$i]) }
      }

      $msg = [string]::Format("Removed batch with {0} user(s) (index {1}..{2})", $take, ($index+1), ($index+$take))
      Write-Host $msg -ForegroundColor Green
    } catch {
      $msg = $_.Exception.Message
      Write-Warning ("Module batch starting at index {0} failed: {1}" -f $index, $msg)
      [void]$failedBatches.Add(("Module idx {0}: {1}" -f $index, $msg))
    }

    $index += $take
  }
}

# --- Verify after Phase 1 ----------------------------------------------------
$stillPresent = New-Object System.Collections.Generic.List[string]
foreach ($upn in ($removedUPNs_Ph1 | Sort-Object -Unique)) {
  try {
    $post = Get-IntuneUserPfxCertificate -UserList $upn -ErrorAction Stop
    $exists = $post | Where-Object { (($_.Thumbprint -replace '\s','').ToUpperInvariant()) -eq $TP_UPPER }
    if ($exists) { [void]$stillPresent.Add($upn) }
  } catch {
    Write-Warning ("Post-check failed for {0}: {1}" -f $upn, $_.Exception.Message)
  }
}

# --- Phase 2 (Fallback): Graph DELETE by resource Id -------------------------
$deletedViaGraphUPNs = New-Object System.Collections.Generic.List[string]
$graphDeleteErrors   = New-Object System.Collections.Generic.List[string]

if ($stillPresent.Count -gt 0) {
  Write-Host "Fallback: deleting via Graph resource Id..." -ForegroundColor Yellow
  foreach ($upn in ($stillPresent | Sort-Object -Unique)) {
    # List PFX objects for this UPN and delete the matching one(s)
    $matches = Get-UserPfxGraphMatches -Upn $upn -ThumbprintUpper $TP_UPPER
    if (-not $matches -or $matches.Count -eq 0) { continue }
    foreach ($m in $matches) {
      try {
        if ($DryRun) {
          "Would DELETE Graph Id: $($m.id) for $upn"
        } else {
          Remove-UserPfxViaGraphId -Id $m.id
          [void]$deletedViaGraphUPNs.Add($upn)
          Write-Host ("Deleted via Graph: {0}" -f $upn) -ForegroundColor Green
        }
      } catch {
        $graphDeleteErrors.Add(("$upn - " + $_.Exception.Message)) | Out-Null
      }
    }
  }
}

# --- Final verification ------------------------------------------------------
$stillPresent2 = New-Object System.Collections.Generic.List[string]
foreach ($upn in ($plannedUPNs | Sort-Object -Unique)) {
  try {
    $post = Get-IntuneUserPfxCertificate -UserList $upn -ErrorAction Stop
    $exists = $post | Where-Object { (($_.Thumbprint -replace '\s','').ToUpperInvariant()) -eq $TP_UPPER }
    if ($exists) { [void]$stillPresent2.Add($upn) }
  } catch {
    Write-Warning ("Final post-check failed for {0}: {1}" -f $upn, $_.Exception.Message)
  }
}

# --- Summary (PS 5.1 friendly) ----------------------------------------------
$groupLabel = if ([string]::IsNullOrWhiteSpace($GroupId)) { $GroupDisplayName } else { $GroupId }

"`n================ Removal Summary ================"
(" Thumbprint (target)          : {0}" -f $TP_UPPER)
(" Group                        : {0}" -f $groupLabel)
(" Phase 1 - Module attempted   : {0}" -f $removedUPNs_Ph1.Count)
if ($removedUPNs_Ph1.Count) { "  -> " + (($removedUPNs_Ph1 | Sort-Object -Unique) -join ", ") }
(" Phase 1 - Module failed batch: {0}" -f $failedBatches.Count)
if ($failedBatches.Count)  { "  -> " + ($failedBatches -join "`n     ") }
(" Phase 2 - Graph deleted      : {0}" -f $deletedViaGraphUPNs.Count)
if ($deletedViaGraphUPNs.Count)  { "  -> " + (($deletedViaGraphUPNs | Sort-Object -Unique) -join ", ") }
(" Still present after final check: {0}" -f $stillPresent2.Count)
if ($stillPresent2.Count) { "  -> " + (($stillPresent2 | Sort-Object -Unique) -join ", ") }
"=================================================="
