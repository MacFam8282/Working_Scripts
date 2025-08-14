<# 
.SYNOPSIS
  Remote into a Windows host, set up a writable SMB share, and provide a menu to view/upload/download files.
  Optionally spins up a minimal read-only HTTP index server on the remote for quick browsing.

.PARAMETER ComputerName
  DNS name or IP of the remote Windows host.

.PARAMETER Credential
  Credentials to use for remoting. If omitted, you’ll be prompted securely.

.PARAMETER UseSSL
  Use WinRM over HTTPS (requires remote to be configured for HTTPS).

.PARAMETER LocalPath
  Default local folder for downloads.

.PARAMETER StartServer
  If set, creates a minimal HTTP file server on the remote that serves files from -ServerRoot on -ServerPort (GET only).

.PARAMETER ServerRoot
  Remote directory that is used both for the SMB share and the HTTP index. Default: C:\Temp\Drop

.PARAMETER ShareName
  SMB share name to create on the remote. Default: Drop

.PARAMETER ServerPort
  Port for the remote HTTP server. Default: 8080

.PARAMETER ServerRestrictTo
  Optional IP/CIDR to restrict the temporary HTTP firewall rule on the remote.

.EXAMPLE
  .\RemoteFetchAndServe.ps1 -ComputerName host01 -StartServer -ServerRoot C:\Shares\Ops -ShareName OpsDrop -Verbose
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
  [Parameter(Mandatory)][string]$ComputerName,
  [Parameter()][pscredential]$Credential,
  [switch]$UseSSL,

  [Parameter()][string]$LocalPath = (Join-Path -Path $PWD -ChildPath '.'),

  [switch]$StartServer,
  [string]$ServerRoot = 'C:\Temp\Drop',
  [string]$ShareName  = 'Drop',
  [int]$ServerPort = 8080,
  [string]$ServerRestrictTo
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-PreReqs {
  Write-Verbose "Testing WinRM reachability on $ComputerName..."
  try {
    Test-WSMan -ComputerName $ComputerName -UseSSL:$UseSSL | Out-Null
  } catch {
    throw "WinRM not reachable on $ComputerName. Ensure PowerShell Remoting is enabled and firewall allows it. Error: $($_.Exception.Message)"
  }
}

function New-RemoteSession {
  param([string]$Computer,[pscredential]$Cred,[switch]$SSL)
  if (-not $Cred) { $Cred = Get-Credential -Message "Credentials for $Computer" }
  $opts = @{
    ComputerName   = $Computer
    Credential     = $Cred
    Authentication = 'Default'
  }
  if ($SSL) { $opts['UseSSL'] = $true }
  Write-Verbose "Creating PSSession to $Computer..."
  New-PSSession @opts
}

function Ensure-RemoteShare {
  <#
    Creates (or fixes) the remote folder and SMB share with read/write for authenticated users.
    Also enables the File & Printer Sharing firewall rules if available.
  #>
  param(
    [System.Management.Automation.Runspaces.PSSession]$Session,
    [string]$SharePath,
    [string]$ShareName
  )

  $script = {
    param($SharePath,$ShareName)
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if (-not (Test-Path -LiteralPath $SharePath -PathType Container)) {
      New-Item -ItemType Directory -Path $SharePath | Out-Null
    }

    # Try modern SMB cmdlets; fallback to 'net share' on older systems
    $smbModule = Get-Command -Name New-SmbShare -ErrorAction SilentlyContinue
    if ($smbModule) {
      # Remove conflicting share name if pointing elsewhere
      $existing = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
      if ($existing) {
        if ($existing.Path -ne (Resolve-Path -LiteralPath $SharePath).Path) {
          Revoke-SmbShareAccess -Name $ShareName -AccountName 'Everyone' -Force -ErrorAction SilentlyContinue | Out-Null
          Set-SmbShare -Name $ShareName -Description '' -FolderEnumerationMode AccessBased -CachingMode None -ConcurrentUserLimit 0
          # If path mismatch, remove and recreate
          Remove-SmbShare -Name $ShareName -Force
          $existing = $null
        }
      }
      if (-not $existing) {
        New-SmbShare -Name $ShareName -Path $SharePath -CachingMode None -Temporary:$false -FullAccess 'Authenticated Users' | Out-Null
      } else {
        # Ensure write access
        Grant-SmbShareAccess -Name $ShareName -AccountName 'Authenticated Users' -AccessRight Full -Force -ErrorAction SilentlyContinue | Out-Null
      }

      # Enable SMB/File & Printer Sharing rules if present
      try {
        Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue | Out-Null
        Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing (SMB-In)' -ErrorAction SilentlyContinue | Out-Null
      } catch { }
    }
    else {
      # Fallback to 'net share'—grants read/write for everyone
      & cmd /c "net share $ShareName=`"$SharePath`" /GRANT:Everyone,FULL" | Out-Null
      try {
        & netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes | Out-Null
      } catch { }
    }

    # Return UNC and path
    [pscustomobject]@{
      SharePath = (Resolve-Path -LiteralPath $SharePath).Path
      Share     = "\\$env:COMPUTERNAME\$ShareName"
    }
  }

  $info = Invoke-Command -Session $Session -ScriptBlock $script -ArgumentList $SharePath,$ShareName
  Write-Host "✅ Remote SMB share ready: $($info.Share) ($($info.SharePath))"
  return $info
}

function Resolve-RemoteFile {
  param([System.Management.Automation.Runspaces.PSSession]$Session, [string]$Path)
  if (-not $Path) {
    $Path = Read-Host -Prompt "Enter FULL remote file path on $($Session.ComputerName)"
  }
  $sb = {
    param($P)
    if (Test-Path -LiteralPath $P -PathType Leaf) {
      Get-Item -LiteralPath $P | Select-Object FullName, Length, LastWriteTime
    } else {
      throw "File not found: $P"
    }
  }
  Invoke-Command -Session $Session -ScriptBlock $sb -ArgumentList $Path
}

function Receive-RemoteFile {
  param(
    [System.Management.Automation.Runspaces.PSSession]$Session,
    [string]$RemoteFile,
    [string]$LocalDestination
  )
  if (Test-Path -LiteralPath $LocalDestination -PathType Container) {
    $fileName = Split-Path -Path $RemoteFile -Leaf
    $LocalFinal = Join-Path -Path $LocalDestination -ChildPath $fileName
  } else {
    $LocalDir = Split-Path -Path $LocalDestination -Parent
    if (-not (Test-Path -LiteralPath $LocalDir -PathType Container)) {
      New-Item -ItemType Directory -Path $LocalDir | Out-Null
    }
    $LocalFinal = $LocalDestination
  }
  Write-Verbose "Copying $RemoteFile from $($Session.ComputerName) to $LocalFinal ..."
  try {
    Copy-Item -Path $RemoteFile -Destination $LocalFinal -FromSession $Session -Force
  } catch {
    throw "Copy failed: $($_.Exception.Message)"
  }
  Write-Host "✅ Downloaded to $LocalFinal"
}

function Send-LocalFile {
  param(
    [System.Management.Automation.Runspaces.PSSession]$Session,
    [string]$LocalFile,
    [string]$RemoteFolder
  )
  if (-not (Test-Path -LiteralPath $LocalFile -PathType Leaf)) {
    throw "Local file not found: $LocalFile"
  }
  # Ensure remote folder exists
  Invoke-Command -Session $Session -ScriptBlock { param($p) if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p | Out-Null } } -ArgumentList $RemoteFolder
  $dest = Join-Path -Path $RemoteFolder -ChildPath (Split-Path -Path $LocalFile -Leaf)
  Write-Verbose "Uploading $LocalFile to $($Session.ComputerName): $dest ..."
  try {
    Copy-Item -Path $LocalFile -Destination $dest -ToSession $Session -Force
  } catch {
    throw "Upload failed: $($_.Exception.Message)"
  }
  Write-Host "✅ Uploaded to $dest"
}

function List-RemoteFiles {
  param([System.Management.Automation.Runspaces.PSSession]$Session,[string]$Folder)
  $sb = { param($f) if (-not (Test-Path -LiteralPath $f -PathType Container)) { return @() }
          Get-ChildItem -LiteralPath $f -File -Recurse | Select-Object FullName, Length, LastWriteTime | Sort-Object FullName }
  Invoke-Command -Session $Session -ScriptBlock $sb -ArgumentList $Folder
}

function Start-RemoteHttpServer {
  param(
    [System.Management.Automation.Runspaces.PSSession]$Session,
    [string]$Root,
    [int]$Port,
    [string]$RestrictTo
  )
  $serverScript = {
    param($Root, $Port, $RestrictTo)
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
      New-Item -ItemType Directory -Path $Root | Out-Null
    }

    $url = "http://+:$Port/"
    try { & netsh http add urlacl url=$url user="Everyone" | Out-Null } catch { }

    $fwName = "Temp-HttpFileServer-$Port"
    if (Get-Command -Name New-NetFirewallRule -ErrorAction SilentlyContinue) {
      try {
        Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null
        $fwParams = @{
          DisplayName = $fwName; Direction = 'Inbound'; Action = 'Allow'
          Protocol='TCP'; LocalPort=$Port; Profile='Domain,Private'
        }
        if ($RestrictTo) { $fwParams['RemoteAddress'] = $RestrictTo }
        New-NetFirewallRule @fwParams | Out-Null
      } catch { }
    }

    $jobName = "SimpleHttpFileServer_$Port"
    $existing = Get-Job -Name $jobName -ErrorAction SilentlyContinue
    if ($existing) { Stop-Job $existing -Force; Remove-Job $existing -Force }

    $null = Start-Job -Name $jobName -ScriptBlock {
      param($Root,$Port)
      Add-Type -AssemblyName System.Net.HttpListener
      $listener = [System.Net.HttpListener]::new()
      $prefix = "http://+:$Port/"
      $listener.Prefixes.Add($prefix)
      $listener.Start()
      try {
        while ($true) {
          $ctx = $listener.GetContext()
          $req = $ctx.Request
          $res = $ctx.Response
          if ($req.HttpMethod -ne 'GET') { $res.StatusCode = 405; $res.Close(); continue }

          $rel = $req.Url.AbsolutePath.TrimStart('/')
          if ([string]::IsNullOrWhiteSpace($rel)) { $rel = 'index.html' }

          if ($rel -ieq 'index.html') {
            $files = Get-ChildItem -Path $Root -File -Recurse | Sort-Object FullName
            $html = "<html><body><h3>Files under $Root</h3><ul>" +
                    ($files | ForEach-Object { '<li><a href="' + ($_.FullName.Substring($Root.Length).TrimStart('\').Replace('\','/')) + '">' + $_.Name + '</a></li>' }) -join '' +
                    "</ul></body></html>"
            $bytes = [Text.Encoding]::UTF8.GetBytes($html)
            $res.ContentType = 'text/html'
            $res.OutputStream.Write($bytes,0,$bytes.Length)
            $res.Close(); continue
          }

          $requested = Join-Path -Path $Root -ChildPath ($rel -replace '/','\')
          $requested = [IO.Path]::GetFullPath($requested)
          $rootFull  = [IO.Path]::GetFullPath($Root)
          if (-not $requested.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) { $res.StatusCode = 403; $res.Close(); continue }
          if (-not (Test-Path -LiteralPath $requested -PathType Leaf)) { $res.StatusCode = 404; $res.Close(); continue }

          try {
            $bytes = [IO.File]::ReadAllBytes($requested)
            $res.ContentType = 'application/octet-stream'
            $res.AddHeader('Content-Disposition', 'attachment; filename="' + [IO.Path]::GetFileName($requested) + '"')
            $res.OutputStream.Write($bytes,0,$bytes.Length)
            $res.StatusCode = 200
          } catch { $res.StatusCode = 500 } finally { $res.Close() }
        }
      } finally { $listener.Stop(); $listener.Close() }
    } -ArgumentList $Root,$Port

    [pscustomobject]@{ JobName="SimpleHttpFileServer_$Port"; Port=$Port; Url="http://$env:COMPUTERNAME`:$Port/"; Root=$Root; Firewall="Temp-HttpFileServer-$Port" }
  }

  $info = Invoke-Command -Session $Session -ScriptBlock $serverScript -ArgumentList $Root,$Port,$RestrictTo
  Write-Host "🚀 Remote HTTP index started: http://$($Session.ComputerName):$($info.Port)/"
  return $info
}

function Stop-RemoteHttpServer {
  param([System.Management.Automation.Runspaces.PSSession]$Session,[int]$Port)
  $stopScript = {
    param($Port)
    $jobName = "SimpleHttpFileServer_$Port"
    Get-Job -Name $jobName -ErrorAction SilentlyContinue | Stop-Job -Force -ErrorAction SilentlyContinue
    Get-Job -Name $jobName -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue
    try { & netsh http delete urlacl url=("http://+:$Port/") | Out-Null } catch { }
    try { Get-NetFirewallRule -DisplayName ("Temp-HttpFileServer-$Port") -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null } catch { }
    "Stopped server on port $Port"
  }
  Invoke-Command -Session $Session -ScriptBlock $stopScript -ArgumentList $Port
}

function Show-Menu {
  param([string]$RemoteFolder,[string]$UNC)
  Write-Host ""
  Write-Host "=== Remote File Menu ($UNC -> $RemoteFolder) ==="
  Write-Host " 1) View files"
  Write-Host " 2) Upload a local file to remote share"
  Write-Host " 3) Download a remote file to local"
  Write-Host " 4) Start HTTP index server"
  Write-Host " 5) Stop HTTP index server"
  Write-Host " 6) Exit"
  Read-Host "Choose [1-6]"
}

# -------- Main --------
try {
  Test-PreReqs
  $session = New-RemoteSession -Computer $ComputerName -Cred $Credential -SSL:$UseSSL

  try {
    # 1) Ensure remote SMB share exists & is writable
    $shareInfo = Ensure-RemoteShare -Session $session -SharePath $ServerRoot -ShareName $ShareName
    $unc = "\\$ComputerName\$ShareName"

    # 2) Optionally start HTTP index (read-only)
    if ($StartServer) { $null = Start-RemoteHttpServer -Session $session -Root $ServerRoot -Port $ServerPort -RestrictTo $ServerRestrictTo }

    # 3) Interactive menu loop
    while ($true) {
      $choice = Show-Menu -RemoteFolder $ServerRoot -UNC $unc
      switch ($choice) {
        '1' {
          $items = List-RemoteFiles -Session $session -Folder $ServerRoot
          if (-not $items -or $items.Count -eq 0) {
            Write-Host "(empty)"
          } else {
            $items | Format-Table -AutoSize
          }
        }
        '2' {
          $lf = Read-Host "Enter LOCAL full file path to upload"
          try { Send-LocalFile -Session $session -LocalFile $lf -RemoteFolder $ServerRoot } catch { Write-Error $_.Exception.Message }
        }
        '3' {
          $rf = Read-Host "Enter REMOTE full file path to download (hint: in $ServerRoot)"
          try { Receive-RemoteFile -Session $session -RemoteFile $rf -LocalDestination $LocalPath } catch { Write-Error $_.Exception.Message }
        }
        '4' {
          try {
            $null = Start-RemoteHttpServer -Session $session -Root $ServerRoot -Port $ServerPort -RestrictTo $ServerRestrictTo
          } catch { Write-Error $_.Exception.Message }
        }
        '5' {
          try {
            $msg = Stop-RemoteHttpServer -Session $session -Port $ServerPort
            Write-Verbose $msg
            Write-Host "🧹 HTTP index stopped."
          } catch { Write-Warning "Could not stop HTTP server: $($_.Exception.Message)" }
        }
        '6' { break }
        default { Write-Host "Invalid choice." }
      }
    }
  }
  finally {
    if ($session) {
      Write-Verbose "Closing session to $ComputerName"
      Remove-PSSession -Session $session
    }
  }

} catch {
  Write-Error ("FAILED: " + $_.Exception.Message)
  if ($PSBoundParameters['Verbose']) { Write-Error ($_.ScriptStackTrace) }
  exit 1
}
