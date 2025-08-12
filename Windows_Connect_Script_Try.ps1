<# 
.SYNOPSIS
  Remote into a Windows host, copy a file back, and optionally create a minimal HTTP file server on the remote.

.PARAMETER ComputerName
  DNS name or IP of the remote Windows host.

.PARAMETER Credential
  Credentials to use for remoting. If omitted, you’ll be prompted securely.

.PARAMETER UseSSL
  Use WinRM over HTTPS (requires remote to be configured for HTTPS).

.PARAMETER RemotePath
  Full path to the file on the remote to copy. If omitted, you’ll be prompted.

.PARAMETER LocalPath
  Destination folder or full file path locally. If a folder, the remote file name is preserved.

.PARAMETER StartServer
  If set, creates a minimal HTTP file server on the remote that serves files from -ServerRoot on -ServerPort.

.PARAMETER ServerRoot
  Remote directory root the HTTP server will expose (GET only, read-only). Default: C:\Temp

.PARAMETER ServerPort
  Port for the remote HTTP server. Default: 8080

.PARAMETER ServerRestrictTo
  Optional IP/CIDR (e.g. 192.168.1.50 or 192.168.1.0/24) used to restrict the temporary firewall rule on the remote.

.EXAMPLE
  .\RemoteFetchAndServe.ps1 -ComputerName host01 -UseSSL -StartServer -ServerRoot C:\Shares -ServerPort 8080

.EXAMPLE
  .\RemoteFetchAndServe.ps1 -ComputerName 10.0.0.12 -RemotePath 'C:\Users\Public\report.pdf' -LocalPath 'C:\Drops'
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
  [Parameter(Mandatory)][string]$ComputerName,
  [Parameter()][pscredential]$Credential,
  [switch]$UseSSL,
  [string]$RemotePath,
  [Parameter()][string]$LocalPath = (Join-Path -Path $PWD -ChildPath '.'),
  [switch]$StartServer,
  [string]$ServerRoot = 'C:\Temp',
  [int]$ServerPort = 8080,
  [string]$ServerRestrictTo
)

# Harden failures to be terminating for proper catch
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
    ComputerName = $Computer
    Credential   = $Cred
    Authentication = 'Default'
  }
  if ($SSL) { $opts['UseSSL'] = $true }
  Write-Verbose "Creating PSSession to $Computer..."
  New-PSSession @opts
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

  # Normalize local path
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

  Write-Host "✅ Copied to $LocalFinal"
}

function Start-RemoteHttpServer {
  param(
    [System.Management.Automation.Runspaces.PSSession]$Session,
    [string]$Root,
    [int]$Port,
    [string]$RestrictTo
  )

  # Script that runs on the remote to create a minimal read-only HTTP server
  $serverScript = {
    param($Root, $Port, $RestrictTo)

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
      New-Item -ItemType Directory -Path $Root | Out-Null
    }

    # Add URL ACL for HttpListener
    $url = "http://+:$Port/"
    try {
      & netsh http add urlacl url=$url user="Everyone" | Out-Null
    } catch {
      # Might already exist or need admin
    }

    # Add a tight inbound firewall rule if RestrictTo provided
    $fwName = "Temp-HttpFileServer-$Port"
    if (Get-Command -Name New-NetFirewallRule -ErrorAction SilentlyContinue) {
      try {
        # Remove pre-existing rule with the same name
        Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null
        $fwParams = @{
          DisplayName = $fwName
          Direction   = 'Inbound'
          Action      = 'Allow'
          Protocol    = 'TCP'
          LocalPort   = $Port
          Profile     = 'Domain,Private'
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

          # Only GET allowed; map to files under $Root
          if ($req.HttpMethod -ne 'GET') {
            $res.StatusCode = 405; $res.Close(); continue
          }

          # Normalize path
          $rel = $req.Url.AbsolutePath.TrimStart('/')
          if ([string]::IsNullOrWhiteSpace($rel)) { $rel = 'index.html' }

          # Simple directory index
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
          # Prevent path escape
          $requested = [IO.Path]::GetFullPath($requested)
          $rootFull  = [IO.Path]::GetFullPath($Root)
          if (-not $requested.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            $res.StatusCode = 403; $res.Close(); continue
          }

          if (-not (Test-Path -LiteralPath $requested -PathType Leaf)) {
            $res.StatusCode = 404; $res.Close(); continue
          }

          try {
            $bytes = [IO.File]::ReadAllBytes($requested)
            $res.ContentType = 'application/octet-stream'
            $res.AddHeader('Content-Disposition', 'attachment; filename="' + [IO.Path]::GetFileName($requested) + '"')
            $res.OutputStream.Write($bytes,0,$bytes.Length)
            $res.StatusCode = 200
          } catch {
            $res.StatusCode = 500
          } finally {
            $res.Close()
          }
        }
      } finally {
        $listener.Stop()
        $listener.Close()
      }
    } -ArgumentList $Root,$Port

    # Return metadata for the caller
    [pscustomobject]@{
      JobName     = $jobName
      Port        = $Port
      Url         = "http://$env:COMPUTERNAME`:$Port/"
      Root        = $Root
      Firewall    = $fwName
    }
  }

  $info = Invoke-Command -Session $Session -ScriptBlock $serverScript -ArgumentList $Root,$Port,$RestrictTo
  Write-Host "🚀 Remote HTTP server started on $($Session.ComputerName):$($info.Port) serving $($info.Root)"
  Write-Host "   Try: http://$($Session.ComputerName):$($info.Port)/  (index of files)"
  return $info
}

function Stop-RemoteHttpServer {
  param(
    [System.Management.Automation.Runspaces.PSSession]$Session,
    [int]$Port
  )
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

# --- Main execution ---
try {
  Test-PreReqs
  $session = New-RemoteSession -Computer $ComputerName -Cred $Credential -SSL:$UseSSL

  try {
    # If requested, bring up a remote HTTP server (read-only) first
    if ($StartServer) {
      $null = Start-RemoteHttpServer -Session $session -Root $ServerRoot -Port $ServerPort -RestrictTo $ServerRestrictTo
    }

    # Resolve remote file (prompt if not supplied)
    $remoteInfo = Resolve-RemoteFile -Session $session -Path $RemotePath
    $remoteFull = $remoteInfo.FullName
    Write-Host "Found remote file:"
    $remoteInfo | Format-List | Out-String | Write-Verbose

    # Copy it home
    Receive-RemoteFile -Session $session -RemoteFile $remoteFull -LocalDestination $LocalPath
  } finally {
    if ($StartServer) {
      # Best-effort cleanup—comment this out if you want the server to keep running
      try {
        $msg = Stop-RemoteHttpServer -Session $session -Port $ServerPort
        Write-Verbose $msg
        Write-Host "🧹 Remote HTTP server stopped and cleaned up."
      } catch {
        Write-Warning "Could not stop remote HTTP server: $($_.Exception.Message)"
      }
    }
    if ($session) {
      Write-Verbose "Closing session to $ComputerName"
      Remove-PSSession -Session $session
    }
  }

} catch {
  Write-Error ("FAILED: " + $_.Exception.Message)
  if ($PSBoundParameters['Verbose']) {
    Write-Error ($_.ScriptStackTrace)
  }
  exit 1
}
