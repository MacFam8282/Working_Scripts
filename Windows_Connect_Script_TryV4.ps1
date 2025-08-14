<# RemoteFetchAndServe.ps1
 - Sets up a writable SMB share on the remote.
 - Menu to View / Upload / Download files.
 - Optional read-only HTTP index server with streaming, correct headers, and diagnostics.
 - HTTP server runs in a separate remote PowerShell process (PID-based control) to avoid Stop hangs.
 - Optional remote keep-alive heartbeat process (PID-based).
 - Auto-port selection and optional bind IP.
 - Windows PowerShell 5.x compatible.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
  [Parameter(Mandatory)][string]$ComputerName,
  [Parameter()][pscredential]$Credential,
  [switch]$UseSSL,

  [Parameter()][string]$LocalPath = (Join-Path -Path $PWD -ChildPath '.'),

  [switch]$StartServer,

  # Root folder on remote used for share & HTTP index
  [string]$ServerRoot = 'C:\Temp\Drop',
  [string]$ShareName  = 'Drop',

  # Port selection:
  #  - Set to 0 to auto-select from candidates
  #  - If specific port is busy, we fall back to candidates automatically
  [int]$ServerPort = 8080,

  # Optional CIDR/IP to limit who can hit the HTTP server (firewall)
  [string]$ServerRestrictTo,

  # Optional specific local IP to bind the HTTP listener to (instead of all)
  [string]$ServerBindAddress,

  # Heartbeat interval (seconds) when you start keep-alive from the menu
  [int]$HeartbeatSeconds = 30
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-PreReqs {
  Write-Verbose "Testing WinRM reachability on $ComputerName..."
  try { Test-WSMan -ComputerName $ComputerName -UseSSL:$UseSSL | Out-Null }
  catch { throw "WinRM not reachable on $ComputerName. Enable PS Remoting + firewall. Error: $($_.Exception.Message)" }
}

function New-RemoteSession {
  param([string]$Computer,[pscredential]$Cred,[switch]$SSL)
  if (-not $Cred) { $Cred = Get-Credential -Message "Credentials for $Computer" }
  $opts = @{ ComputerName=$Computer; Credential=$Cred; Authentication='Default' }
  if ($SSL) { $opts.UseSSL = $true }
  Write-Verbose "Creating PSSession to $Computer..."
  New-PSSession @opts
}

function Ensure-RemoteShare {
  param([System.Management.Automation.Runspaces.PSSession]$Session,[string]$SharePath,[string]$ShareName)
  $script = {
    param($SharePath,$ShareName)
    $ErrorActionPreference='Stop'; Set-StrictMode -Version Latest

    if (-not (Test-Path -LiteralPath $SharePath -PathType Container)) {
      New-Item -ItemType Directory -Path $SharePath | Out-Null
    }

    if (Get-Command New-SmbShare -ErrorAction SilentlyContinue) {
      $resolvedPath = (Resolve-Path -LiteralPath $SharePath).Path
      $existing = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
      if ($existing -and $existing.Path -ne $resolvedPath) {
        Remove-SmbShare -Name $ShareName -Force
        $existing = $null
      }
      if (-not $existing) {
        New-SmbShare -Name $ShareName -Path $resolvedPath -CachingMode None -Temporary:$false -FullAccess 'Authenticated Users' | Out-Null
      } else {
        Grant-SmbShareAccess -Name $ShareName -AccountName 'Authenticated Users' -AccessRight Full -Force -ErrorAction SilentlyContinue | Out-Null
      }
      try {
        Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue | Out-Null
        Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing (SMB-In)' -ErrorAction SilentlyContinue | Out-Null
      } catch {}
    } else {
      & cmd /c "net share $ShareName=`"$SharePath`" /GRANT:Everyone,FULL" | Out-Null
      try { & netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes | Out-Null } catch {}
    }

    $ips = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Manual, Dhcp -ErrorAction SilentlyContinue |
            Where-Object {$_.IPAddress -notlike '169.254.*'} | Select-Object -ExpandProperty IPAddress)
    $ips = @($ips)
    [pscustomobject]@{
      SharePath = (Resolve-Path -LiteralPath $SharePath).Path
      Share     = "\\$env:COMPUTERNAME\$ShareName"
      IPv4      = ($ips -join ', ')
    }
  }

  $info = Invoke-Command -Session $Session -ScriptBlock $script -ArgumentList $SharePath,$ShareName
  Write-Host "✅ Task complete: Remote SMB share ready — $($info.Share)  (Path: $($info.SharePath); IP(s): $($info.IPv4))"
  return $info
}

function List-RemoteFiles {
  param([System.Management.Automation.Runspaces.PSSession]$Session,[string]$Folder)
  $sb = {
    param($f)
    if (-not (Test-Path -LiteralPath $f -PathType Container)) { return @() }
    Get-ChildItem -LiteralPath $f -File -Recurse |
      Select-Object FullName, Length, LastWriteTime |
      Sort-Object FullName
  }
  Invoke-Command -Session $Session -ScriptBlock $sb -ArgumentList $Folder
}

function Receive-RemoteFile {
  param([System.Management.Automation.Runspaces.PSSession]$Session,[string]$RemoteFile,[string]$LocalDestination)
  if (Test-Path -LiteralPath $LocalDestination -PathType Container) {
    $LocalFinal = Join-Path $LocalDestination (Split-Path $RemoteFile -Leaf)
  } else {
    $dir = Split-Path $LocalDestination -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir -PathType Container)) {
      New-Item -ItemType Directory -Path $dir | Out-Null
    }
    $LocalFinal = $LocalDestination
  }
  Copy-Item -Path $RemoteFile -Destination $LocalFinal -FromSession $Session -Force
  Write-Host "✅ Task complete: Downloaded to $LocalFinal"
}

function Send-LocalFile {
  param([System.Management.Automation.Runspaces.PSSession]$Session,[string]$LocalFile,[string]$RemoteFolder)
  if (-not (Test-Path -LiteralPath $LocalFile -PathType Leaf)) { throw "Local file not found: $LocalFile" }
  Invoke-Command -Session $Session -ScriptBlock {
    param($p) if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
  } -ArgumentList $RemoteFolder
  $dest = Join-Path $RemoteFolder (Split-Path $LocalFile -Leaf)
  Copy-Item -Path $LocalFile -Destination $dest -ToSession $Session -Force
  Write-Host "✅ Task complete: Uploaded to $dest"
}

function Start-RemoteHttpServer {
  <#
    Starts a minimal read-only HTTP server on the remote host, indexes $Root.
    - Spawns a separate powershell.exe on the remote; PID-based stop (no hangs).
    - Correct headers, streaming, keep-alive disabled (safer across middleboxes).
    - Auto-port selection; optional bind IP; ACL + firewall.
    - Adds /health and /diag endpoints and request logging.
    - WinPS5 compatible.
  #>
  param(
    [System.Management.Automation.Runspaces.PSSession]$Session,
    [string]$Root,[int]$Port,[string]$RestrictTo,[string]$BindIP
  )

  $serverScript = {
    param($Root,$Port,$RestrictTo,$BindIP)

    function Get-FirstOpenPort {
      param([int[]]$Candidates)
      foreach ($p in $Candidates) {
        $busy = $false
        try { $busy = [bool](Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue) }
        catch { try { $busy = (Test-NetConnection -ComputerName '127.0.0.1' -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded } catch {} }
        if (-not $busy) { return $p }
      }
      return $null
    }

    $ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { New-Item -ItemType Directory -Path $Root | Out-Null }

    # Port candidates
    $candidates = @()
    if ($Port -gt 0) { $candidates += $Port }
    $candidates += 8080,8000,8888,9090
    $candidates += 49160..49180
    $candidates += (Get-Random -Minimum 49152 -Maximum 65535)
    $pick = Get-FirstOpenPort -Candidates ($candidates | Select-Object -Unique)
    if (-not $pick) { throw "No free HTTP port found in candidate set." }

    # IPs/prefixes
    $ips = @()
    if ($BindIP) { $ips = ,$BindIP } else {
      $ips = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Manual, Dhcp -ErrorAction SilentlyContinue |
             Where-Object {$_.IPAddress -notlike '169.254.*'} | Select-Object -ExpandProperty IPAddress)
    }
    $ips = @($ips); if ($ips.Count -eq 0) { $ips = @('127.0.0.1') }

    $prefixes = @()
    if (-not $BindIP) { $prefixes += ("http://+:{0}/" -f $pick) }
    $prefixes += ("http://localhost:{0}/" -f $pick)
    $prefixes += ($ips | ForEach-Object { "http://" + $_ + ":" + $pick + "/" }) | Select-Object -Unique
    $prefixes = @($prefixes)

    # URLACLs
    $currentUser = "$env:USERDOMAIN\$env:USERNAME"
    foreach ($pref in $prefixes) {
      try { & netsh http delete urlacl url=$pref | Out-Null } catch {}
      foreach ($acct in @('Everyone','BUILTIN\Users',$currentUser)) {
        try { & netsh http add urlacl url=$pref user="$acct" | Out-Null } catch {}
      }
    }

    # Firewall
    $fwName = "Temp-HttpFileServer-$pick"
    if (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) {
      try {
        Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        $fwParams = @{ DisplayName=$fwName; Direction='Inbound'; Action='Allow'; Protocol='TCP'; LocalPort=$pick; Profile='Any' }
        if ($RestrictTo) { $fwParams.RemoteAddress = $RestrictTo }
        New-NetFirewallRule @fwParams | Out-Null
      } catch {}
    }

    # Build server runner script on remote disk (single-quoted here-string!)
    $temp    = [IO.Path]::GetTempPath()
    $runner  = Join-Path $temp ("SimpleHttpFileServer_{0}.ps1" -f $pick)
    $pidfile = Join-Path $temp ("SimpleHttpFileServer_{0}.pid" -f $pick)

    $runnerSource = @'
param([string]$Root,[int]$Port,[string[]]$Prefixes)

Add-Type -AssemblyName System.Net.HttpListener

$LogPath = Join-Path $env:TEMP ("SimpleHttpFileServer_{0}.log" -f $Port)
function Log([string]$msg) {
  $ts = (Get-Date).ToString("s")
  Add-Content -Path $LogPath -Value ("[{0}] {1}" -f $ts, $msg)
}

function Get-MimeType([string]$Path) {
  $ext = [IO.Path]::GetExtension($Path); if ($null -eq $ext) { $ext = '' }; $ext = $ext.ToLowerInvariant()
  switch ($ext) {
    '.htm' { 'text/html' ; break }
    '.html'{ 'text/html' ; break }
    '.txt' { 'text/plain'; break }
    '.json'{ 'application/json'; break }
    '.csv' { 'text/csv' ; break }
    '.jpg' { 'image/jpeg'; break }
    '.jpeg'{ 'image/jpeg'; break }
    '.png' { 'image/png' ; break }
    '.gif' { 'image/gif' ; break }
    '.pdf' { 'application/pdf'; break }
    default { 'application/octet-stream' }
  }
}

function Send-Text($res, [string]$text, [int]$code=200, [string]$mime='text/plain') {
  try {
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    $res.KeepAlive = $false; $res.Headers['Connection'] = 'close'
    $res.SendChunked = $false; $res.ContentType = $mime
    $res.ContentLength64 = $bytes.LongLength; $res.StatusCode = $code
    $res.OutputStream.Write($bytes,0,$bytes.Length)
    $res.OutputStream.Flush()
  } catch {} finally { try { $res.Close() } catch {} }
}

function Send-File($res, [string]$filePath) {
  $res.KeepAlive = $false; $res.Headers['Connection'] = 'close'
  $res.SendChunked = $false; $res.ContentType = Get-MimeType $filePath
  $name = [IO.Path]::GetFileName($filePath)
  $res.AddHeader('Content-Disposition','attachment; filename="'+$name+'"')
  $fs = $null
  try {
    $fs = [IO.File]::Open($filePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $res.ContentLength64 = $fs.Length
    $buffer = New-Object byte[] 65536
    while (($read = $fs.Read($buffer,0,$buffer.Length)) -gt 0) {
      $res.OutputStream.Write($buffer,0,$read)
    }
    $res.StatusCode = 200
    $res.OutputStream.Flush()
  } catch {
    Send-Text -res $res -text "500 - Error reading file." -code 500
    return
  } finally {
    if ($fs) { $fs.Dispose() }
    try { $res.Close() } catch {}
  }
}

$listener = [System.Net.HttpListener]::new()
foreach ($pfx in $Prefixes) { $listener.Prefixes.Add($pfx) }
$listener.IgnoreWriteExceptions = $true
$listener.Start()
Log "Listening on: $($Prefixes -join ', ') | Root: $Root"

try {
  while ($true) {
    $ctx = $listener.GetContext()
    $req = $ctx.Request; $res = $ctx.Response
    $path = $req.Url.AbsolutePath
    Log ("{0} {1} from {2}" -f $req.HttpMethod, $path, $req.RemoteEndPoint)

    try {
      if ($req.HttpMethod -ne 'GET') { Send-Text -res $res -text '405 - Method Not Allowed' -code 405; continue }

      # Health/diag endpoints
      if ($path -ieq '/health') { Send-Text -res $res -text 'ok' -code 200; continue }
      if ($path -ieq '/diag') {
        $obj = [pscustomobject]@{
          Port = $Port; Prefixes = $Prefixes; Root = $Root
          Now  = (Get-Date).ToString("o"); Hostname = $env:COMPUTERNAME
          Log  = $LogPath
        } | ConvertTo-Json -Depth 3
        Send-Text -res $res -text $obj -code 200 -mime 'application/json'; continue
      }

      $rel = $path.TrimStart('/')
      if ([string]::IsNullOrWhiteSpace($rel)) { $rel = 'index.html' }

      if ($rel -ieq 'index.html') {
        $files = @(); try { $files = Get-ChildItem -Path $Root -File -Recurse | Sort-Object FullName } catch {}
        $list = ($files | ForEach-Object { '<li><a href="./' + ($_.FullName.Substring($Root.Length).TrimStart('\').Replace('\','/')) + '">' + $_.Name + '</a></li>' }) -join ''
        $html = "<!doctype html><html><head><meta charset='utf-8'><title>Index</title></head><body><h3>Files under $Root</h3><ul>$list</ul></body></html>"
        Send-Text -res $res -text $html -code 200 -mime 'text/html'; continue
      }

      $requested = Join-Path -Path $Root -ChildPath ($rel -replace '/','\')
      $requested = [IO.Path]::GetFullPath($requested)
      $rootFull  = [IO.Path]::GetFullPath($Root)
      if (-not $requested.StartsWith($rootFull,[System.StringComparison]::OrdinalIgnoreCase)) { Send-Text -res $res -text '403 - Forbidden' -code 403; continue }
      if (-not (Test-Path -LiteralPath $requested -PathType Leaf)) { Send-Text -res $res -text '404 - Not Found' -code 404; continue }

      Send-File -res $res -filePath $requested
    } catch {
      Log ("ERROR: " + $_.Exception.Message)
      try { Send-Text -res $res -text '500 - Internal Server Error' -code 500 } catch {}
    }
  }
} finally {
  try { $listener.Stop() } catch {}
  try { $listener.Close() } catch {}
  Log "Listener stopped."
}
'@

    Set-Content -Path $runner -Value $runnerSource -Encoding UTF8 -Force

    # Start remote process (pass Prefixes as multiple args)
    $argList = @(
      '-NoLogo','-NoProfile','-ExecutionPolicy','Bypass',
      '-File', $runner,
      '-Root', $Root,
      '-Port', $pick,
      '-Prefixes'
    ) + $prefixes

    $srvProc = Start-Process -FilePath (Get-Command powershell.exe).Path -ArgumentList $argList -WindowStyle Hidden -PassThru
    Set-Content -Path $pidfile -Value $srvProc.Id -Encoding ASCII -Force

    # Quick self-test
    $listening = $false; $httpOK = $false
    $deadline  = (Get-Date).AddSeconds(5)
    $ipsForTest = if ($BindIP) { ,$BindIP } else { $ips }
    $ipsForTest = @($ipsForTest)
    $testHosts  = @('127.0.0.1','localhost') + $ipsForTest
    while ((Get-Date) -lt $deadline) {
      foreach ($h in $testHosts) {
        try {
          $tcp = New-Object System.Net.Sockets.TcpClient
          $iar = $tcp.BeginConnect($h, $pick, $null, $null)
          if ($iar.AsyncWaitHandle.WaitOne(300)) { $tcp.EndConnect($iar); $tcp.Dispose(); $listening = $true } else { $tcp.Close() }
        } catch {}
        if ($listening -and -not $httpOK) {
          try {
            $uri = ("http://{0}:{1}/health" -f $h, $pick)
            $wc = New-Object System.Net.WebClient
            $wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
            ($wc.DownloadString($uri)) | Out-Null
            $httpOK = $true
          } catch {}
        }
        if ($httpOK) { break }
      }
      if ($httpOK) { break }
      Start-Sleep -Milliseconds 200
    }

    [pscustomobject]@{
      Port         = $pick
      Urls         = $prefixes
      Root         = (Resolve-Path -LiteralPath $Root).Path
      FirewallRule = $fwName
      Pid          = $srvProc.Id
      PidFile      = $pidfile
      HttpOK       = $httpOK
      Listening    = $listening
      BoundIPs     = ($ipsForTest -join ', ')
    }
  }

  $info = Invoke-Command -Session $Session -ScriptBlock $serverScript -ArgumentList $Root,$ServerPort,$ServerRestrictTo,$BindIP
  if ($info.HttpOK -or $info.Listening) {
    $auto = ($ServerPort -eq 0 -or $ServerPort -ne $info.Port) ? " (auto-selected)" : ""
    Write-Host ("✅ Task complete: Remote HTTP index listening on port {0}{1}" -f $info.Port, $auto)
    Write-Host ("   Bound IPs: {0}" -f $info.BoundIPs)
    Write-Host ("   URLs: {0}" -f (@($info.Urls) -join ' , '))
    Write-Host ("   Root: {0}" -f $info.Root)
    Write-Host ("   PID:  {0}" -f $info.Pid)
  } else {
    Write-Warning "❌ HTTP start attempted but remote self-test still failed.
   Hints:
     • Try -ServerBindAddress <remote-IP> to avoid wildcard conflicts.
     • Ensure upstream firewalls allow the chosen port to the remote IP.
     • Check: netsh http show urlacl   and   netstat -ano | findstr :$($info.Port)"
  }
  return $info
}

function Stop-RemoteHttpServer {
  <#
    Stops the remote HTTP server fast and safely (PID-based).
    Also cleans URLACL + firewall; won’t hang the local menu.
  #>
  param([System.Management.Automation.Runspaces.PSSession]$Session,[int]$Port)

  $stopScript = {
    param($Port)
    $ErrorActionPreference = 'Continue'

    function Remove-UrlAclForPort([int]$p) {
      foreach ($t in @("http://+:$p/","http://localhost:$p/")) {
        try { & netsh http delete urlacl url=$t | Out-Null } catch {}
      }
    }
    function Remove-FirewallRuleForPort([int]$p) {
      $name = "Temp-HttpFileServer-$p"
      try { Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    }

    $temp = [IO.Path]::GetTempPath()
    $pidfile = $null
    if ($Port -gt 0) { $pidfile = Join-Path $temp ("SimpleHttpFileServer_{0}.pid" -f $Port) }

    $killed = $false
    if ($pidfile -and (Test-Path -LiteralPath $pidfile)) {
      try {
        $srvPid = [int](Get-Content -LiteralPath $pidfile -ErrorAction SilentlyContinue)
        if ($srvPid -gt 0) {
          try { Stop-Process -Id $srvPid -Force -ErrorAction SilentlyContinue } catch {}
          $killed = $true
        }
      } catch {}
      try { Remove-Item -LiteralPath $pidfile -Force -ErrorAction SilentlyContinue } catch {}
    } elseif ($Port -le 0) {
      # Unknown port: attempt to kill any server process runners we created
      Get-ChildItem -Path $temp -Filter 'SimpleHttpFileServer_*.pid' -ErrorAction SilentlyContinue | ForEach-Object {
        try {
          $srvPid = [int](Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue)
          if ($srvPid -gt 0) { Stop-Process -Id $srvPid -Force -ErrorAction SilentlyContinue }
        } catch {}
        try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
      }
      $killed = $true
    }

    # Cleanup any leftover background jobs (very old versions)
    $jobs = @(Get-Job -Name 'SimpleHttpFileServer_*' -ErrorAction SilentlyContinue)
    foreach ($j in $jobs) {
      try { Stop-Job -Job $j -ErrorAction SilentlyContinue | Out-Null } catch {}
      try { Remove-Job -Job $j -ErrorAction SilentlyContinue | Out-Null } catch {}
    }

    # Clean ACL/firewall
    if ($Port -gt 0)       { Remove-UrlAclForPort $Port; Remove-FirewallRuleForPort $Port }
    else { foreach ($p in (8080,8000,8888,9090) + (49160..49180)) { Remove-UrlAclForPort $p; Remove-FirewallRuleForPort $p } }

    if ($killed) { "Stopped server process." } else { "No running server process found." }
  }

  try {
    $msg = Invoke-Command -Session $Session -ScriptBlock $stopScript -ArgumentList $Port
    Write-Host "✅ Task complete: HTTP server stopped. $msg"
  } catch {
    Write-Warning ("❌ HTTP stop encountered errors: {0}" -f $_.Exception.Message)
  }
}

function Start-RemoteKeepAlive {
  <#
    Starts a remote heartbeat process that curls /health every N seconds.
    Creates SimpleHttpFileServer_<port>.hb.pid to manage it.
  #>
  param([System.Management.Automation.Runspaces.PSSession]$Session,[int]$Port,[int]$IntervalSec=30)
  $script = {
    param($Port,$IntervalSec)
    $ErrorActionPreference = 'Stop'
    $temp = [IO.Path]::GetTempPath()
    $hbScript = Join-Path $temp ("SimpleHttpFileServer_{0}.hb.ps1" -f $Port)
    $pidfile  = Join-Path $temp ("SimpleHttpFileServer_{0}.hb.pid" -f $Port)

    $src = @'
param([int]$Port,[int]$IntervalSec)
while ($true) {
  try {
    $wc = New-Object System.Net.WebClient
    $wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
    $wc.DownloadString(("http://127.0.0.1:{0}/health" -f $Port)) | Out-Null
  } catch { }
  Start-Sleep -Seconds $IntervalSec
}
'@
    Set-Content -Path $hbScript -Value $src -Encoding UTF8 -Force
    $argList = @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$hbScript,'-Port',$Port,'-IntervalSec',$IntervalSec)
    $hbProc = Start-Process -FilePath (Get-Command powershell.exe).Path -ArgumentList $argList -WindowStyle Hidden -PassThru
    Set-Content -Path $pidfile -Value $hbProc.Id -Encoding ASCII -Force

    [pscustomobject]@{ Port=$Port; Interval=$IntervalSec; Pid=$hbProc.Id; PidFile=$pidfile }
  }
  $info = Invoke-Command -Session $Session -ScriptBlock $script -ArgumentList $Port,$IntervalSec
  Write-Host ("✅ Task complete: Keep-alive started (PID {0}) every {1}s" -f $info.Pid, $info.Interval)
  return $info
}

function Stop-RemoteKeepAlive {
  <#
    Stops the heartbeat process if running.
  #>
  param([System.Management.Automation.Runspaces.PSSession]$Session,[int]$Port)
  $script = {
    param($Port)
    $ErrorActionPreference='Continue'
    $temp = [IO.Path]::GetTempPath()
    $pidfile = Join-Path $temp ("SimpleHttpFileServer_{0}.hb.pid" -f $Port)
    if (Test-Path -LiteralPath $pidfile) {
      try {
        $hbPid = [int](Get-Content -LiteralPath $pidfile -ErrorAction SilentlyContinue)
        if ($hbPid -gt 0) { Stop-Process -Id $hbPid -Force -ErrorAction SilentlyContinue }
      } catch {}
      try { Remove-Item -LiteralPath $pidfile -Force -ErrorAction SilentlyContinue } catch {}
      "Stopped keep-alive."
    } else {
      "No keep-alive process found."
    }
  }
  $msg = Invoke-Command -Session $Session -ScriptBlock $script -ArgumentList $Port
  Write-Host "✅ Task complete: $msg"
}

function Check-RemoteHttpStatus {
  <#
    Calls /health and /diag on the remote and prints the results.
  #>
  param([System.Management.Automation.Runspaces.PSSession]$Session,[int]$Port,[string]$BindIP)
  $script = {
    param($Port,$BindIP)
    $ErrorActionPreference='Continue'
    $hostToTry = if ($BindIP) { $BindIP } else { '127.0.0.1' }
    $result = [ordered]@{ Health=''; Diag=$null }
    try {
      $wc = New-Object System.Net.WebClient
      $wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
      $result.Health = $wc.DownloadString(("http://{0}:{1}/health" -f $hostToTry,$Port))
      $json = $wc.DownloadString(("http://{0}:{1}/diag" -f $hostToTry,$Port))
      $result.Diag = $json | ConvertFrom-Json
    } catch { $result.Health = "ERROR: $($_.Exception.Message)" }
    $result
  }
  $r = Invoke-Command -Session $Session -ScriptBlock $script -ArgumentList $Port,$BindIP
  if ($r.Health -eq 'ok') {
    Write-Host "✅ Task complete: HTTP health OK"
    if ($r.Diag) {
      Write-Host ("   Root: {0}" -f $r.Diag.Root)
      Write-Host ("   Prefixes: {0}" -f ($r.Diag.Prefixes -join ' , '))
      Write-Host ("   Log: {0}" -f $r.Diag.Log)
    }
  } else {
    Write-Warning ("❌ Health check failed: {0}" -f $r.Health)
  }
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
  Write-Host " --- HTTP Tools ---"
  Write-Host " 7) Check HTTP server status (/health + /diag)"
  Write-Host " 8) Start keep-alive heartbeat"
  Write-Host " 9) Stop keep-alive heartbeat"
  Read-Host "Choose [1-9]"
}

# -------------------- Main --------------------
$exitRequested = $false
try {
  Test-PreReqs
  $session = New-RemoteSession -Computer $ComputerName -Cred $Credential -SSL:$UseSSL

  try {
    # Ensure remote SMB share exists & is writable
    $shareInfo = Ensure-RemoteShare -Session $session -SharePath $ServerRoot -ShareName $ShareName
    $unc = "\\$ComputerName\$ShareName"

    # Optional: auto-start HTTP
    if ($StartServer) { $null = Start-RemoteHttpServer -Session $session -Root $ServerRoot -Port $ServerPort -RestrictTo $ServerRestrictTo -BindIP $ServerBindAddress }

    while (-not $exitRequested) {
      $choice = Show-Menu -RemoteFolder $ServerRoot -UNC $unc
      switch ($choice) {
        '1' {
          try { $items = List-RemoteFiles -Session $session -Folder $ServerRoot; if (-not $items -or @($items).Count -eq 0) { Write-Host "(empty)" } else { @($items) | Format-Table -AutoSize }; Write-Host "✅ Task complete: View files" }
          catch { Write-Error "❌ View failed: $($_.Exception.Message)" }
        }
        '2' {
          $lf = Read-Host "Enter LOCAL full file path to upload"
          try { Send-LocalFile -Session $session -LocalFile $lf -RemoteFolder $ServerRoot }
          catch { Write-Error "❌ Upload failed: $($_.Exception.Message)" }
        }
        '3' {
          $rf = Read-Host "Enter REMOTE full file path to download (hint: under $ServerRoot)"
          try { Receive-RemoteFile -Session $session -RemoteFile $rf -LocalDestination $LocalPath }
          catch { Write-Error "❌ Download failed: $($_.Exception.Message)" }
        }
        '4' {
          try { $null = Start-RemoteHttpServer -Session $session -Root $ServerRoot -Port $ServerPort -RestrictTo $ServerRestrictTo -BindIP $ServerBindAddress }
          catch { Write-Error "❌ HTTP start failed: $($_.Exception.Message)" }
        }
        '5' {
          try { Stop-RemoteHttpServer -Session $session -Port $ServerPort }
          catch { Write-Error "❌ HTTP stop failed: $($_.Exception.Message)" }
        }
        '6' {
          $exitRequested = $true
          Write-Host "✅ Task complete: Exit requested"
        }
        '7' {
          try { Check-RemoteHttpStatus -Session $session -Port $ServerPort -BindIP $ServerBindAddress }
          catch { Write-Error "❌ Status check failed: $($_.Exception.Message)" }
        }
        '8' {
          try { Start-RemoteKeepAlive -Session $session -Port $ServerPort -IntervalSec $HeartbeatSeconds | Out-Null }
          catch { Write-Error "❌ Keep-alive start failed: $($_.Exception.Message)" }
        }
        '9' {
          try { Stop-RemoteKeepAlive -Session $session -Port $ServerPort }
          catch { Write-Error "❌ Keep-alive stop failed: $($_.Exception.Message)" }
        }
        default {
          Write-Host "Invalid choice. Enter 1-9."
        }
      }
    }
  }
  finally {
    if ($session) {
      Write-Verbose "Closing session to $ComputerName"
      Remove-PSSession -Session $session
      Write-Host "✅ Task complete: Remote session closed"
    }
  }

} catch {
  Write-Error ("FAILED: " + $_.Exception.Message)
  if ($PSBoundParameters['Verbose']) { Write-Error ($_.ScriptStackTrace) }
  exit 1
}
