<# 
.SYNOPSIS
  Measure local + remote hashing performance for a given local file.
  Computes actual local hash; on remotes either benchmarks equivalent bytes
  or (optionally) copies file and computes the real hash there too.

.DESCRIPTION
  - Prompts for computers (or takes -Computers / pipeline)
  - Prompts for local file path; validates & reads size
  - Prompts for algorithm (SHA256/SHA1/MD5; default SHA256)
  - Local: Get-FileHash + timing
  - Remote (default): no file copy; measures hashing throughput by hashing
    a fixed buffer repeatedly until total bytes ≈ file size (timed).
  - Remote (optional -CopyToRemotes): copies the file to %TEMP%,
    computes hash (timed), returns result, then deletes the copy.
  - Parallel jobs, live status, robust error handling & cleanup.

.EXAMPLES
  .\Measure-DistributedHash.ps1
  'VM1','VM2','VM3','VM4' | .\Measure-DistributedHash.ps1 -Algorithm SHA256
  .\Measure-DistributedHash.ps1 -Computers VM1,VM2,VM3,VM4 -CopyToRemotes
#>

[CmdletBinding()]
param(
  [Parameter(ValueFromPipeline=$true)]
  [string[]]$Computers,

  [ValidateSet('SHA256','SHA1','MD5')]
  [string]$Algorithm = 'SHA256',

  [switch]$PromptForCredential,

  # When set, copy the file to each remote and compute real hash remotely
  [switch]$CopyToRemotes,

  # Safety/timeouts
  [int]$OverallTimeoutSec = 900
)

begin {
  function Write-Info   { param([string]$m) Write-Host "[INFO ] $m" -ForegroundColor Cyan }
  function Write-Warn   { param([string]$m) Write-Host "[WARN ] $m" -ForegroundColor Yellow }
  function Write-ErrMsg { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

  # --- Get computer names (prompt if not provided)
  if (-not $PSBoundParameters.ContainsKey('Computers') -or -not $Computers -or $Computers.Count -eq 0) {
    Write-Info "Enter computer names (comma or space separated). Example: VM1, VM2 VM3 VM4"
    $raw = Read-Host "Computers"
    $Computers = $raw -split '[,\s]+' | Where-Object { $_ -and $_.Trim() } | ForEach-Object Trim | Select-Object -Unique
  }
  if (-not $Computers -or $Computers.Count -eq 0) { Write-ErrMsg "No computer names."; break }

  # --- Creds (optional)
  $cred = $null
  if ($PromptForCredential) { $cred = Get-Credential -Message "Remote credentials" }

  # --- Prompt for local file (password-protected is fine — we hash bytes only)
  $localPath = Read-Host "Enter FULL path to the local (password-protected) file to hash"
  if (-not (Test-Path -LiteralPath $localPath)) { Write-ErrMsg "File not found: $localPath"; break }
  try {
    $fileInfo = Get-Item -LiteralPath $localPath -ErrorAction Stop
  } catch { Write-ErrMsg "Cannot read file: $($_.Exception.Message)"; break }

  $fileSize = $fileInfo.Length
  if ($fileSize -le 0) { Write-ErrMsg "File is empty."; break }
  Write-Info ("Target file: {0}  |  Size: {1:N0} bytes ({2:N2} MB)" -f $fileInfo.Name, $fileSize, ($fileSize/1MB))

  # --- Local hash (actual)
  Write-Info "Computing LOCAL hash with $Algorithm..."
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $localHash = (Get-FileHash -LiteralPath $localPath -Algorithm $Algorithm -ErrorAction Stop).Hash
    $sw.Stop()
    $localSeconds = [math]::Round($sw.Elapsed.TotalSeconds,2)
    $localMBps    = [math]::Round(($fileSize/1MB)/[math]::Max($localSeconds,0.0001),2)
    Write-Host ("Local {0}: {1}" -f $Algorithm, $localHash)
    Write-Host ("Local time: {0}s  |  Throughput: {1} MB/s" -f $localSeconds, $localMBps)
  } catch {
    $sw.Stop()
    $localHash    = $null
    $localSeconds = $null
    $localMBps    = $null
    Write-Warn "Local hashing failed: $($_.Exception.Message)"
  }

  # --- Remote payloads
  # A) Benchmark payload (no copy): hash a fixed buffer repeatedly to simulate hashing $fileSize bytes
  $RemoteBench = {
    param([int64]$TotalBytes, [string]$Algo, [int]$BlockBytes)
    $ErrorActionPreference = 'Stop'
    # pick hash algo
    switch ($Algo) {
      'SHA256' { $sha = [System.Security.Cryptography.SHA256]::Create() }
      'SHA1'   { $sha = [System.Security.Cryptography.SHA1]::Create() }
      'MD5'    { $sha = [System.Security.Cryptography.MD5]::Create() }
      default  { throw "Unsupported algorithm $Algo" }
    }
    try {
      $buf = New-Object byte[] $BlockBytes   # zeros are fine; we're measuring speed, not value
      $count = 0L
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      while ($count -lt $TotalBytes) {
        $toHash = [Math]::Min($BlockBytes, [int]($TotalBytes - $count))
        # Hash block by block using TransformBlock/TransformFinalBlock for realism
        $sha.TransformBlock($buf, 0, $toHash, $null, 0) | Out-Null
        $count += $toHash
      }
      $sha.TransformFinalBlock([byte[]]::new(0), 0, 0) | Out-Null
      $sw.Stop()
      $elapsed = [math]::Max($sw.Elapsed.TotalSeconds, 0.0001)
      [pscustomobject]@{
        Type      = 'Bench'
        Computer  = $env:COMPUTERNAME
        Algo      = $Algo
        Bytes     = $TotalBytes
        Seconds   = [math]::Round($elapsed, 2)
        MBps      = [math]::Round(($TotalBytes/1MB)/$elapsed, 2)
      }
    } catch {
      [pscustomobject]@{
        Type      = 'Bench'
        Computer  = $env:COMPUTERNAME
        Algo      = $Algo
        Bytes     = $TotalBytes
        Seconds   = $null
        MBps      = $null
        Error     = $_.Exception.Message
      }
    } finally {
      if ($sha) { $sha.Dispose() }
    }
  }

  # B) Real hash payload (with copy): compute Get-FileHash on remote copy
  $RemoteHash = {
    param([string]$RemotePath, [string]$Algo)
    $ErrorActionPreference = 'Stop'
    try {
      $sw = [System.Diagnostics.Stopwatch]::StartNew()
      $h = Get-FileHash -LiteralPath $RemotePath -Algorithm $Algo -ErrorAction Stop
      $sw.Stop()
      $size = (Get-Item -LiteralPath $RemotePath).Length
      $elapsed = [math]::Max($sw.Elapsed.TotalSeconds, 0.0001)
      [pscustomobject]@{
        Type     = 'RemoteHash'
        Computer = $env:COMPUTERNAME
        Algo     = $Algo
        Hash     = $h.Hash
        Bytes    = $size
        Seconds  = [math]::Round($elapsed, 2)
        MBps     = [math]::Round(($size/1MB)/$elapsed, 2)
        Path     = $RemotePath
      }
    } catch {
      [pscustomobject]@{
        Type     = 'RemoteHash'
        Computer = $env:COMPUTERNAME
        Algo     = $Algo
        Hash     = $null
        Bytes    = $null
        Seconds  = $null
        MBps     = $null
        Path     = $RemotePath
        Error    = $_.Exception.Message
      }
    } finally {
      # Remove the file copy if present
      try { Remove-Item -LiteralPath $RemotePath -Force -ErrorAction SilentlyContinue } catch {}
    }
  }

  $jobTag = ("HashMeasure_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
  $script:jobs = @()
  Write-Info "Starting parallel remote jobs (tag: $jobTag)..."

  function Start-RemoteJob {
    param([string]$Computer)

    # simple WSMan check first
    try { Test-WSMan -ComputerName $Computer -ErrorAction Stop | Out-Null }
    catch { return [pscustomobject]@{ Type='EarlyFail'; Computer=$Computer; Error="WSMan: $($_.Exception.Message)" } }

    if ($CopyToRemotes) {
      # Copy file to remote %TEMP%\hash_measure\<filename>
      $sess = $null
      try {
        $sess = New-PSSession -ComputerName $Computer -ErrorAction Stop -Credential:$cred
        $remoteTemp = Invoke-Command -Session $sess -ScriptBlock { Join-Path $env:TEMP ("hash_measure_" + [guid]::NewGuid().ToString("N")) }
        $null = Invoke-Command -Session $sess -ScriptBlock { param($p) New-Item -ItemType Directory -Path $p -Force | Out-Null } -ArgumentList $remoteTemp
        $remotePath = Join-Path $remoteTemp $fileInfo.Name
        Copy-Item -Path $localPath -Destination $remotePath -ToSession $sess -Force -ErrorAction Stop

        # Start remote hash job
        $startParams = @{
          Name        = "$jobTag`_$Computer"
          ArgumentList= @($remotePath, $Algorithm, $cred, $RemoteHash, $Computer)
          ScriptBlock = {
            param($RPath, $Algo, $Cred, $RemoteHashSB, $Target)
            $ErrorActionPreference = 'Stop'
            try {
              Invoke-Command -ComputerName $Target -Credential:$Cred -ScriptBlock $RemoteHashSB -ArgumentList @($RPath, $Algo)
            } catch {
              [pscustomobject]@{ Type='RemoteHash'; Computer=$Target; Algo=$Algo; Error=$_.Exception.Message; Path=$RPath }
            }
          }
        }
      } catch {
        if ($sess) { try { Remove-PSSession $sess } catch {} }
        return [pscustomobject]@{ Type='EarlyFail'; Computer=$Computer; Error="Copy/Session: $($_.Exception.Message)" }
      }

      # Launch local job that will call remote to compute hash; session not needed after Copy-Item
      if ($sess) { try { Remove-PSSession $sess } catch {} }
      return Start-Job @startParams
    }
    else {
      # Benchmark job (no copy)
      $block = 4MB
      $startParams = @{
        Name        = "$jobTag`_$Computer"
        ArgumentList= @($fileSize, $Algorithm, [int]$block, $cred, $RemoteBench, $Computer)
        ScriptBlock = {
          param($Size, $Algo, $BlockBytes, $Cred, $BenchSB, $Target)
          $ErrorActionPreference = 'Stop'
          try {
            Invoke-Command -ComputerName $Target -Credential:$Cred -ScriptBlock $BenchSB -ArgumentList @($Size, $Algo, $BlockBytes)
          } catch {
            [pscustomobject]@{ Type='Bench'; Computer=$Target; Algo=$Algo; Error=$_.Exception.Message; Bytes=$Size }
          }
        }
      }
      return Start-Job @startParams
    }
  }

  # Kick off all
  foreach ($c in $Computers) {
    $jobOrFail = Start-RemoteJob -Computer $c
    if ($jobOrFail -is [System.Management.Automation.Job]) { $script:jobs += $jobOrFail }
    else {
      # Early failure pseudo-row (will show later)
      $script:jobs += Start-Job -Name "$jobTag`_$($c)_failwrap" -ScriptBlock { param($x) $x } -ArgumentList $jobOrFail
    }
  }
}

process { }

end {
  if (-not $jobs -or $jobs.Count -eq 0) { Write-ErrMsg "No jobs started."; return }

  Write-Info "Polling jobs..."
  $start = Get-Date
  while ($true) {
    if ((Get-Date) - $start -gt [timespan]::FromSeconds($OverallTimeoutSec)) {
      Write-Warn "Overall timeout reached; stopping remaining jobs..."
      foreach ($j in ($jobs | Get-Job | Where-Object State -eq 'Running')) { try { Stop-Job $j -Force } catch {} }
      break
    }

    $snap = $jobs | Get-Job | Select-Object Id, Name, State, HasMoreData, PSBeginTime, PSEndTime
    $snap | Format-Table -AutoSize
    if ($snap.State -contains 'Running') { Start-Sleep -Milliseconds 800 } else { break }
  }

  # Receive & cleanup
  Write-Info "Collecting results..."
  $all = @()
  foreach ($j in $jobs) {
    try { $all += Receive-Job -Job $j -ErrorAction SilentlyContinue } catch {}
  }
  Write-Info "Cleaning up jobs..."
  foreach ($j in $jobs) { try { Stop-Job $j -Force -ErrorAction SilentlyContinue } catch {}; try { Remove-Job $j -Force -ErrorAction SilentlyContinue } catch {} }

  if (-not $all -or $all.Count -eq 0) { Write-ErrMsg "No results."; return }

  # Split
  $earlyFails = $all | Where-Object { $_.Type -eq 'EarlyFail' }
  $benches    = $all | Where-Object { $_.Type -eq 'Bench' }
  $rhashes    = $all | Where-Object { $_.Type -eq 'RemoteHash' }

  # Summary
  Write-Host ""
  Write-Host "===== LOCAL RESULT =====" -ForegroundColor Green
  if ($localHash) {
    Write-Host ("File: {0}" -f $fileInfo.FullName)
    Write-Host ("Algo: {0}" -f $Algorithm)
    Write-Host ("Hash: {0}" -f $localHash)
    Write-Host ("Time: {0}s   Throughput: {1} MB/s" -f $localSeconds, $localMBps)
  } else {
    Write-Warn "Local hashing failed."
  }

  if ($earlyFails.Count -gt 0) {
    Write-Host ""
    Write-Warn "Early connection/copy failures:"
    $earlyFails | Select-Object Computer, Error | Format-Table -AutoSize
  }

  if (-not $CopyToRemotes) {
    Write-Host ""
    Write-Host "===== REMOTE BENCHMARKS (no file copy) =====" -ForegroundColor Green
    if ($benches.Count -eq 0) { Write-Warn "No benchmark data."; }
    else {
      $benches |
        Select-Object Computer, Algo, @{n='BytesMB';e={[math]::Round($_.Bytes/1MB,2)}}, Seconds, MBps, Error |
        Sort-Object Computer | Format-Table -AutoSize

      Write-Host ""
      Write-Host "Estimated times to hash THIS file remotely (based on MB/s):" -ForegroundColor Cyan
      ($benches | ForEach-Object {
        if ($_.MBps -and $_.MBps -gt 0) {
          [pscustomobject]@{
            Computer = $_.Computer
            EstSeconds = [math]::Round( ($fileSize/1MB) / $_.MBps, 2 )
            MBps = $_.MBps
          }
        }
      } | Sort-Object Computer) | Format-Table -AutoSize
    }
  }
  else {
    Write-Host ""
    Write-Host "===== REMOTE REAL HASHES (file copied to %TEMP%) =====" -ForegroundColor Green
    if ($rhashes.Count -eq 0) { Write-Warn "No remote hash data."; }
    else {
      $rhashes |
        Select-Object Computer, Algo, Hash, @{n='BytesMB';e={[math]::Round(($_.Bytes/1MB),2)}}, Seconds, MBps, Error |
        Sort-Object Computer | Format-Table -AutoSize

      # Compare remote hashes to local if local succeeded
      if ($localHash) {
        $mismatch = $rhashes | Where-Object { $_.Hash -and $_.Hash -ne $localHash }
        if ($mismatch.Count -gt 0) {
          Write-Warn "WARNING: {0} remote hash(es) did not match local." -f $mismatch.Count
          $mismatch | Select-Object Computer, Hash | Format-Table -AutoSize
        } else {
          Write-Info "All remote hashes matched local."
        }
      }
    }
  }

  Write-Host ""
  Write-Info "Done."
}
