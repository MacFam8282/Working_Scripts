<# 
.SYNOPSIS
  Parallel remote audit (NIC + Memory) and distributed 3-char combination counting,
  with robust error handling and graceful failures.

.DESCRIPTION
  - Prompts for computer names (or accept -Computers / pipeline)
  - One parallel job per remote target (Start-Job / Start-ThreadJob if available)
  - Each remote returns NIC info + Memory (GB)
  - Distributes a 3-char combination COUNT across machines (Upper/Lower/Digits/Symbols by default)
  - Live job progress table
  - Aggregates totals on the host
  - Timeouts, guarded Receive-Job, and cleanup of all jobs

.EXAMPLES
  .\Run-Parallel-NIC-Memory-Combos.ps1
  'PC-A','PC-B','PC-C','PC-D' | .\Run-Parallel-NIC-Memory-Combos.ps1
  .\Run-Parallel-NIC-Memory-Combos.ps1 -Computers a,b,c,d -PromptForCredential
#>

[CmdletBinding()]
param(
  [Parameter(ValueFromPipeline=$true)]
  [string[]]$Computers,

  [switch]$PromptForCredential,

  # Character set controls
  [switch]$NoDigits,
  [switch]$NoSymbols,

  # Safety/timeouts
  [int]$OverallTimeoutSec = 600, # overall polling timeout (10 min)
  [int]$PerReceiveTimeoutMs = 1500
)

begin {
  # ---------- console helpers ----------
  function Write-Info   { param([string]$m) Write-Host "[INFO ] $m" -ForegroundColor Cyan }
  function Write-Warn   { param([string]$m) Write-Host "[WARN ] $m" -ForegroundColor Yellow }
  function Write-ErrMsg { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

  # ---------- prompt for computers if needed ----------
  if (-not $PSBoundParameters.ContainsKey('Computers') -or -not $Computers -or $Computers.Count -eq 0) {
    Write-Info "Enter computer names (comma or space separated). Example: PC-A, PC-B PC-C PC-D"
    $raw = Read-Host "Computers"
    $Computers = $raw -split '[,\s]+' | Where-Object { $_ -and $_.Trim() } | ForEach-Object Trim | Select-Object -Unique
  }
  if (-not $Computers -or $Computers.Count -eq 0) {
    Write-ErrMsg "No computer names provided."; break
  }

  # ---------- optional credentials ----------
  $cred = $null
  if ($PromptForCredential) {
    $cred = Get-Credential -Message "Enter credentials for remote connections"
  }

  # ---------- build the character set ----------
  $upper   = [char[]]([string](65..90  | ForEach-Object {[char]$_}))
  $lower   = [char[]]([string](97..122 | ForEach-Object {[char]$_}))
  $digits  = [char[]]'0123456789'
  $symbols = [char[]]'!@#$%^&*()-_=+[]{};:,<.>/?\|`~'

  $charset = @()
  $charset += $upper
  $charset += $lower
  if (-not $NoDigits)  { $charset += $digits }
  if (-not $NoSymbols) { $charset += $symbols }

  $charset = $charset | Select-Object -Unique
  $N = $charset.Count
  $comboLength = 3
  $totalCombos = [math]::Pow($N, $comboLength)

  Write-Info "Character set size: $N  |  Total 3-char combinations: $([int64]$totalCombos)"

  # ---------- slice work across machines by first-character partitions ----------
  $targets = $Computers
  $slices = @{}
  for ($i=0; $i -lt $targets.Count; $i++) { $slices[$targets[$i]] = New-Object System.Collections.Generic.List[char] }

  for ($idx=0; $idx -lt $charset.Count; $idx++) {
    $machine = $targets[$idx % $targets.Count]
    $slices[$machine].Add($charset[$idx])
  }

  # ---------- remote payload ----------
  $RemoteWork = {
    param(
      [char[]]$FirstChars,   # slice for this machine (first-character positions)
      [char[]]$Charset,      # full charset
      [int]   $Len           # length == 3
    )
    $ErrorActionPreference = 'Stop'

    # --- NIC & Memory info ---
    $totalGB = $null
    $nics = @()
    try {
      $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
      $totalGB = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
    } catch {
      $totalGB = $null
    }

    try {
      $activeAdapters = Get-CimInstance Win32_NetworkAdapter -Filter "NetEnabled = TRUE" -ErrorAction Stop
      $configs  = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction Stop |
                  Select-Object MACAddress, IPAddress, Description

      foreach ($a in $activeAdapters) {
        $conf = $configs | Where-Object { $_.Description -eq $a.Name -or $_.MACAddress -eq $a.MACAddress } | Select-Object -First 1
        $ipv4 = $null
        if ($conf -and $conf.IPAddress) { $ipv4 = ($conf.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1) }
        $nics += [pscustomobject]@{
          NICName   = $a.Name
          MAC       = $a.MACAddress
          SpeedMbps = if ($a.Speed) { [math]::Round($a.Speed/1MB,0) } else { $null }
          IPv4      = $ipv4
        }
      }
    } catch {}

    # Emit a header record with system info
    [pscustomobject]@{
      Type       = 'System'
      Computer   = $env:COMPUTERNAME
      MemoryGB   = $totalGB
      NICs       = $nics
    }

    # --- distributed combination counting (progressive output) ---
    $n  = $Charset.Count
    $perFirst = [math]::Pow($n, $Len-1)
    $assigned = $FirstChars.Count
    $targetTotal = [int64]($perFirst * $assigned)

    $count = [int64]0
    $lastEmit = [datetime]::UtcNow.AddSeconds(-5)
    $i = 0

    foreach ($fc in $FirstChars) {
      $count += [int64]$perFirst
      $i++
      if (([datetime]::UtcNow - $lastEmit).TotalMilliseconds -ge 500 -or $i -eq $assigned) {
        $pct = if ($targetTotal -gt 0) { [math]::Min(100, [math]::Round(($count * 100.0) / $targetTotal,2)) } else { 100 }
        [pscustomobject]@{
          Type          = 'Progress'
          Computer      = $env:COMPUTERNAME
          PartialCount  = $count
          TargetCount   = $targetTotal
          Percent       = $pct
          Timestamp     = [datetime]::UtcNow
        }
        $lastEmit = [datetime]::UtcNow
      }
    }

    # Emit final result row
    [pscustomobject]@{
      Type         = 'Result'
      Computer     = $env:COMPUTERNAME
      AssignedFirstChars = ($FirstChars -join '')
      Count        = $count
      TargetCount  = $targetTotal
      CharsetSize  = $n
      Length       = $Len
    }
  }

  $script:jobTag = ("ParallelAudit_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
  $script:jobs = @()
  Write-Info "Starting parallel jobs (tag: $jobTag)..."

  function Start-OneJob {
    param([string]$Computer, [char[]]$FirstCharsForThisMachine)

    $startParams = @{
      Name        = "$jobTag`_$Computer"
      ArgumentList= @($FirstCharsForThisMachine, $charset, $comboLength, $cred, $RemoteWork, $Computer)
      ScriptBlock = {
        param($FirstChars, $Charset, $Len, $Cred, $RemoteSB, $Target)
        $ErrorActionPreference = 'Stop'
        try {
          try {
            Test-WSMan -ComputerName $Target -ErrorAction Stop | Out-Null
          } catch {
            $msg = "WSMan/WinRM check failed for $($Target): $($_.Exception.Message)"
            throw [System.Exception]::new($msg, $_.Exception)
          }

          $icmParams = @{
            ComputerName = $Target
            ScriptBlock  = $RemoteSB
            ArgumentList = @($FirstChars, $Charset, $Len)
            ErrorAction  = 'Stop'
          }
          if ($Cred) { $icmParams.Credential = $Cred }

          Invoke-Command @icmParams
        }
        catch {
          # Return a system row with the error (so host can show it)
          [pscustomobject]@{
            Type       = 'System'
            Computer   = $Target
            MemoryGB   = $null
            NICs       = @()
            Error      = $_.Exception.Message
          }
        }
      }
    }

    if ([bool](Get-Module -ListAvailable -Name ThreadJob)) {
      Start-ThreadJob @startParams
    } else {
      Start-Job @startParams
    }
  }

  # ---------- start jobs (pipeline style) ----------
  $script:jobs = $targets | ForEach-Object {
    Start-OneJob -Computer $_ -FirstCharsForThisMachine $slices[$_]
  }
}

process { }

end {
  if (-not $jobs -or $jobs.Count -eq 0) {
    Write-ErrMsg "No jobs were started. Exiting."
    return
  }

  Write-Info "Polling jobs for progress..."
  $progressState = @{}   # Computer => latest percent
  $partialCounts = @{}   # Computer => latest partial count

  $start = Get-Date
  while ($true) {
    # Guard overall timeout
    if ((Get-Date) - $start -gt [timespan]::FromSeconds($OverallTimeoutSec)) {
      Write-Warn "Overall timeout reached ($OverallTimeoutSec s). Stopping remaining jobs..."
      foreach ($j in ($jobs | Get-Job | Where-Object State -eq 'Running')) {
        try { Stop-Job -Job $j -Force -ErrorAction SilentlyContinue } catch {}
      }
      break
    }

    $running = ($jobs | Get-Job | Where-Object State -eq 'Running')

    foreach ($j in $jobs) {
      # Guarded receive to avoid noisy errors
      $chunks = @()
      try {
        $chunks = Receive-Job -Job $j -Keep -ErrorAction SilentlyContinue
      } catch {
        # swallow transient deserialization/transport errors during polling
      }
      foreach ($o in $chunks) {
        if ($null -eq $o) { continue }
        if ($null -eq $o.PSObject) { continue }
        $typeProp = $o.PSObject.Properties['Type']
        if (-not $typeProp) { continue }
        switch ($typeProp.Value) {
          'Progress' {
            $progressState[$o.Computer] = $o.Percent
            $partialCounts[$o.Computer] = $o.PartialCount
          }
          default { } # System/Result handled later
        }
      }
    }

    # Render a compact live progress table (compute values first; no inline if)
    $table = foreach ($j in $jobs) {
      $comp   = ($j.Name -split '_',2)[1]
      $state  = (Get-Job -Id $j.Id).State
      $pcRaw  = if ($progressState.ContainsKey($comp)) { $progressState[$comp] } else { 0 }
      $paRaw  = if ($partialCounts.ContainsKey($comp)) { $partialCounts[$comp] } else { 0 }
      $pcText = ('{0}%' -f $pcRaw)

      [pscustomobject]@{
        Computer = $comp
        State    = $state
        Percent  = $pcText
        Partial  = $paRaw
      }
    }
    $table | Sort-Object Computer | Format-Table -AutoSize

    if ($running.Count -gt 0) {
      Start-Sleep -Milliseconds 800
    } else {
      break
    }
  }

  # Final receive (guarded)
  Write-Info "Collecting final results..."
  $all = @()
  foreach ($j in $jobs) {
    try {
      $all += Receive-Job -Job $j -ErrorAction SilentlyContinue
    } catch {
      # Keep going; we'll still emit what we have
    }
  }

  # Cleanup
  Write-Info "Cleaning up jobs..."
  foreach ($j in $jobs) {
    try { Stop-Job -Job $j -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Job -Job $j -Force -ErrorAction SilentlyContinue } catch {}
  }

  if (-not $all -or $all.Count -eq 0) {
    Write-ErrMsg "No data returned."; return
  }

  # Split streams
  $systems = $all | Where-Object { $_.Type -eq 'System' }
  $results = $all | Where-Object { $_.Type -eq 'Result' }

  # Show system (NIC + Memory) info
  Write-Host ""
  Write-Host "===== System Info (NICs & Memory) =====" -ForegroundColor Green
  if ($systems.Count -eq 0) {
    Write-Warn "No system info returned."
  } else {
    $systems | ForEach-Object {
      $err = $_.PSObject.Properties['Error']?.Value
      if ($err) {
        Write-Warn "[$($_.Computer)] $err"
        return
      }
      Write-Host ("[{0}] Memory: {1} GB" -f $_.Computer, $_.MemoryGB) -ForegroundColor Cyan
      if ($_.NICs -and $_.NICs.Count -gt 0) {
        $_.NICs | Select-Object NICName, MAC, SpeedMbps, IPv4 | Format-Table -AutoSize
      } else {
        Write-Warn "[$($_.Computer)] No NIC data returned."
      }
      Write-Host ""
    }
  }

  # Aggregate combination counts
  Write-Host "===== Combination Counting Results =====" -ForegroundColor Green
  if ($results.Count -eq 0) {
    Write-Warn "No counting results returned."
  } else {
    $perComp = $results | Select-Object Computer, AssignedFirstChars, Count, TargetCount, CharsetSize, Length
    $perComp | Sort-Object Computer | Format-Table -AutoSize

    $grand = ($perComp | Measure-Object Count -Sum).Sum
    Write-Host ""
    Write-Host ("TOTAL (from all machines): {0}" -f $grand) -ForegroundColor Green

    # Compare with expected (N^3) if we have at least one row
    $firstRow = $perComp | Select-Object -First 1
    if ($null -ne $firstRow) {
      $expected = [math]::Pow($firstRow.CharsetSize, $firstRow.Length)
      if ([int64]$expected -ne [int64]$grand) {
        Write-Warn "Mismatch vs expected total $([int64]$expected). Check machines that returned errors or timed out."
      } else {
        Write-Info "Verified total matches expected $([int64]$expected)."
      }
    }
  }

  Write-Host ""
  Write-Info "Done. All started jobs were stopped and removed."
}
