<# 
.SYNOPSIS
  Parallel remote NIC+Memory audit and distributed password "tries" generator.
  Prompts for length and character classes; streams tries to files on the host.

.DESCRIPTION
  - Prompts for: computers, password length, and which char sets to include
  - Distributes work across targets by partitioning the first character
  - Each remote streams "tries" back in batches; host writes to N files (round-robin)
  - Robust: progress display, timeouts, graceful failures, and safe output paths

.EXAMPLES
  .\Run-Parallel-PasswordTries.ps1
  'PC-A','PC-B','PC-C','PC-D' | .\Run-Parallel-PasswordTries.ps1 -OutputDir Out
  .\Run-Parallel-PasswordTries.ps1 -Computers A,B,C,D -PromptForCredential -OutputFiles 5
#>

[CmdletBinding()]
param(
  [Parameter(ValueFromPipeline=$true)]
  [string[]]$Computers,

  [switch]$PromptForCredential,

  # Output (host). If omitted, defaults to <scriptDir>\PasswordTries (or $HOME\Documents\PasswordTries if unsaved).
  [string]$OutputDir,

  [int]$OutputFiles = 3,
  [string]$OutputPrefix = "password-tries",

  # Safety/timeouts
  [int]$OverallTimeoutSec = 900  # 15 min overall guard
)

begin {
  # ---------- console helpers ----------
  function Write-Info   { param([string]$m) Write-Host "[INFO ] $m" -ForegroundColor Cyan }
  function Write-Warn   { param([string]$m) Write-Host "[WARN ] $m" -ForegroundColor Yellow }
  function Write-ErrMsg { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

  # ---------- input helpers (no [ref] usage) ----------
  function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $true)
    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
      $resp = Read-Host "$Prompt $suffix"
      if ([string]::IsNullOrWhiteSpace($resp)) { return $Default }
      switch -Regex ($resp.Trim()) {
        '^(y|yes)$' { return $true }
        '^(n|no)$'  { return $false }
        default { Write-Warn "Please answer yes or no." }
      }
    }
  }

  function Read-Int {
    param([string]$Prompt, [int]$Min = 1, [int]$Max = 12, [int]$Default = 3)
    while ($true) {
      $resp = Read-Host "$Prompt [$Default]"
      if ([string]::IsNullOrWhiteSpace($resp)) { return $Default }
      if ($resp -match '^\d+$') {
        $val = [int]$resp
        if ($val -ge $Min -and $val -le $Max) { return $val }
      }
      Write-Warn "Enter an integer between $Min and $Max."
    }
  }

  # ---------- resolve a safe output directory ----------
  function Resolve-SafeOutputDir {
    param([string]$OutputDirParam)
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir  = $null
    if ($scriptPath -and (Test-Path -LiteralPath $scriptPath)) {
      try { $scriptDir = Split-Path -Parent $scriptPath } catch {}
    }

    if ([string]::IsNullOrWhiteSpace($OutputDirParam)) {
      if ($scriptDir) { return (Join-Path $scriptDir 'PasswordTries') }
      else { return (Join-Path $env:USERPROFILE 'Documents\PasswordTries') }
    }

    if ([System.IO.Path]::IsPathRooted($OutputDirParam)) {
      return $OutputDirParam
    } else {
      if ($scriptDir) { return (Join-Path $scriptDir $OutputDirParam) }
      else { return (Join-Path (Join-Path $env:USERPROFILE 'Documents') $OutputDirParam) }
    }
  }

  # ---------- computers (prompt or accept param/pipeline) ----------
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

  # ---------- prompt for password length & char classes ----------
  $Length = Read-Int -Prompt "Password length to try" -Min 1 -Max 12 -Default 3
  $useUpper   = Read-YesNo -Prompt "Include UPPERCASE letters (A-Z)?"            -Default $true
  $useLower   = Read-YesNo -Prompt "Include lowercase letters (a-z)?"            -Default $true
  $useDigits  = Read-YesNo -Prompt "Include digits (0-9)?"                        -Default $true
  $useSymbols = Read-YesNo -Prompt "Include special characters (!@#...)"         -Default $false

  # Build charset
  $charset = @()
  if ($useUpper)   { $charset += [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ' }
  if ($useLower)   { $charset += [char[]]'abcdefghijklmnopqrstuvwxyz' }
  if ($useDigits)  { $charset += [char[]]'0123456789' }
  if ($useSymbols) { $charset += [char[]]'!@#$%^&*()-_=+[]{};:,<.>/?\|`~' }

  $charset = $charset | Select-Object -Unique
  $N = $charset.Count
  if ($N -le 0) { Write-ErrMsg "No character classes selected. Aborting."; break }

  $totalCombos = [math]::Pow($N, $Length)
  Write-Info "Charset size: $N | Length: $Length | Total combinations: $([int64]$totalCombos)"
  if ($totalCombos -gt [double]1e8) {
    $proceed = Read-YesNo -Prompt "This will generate more than 100,000,000 lines. Proceed?" -Default $false
    if (-not $proceed) { Write-Warn "User aborted."; break }
  }

  # ---------- slice first-character partitions across targets ----------
  $targets = $Computers
  $slices = @{}
  for ($i=0; $i -lt $targets.Count; $i++) { $slices[$targets[$i]] = New-Object System.Collections.Generic.List[char] }
  for ($idx=0; $idx -lt $charset.Count; $idx++) {
    $machine = $targets[$idx % $targets.Count]
    $slices[$machine].Add($charset[$idx])
  }

  # ---------- remote payload (runs on each target) ----------
  $RemoteWork = {
    param(
      [char[]]$FirstChars,  # this machine's first-char slice
      [char[]]$Charset,     # full charset
      [int]   $Len          # password length
    )
    $ErrorActionPreference = 'Stop'

    # -- NIC & Memory info
    $totalGB = $null
    $nics = @()
    try {
      $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
      $totalGB = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
    } catch { $totalGB = $null }
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

    [pscustomobject]@{ Type='System'; Computer=$env:COMPUTERNAME; MemoryGB=$totalGB; NICs=$nics }

    # ---- stream tries in batches ----
    $n  = $Charset.Count

    if ($Len -eq 1) {
      $count = 0L
      $batchSize = 10000
      $batch = New-Object System.Collections.Generic.List[string]
      foreach ($fc in $FirstChars) {
        $count++
        $batch.Add( ("{0}" -f $fc) )
        if ($batch.Count -ge $batchSize) {
          [pscustomobject]@{ Type='Batch'; Computer=$env:COMPUTERNAME; Data=$batch.ToArray() }
          $batch.Clear()
        }
      }
      if ($batch.Count -gt 0) { [pscustomobject]@{ Type='Batch'; Computer=$env:COMPUTERNAME; Data=$batch.ToArray() } }
      [pscustomobject]@{ Type='Result'; Computer=$env:COMPUTERNAME; AssignedFirstChars=($FirstChars -join ''); Count=$count; TargetCount=$FirstChars.Count; CharsetSize=$n; Length=$Len }
      return
    }

    # General case: Len >= 2; map trailing indices (base-n) without recursion
    $perFirst = [math]::Pow($n, $Len-1)
    $assigned = $FirstChars.Count
    $targetTotal = [int64]($perFirst * $assigned)

    $count = 0L
    $lastEmit = [datetime]::UtcNow.AddSeconds(-5)
    $batchSize = 10000
    $batch = New-Object System.Collections.Generic.List[string]

    function Get-TrailingString {
      param([int64]$Index, [int]$Base, [int]$Digits, [char[]]$Chars)
      $arr = New-Object 'char[]' ($Digits)
      $i = $Digits - 1
      $val = $Index
      while ($i -ge 0) {
        $digit = [int]($val % $Base)
        $arr[$i] = $Chars[$digit]
        $val = [int64]([math]::Floor($val / $Base))
        $i--
      }
      -join $arr
    }

    foreach ($fc in $FirstChars) {
      for ($t = 0L; $t -lt [int64]$perFirst; $t++) {
        $trailing = Get-TrailingString -Index $t -Base $n -Digits ($Len-1) -Chars $Charset
        $batch.Add( ("{0}{1}" -f $fc, $trailing) )
        $count++

        if ($batch.Count -ge $batchSize) {
          [pscustomobject]@{ Type='Batch'; Computer=$env:COMPUTERNAME; Data=$batch.ToArray() }
          $batch.Clear()
        }

        if (([datetime]::UtcNow - $lastEmit).TotalMilliseconds -ge 500) {
          $pct = if ($targetTotal -gt 0) { [math]::Min(100, [math]::Round(($count * 100.0) / $targetTotal,2)) } else { 100 }
          [pscustomobject]@{ Type='Progress'; Computer=$env:COMPUTERNAME; PartialCount=$count; TargetCount=$targetTotal; Percent=$pct; Timestamp=[datetime]::UtcNow }
          $lastEmit = [datetime]::UtcNow
        }
      }
    }
    if ($batch.Count -gt 0) {
      [pscustomobject]@{ Type='Batch'; Computer=$env:COMPUTERNAME; Data=$batch.ToArray() }
      $batch.Clear()
    }

    [pscustomobject]@{
      Type='Result'; Computer=$env:COMPUTERNAME; AssignedFirstChars=($FirstChars -join '');
      Count=$count; TargetCount=$targetTotal; CharsetSize=$n; Length=$Len
    }
  }

  $script:jobTag = ("ParallelPw_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
  $script:jobs = @()
  Write-Info "Starting parallel jobs (tag: $jobTag)..."

  function Start-OneJob {
    param([string]$Computer, [char[]]$FirstCharsForThisMachine)

    $startParams = @{
      Name        = "$jobTag`_$Computer"
      ArgumentList= @($FirstCharsForThisMachine, $charset, $Length, $cred, $RemoteWork, $Computer)
      ScriptBlock = {
        param($FirstChars, $Charset, $Len, $Cred, $RemoteSB, $Target)
        $ErrorActionPreference = 'Stop'
        try {
          try { Test-WSMan -ComputerName $Target -ErrorAction Stop | Out-Null }
          catch {
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
          [pscustomobject]@{ Type='System'; Computer=$Target; MemoryGB=$null; NICs=@(); Error=$_.Exception.Message }
        }
      }
    }

    if ([bool](Get-Module -ListAvailable -Name ThreadJob)) { Start-ThreadJob @startParams } else { Start-Job @startParams }
  }

  # ---------- start jobs (pipeline style Option B) ----------
  $script:jobs = $targets | ForEach-Object {
    Start-OneJob -Computer $_ -FirstCharsForThisMachine $slices[$_]
  }

  # ---------- prepare output writers on host (FAIL-SAFE) ----------
  $resolvedOutDir = Resolve-SafeOutputDir -OutputDirParam $OutputDir
  try {
    if (-not (Test-Path -LiteralPath $resolvedOutDir)) {
      New-Item -ItemType Directory -Path $resolvedOutDir -Force | Out-Null
    }
  } catch {
    Write-ErrMsg "Cannot create output directory '$resolvedOutDir': $($_.Exception.Message)"
    break
  }
  $script:ResolvedOutputDir = $resolvedOutDir
}

process { }

end {
  if (-not $jobs -or $jobs.Count -eq 0) {
    Write-ErrMsg "No jobs were started. Exiting."
    return
  }

  # ---------- open output files ----------
  $timestamp = Get-Date -Format yyyyMMdd_HHmmss
  $writers = @()
  for ($i=1; $i -le [Math]::Max(1,$OutputFiles); $i++) {
    $outPath = Join-Path $script:ResolvedOutputDir ("{0}-{1}-{2}.txt" -f $OutputPrefix, $timestamp, $i)
    try {
      $sw = New-Object System.IO.StreamWriter($outPath, $false, [System.Text.Encoding]::UTF8)
      $writers += @{ Path = $outPath; Writer = $sw }
    } catch {
      Write-ErrMsg "Failed to open output file '$outPath': $($_.Exception.Message)"
      foreach ($w in $writers) { try { $w.Writer.Flush() } catch {}; try { $w.Writer.Close() } catch {} }
      return
    }
  }
  $rr = 0  # round-robin file index

  Write-Info "Polling jobs for progress and streaming batches to files..."
  $progressState = @{}   # Computer => latest percent
  $partialCounts = @{}   # Computer => latest partial count
  $start = Get-Date

  try {
    while ($true) {
      if ((Get-Date) - $start -gt [timespan]::FromSeconds($OverallTimeoutSec)) {
        Write-Warn "Overall timeout reached ($OverallTimeoutSec s). Stopping remaining jobs..."
        foreach ($j in ($jobs | Get-Job | Where-Object State -eq 'Running')) {
          try { Stop-Job -Job $j -Force -ErrorAction SilentlyContinue } catch {}
        }
        break
      }

      $running = ($jobs | Get-Job | Where-Object State -eq 'Running')

      foreach ($j in $jobs) {
        $chunks = @()
        try { $chunks = Receive-Job -Job $j -Keep -ErrorAction SilentlyContinue } catch {}
        foreach ($o in $chunks) {
          if ($null -eq $o) { continue }
          $typeProp = $o.PSObject.Properties['Type']
          if (-not $typeProp) { continue }

          switch ($typeProp.Value) {
            'Batch' {
              if ($o.Data -and $o.Data.Count -gt 0) {
                foreach ($line in $o.Data) {
                  $writers[$rr].Writer.WriteLine($line)
                  $rr = ($rr + 1) % $writers.Count
                }
              }
            }
            'Progress' {
              $progressState[$o.Computer] = $o.Percent
              $partialCounts[$o.Computer] = $o.PartialCount
            }
            default { } # System/Result handled later
          }
        }
      }

      # Live progress table (compute fields first, no inline ifs)
      $table = foreach ($j in $jobs) {
        $comp   = ($j.Name -split '_',2)[1]
        $state  = (Get-Job -Id $j.Id).State
        $pcRaw  = if ($progressState.ContainsKey($comp)) { $progressState[$comp] } else { 0 }
        $paRaw  = if ($partialCounts.ContainsKey($comp)) { $partialCounts[$comp] } else { 0 }
        $pcText = ('{0}%' -f $pcRaw)
        [pscustomobject]@{ Computer=$comp; State=$state; Percent=$pcText; Partial=$paRaw }
      }
      $table | Sort-Object Computer | Format-Table -AutoSize

      if ($running.Count -gt 0) { Start-Sleep -Milliseconds 800 } else { break }
    }
  }
  finally {
    foreach ($w in $writers) { try { $w.Writer.Flush() } catch {}; try { $w.Writer.Close() } catch {} }
  }

  # Final receive & cleanup
  Write-Info "Collecting final results..."
  $all = @()
  foreach ($j in $jobs) { try { $all += Receive-Job -Job $j -ErrorAction SilentlyContinue } catch {} }

  Write-Info "Cleaning up jobs..."
  foreach ($j in $jobs) {
    try { Stop-Job -Job $j -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Job -Job $j -Force -ErrorAction SilentlyContinue } catch {}
  }

  if (-not $all -or $all.Count -eq 0) {
    Write-ErrMsg "No data returned."; return
  }

  # Show system info
  $systems = $all | Where-Object { $_.Type -eq 'System' }
  Write-Host ""
  Write-Host "===== System Info (NICs & Memory) =====" -ForegroundColor Green
  if ($systems.Count -eq 0) { Write-Warn "No system info returned." }
  else {
    $systems | ForEach-Object {
      $errProp = $_.PSObject.Properties['Error']
      $err = if ($errProp) { $errProp.Value } else { $null }
      if ($err) { Write-Warn "[$($_.Computer)] $err"; return }
      Write-Host ("[{0}] Memory: {1} GB" -f $_.Computer, $_.MemoryGB) -ForegroundColor Cyan
      if ($_.NICs -and $_.NICs.Count -gt 0) {
        $_.NICs | Select-Object NICName, MAC, SpeedMbps, IPv4 | Format-Table -AutoSize
      } else {
        Write-Warn "[$($_.Computer)] No NIC data returned."
      }
      Write-Host ""
    }
  }

  # Results
  $results = $all | Where-Object { $_.Type -eq 'Result' }
  Write-Host "===== Combination Results =====" -ForegroundColor Green
  if ($results.Count -eq 0) {
    Write-Warn "No counting results returned."
  } else {
    $perComp = $results | Select-Object Computer, AssignedFirstChars, Count, TargetCount, CharsetSize, Length
    $perComp | Sort-Object Computer | Format-Table -AutoSize

    $grand = ($perComp | Measure-Object Count -Sum).Sum
    Write-Host ""
    Write-Host ("TOTAL (from all machines): {0}" -f $grand) -ForegroundColor Green

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

  # List created files
  Write-Host ""
  Write-Host "===== Files written on host =====" -ForegroundColor Green
  $writers | ForEach-Object { $_.Path } | Format-Table -AutoSize

  Write-Host ""
  Write-Info "Done. All started jobs were stopped and removed."
}
