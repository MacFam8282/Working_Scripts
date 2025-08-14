<# 
.SYNOPSIS
  Parallel password "tries" generator with file splitting, ETA estimator,
  and per-machine credential control.

.DESCRIPTION
  - Prompts for length and charsets; partitions first characters across machines
  - Parallel remoting (ThreadJob if available, else background Job)
  - Streams batches back; host writes to rolling files (MaxLines/MaxMB thresholds)
  - Robust: connectivity checks, guarded receives, cleanup
  - Credentials:
      * -CredentialMap    : hashtable ComputerName -> PSCredential
      * -DefaultCredential: PSCredential used when a machine has no explicit mapping
      * -PromptForUnknownCredentials: prompt for machines without mapping/default
      * If none apply, connects WITHOUT -Credential (Kerberos/SSO/etc.)

.EXAMPLES
  # simplest: prompt for computers and run w/o creds
  .\Run-Parallel-PasswordTries-Split.ps1

  # provide a default domain credential for all machines
  $def = Get-Credential 'DOMAIN\User'
  .\Run-Parallel-PasswordTries-Split.ps1 -DefaultCredential $def

  # per-machine credentials (hashtable)
  $map = @{ 'depot' = (Get-Credential 'DOMAIN\svc_depot')
            'system-1' = (Get-Credential 'DOMAIN\svc_sys1') }
  .\Run-Parallel-PasswordTries-Split.ps1 -CredentialMap $map -PromptForUnknownCredentials

.NOTES
  PowerShell 5.1 compatible (no numeric separators in literals)
#>

[CmdletBinding()]
param(
  # Targets (can also be piped)
  [Parameter(ValueFromPipeline=$true)]
  [string[]]$Computers,

  # Credentials
  [hashtable]$CredentialMap,   # ComputerName (case-insensitive) -> PSCredential
  [System.Management.Automation.PSCredential]$DefaultCredential,
  [switch]$PromptForUnknownCredentials,

  # Output directory. If omitted, uses <scriptDir>\PasswordTries or $HOME\Documents\PasswordTries.
  [string]$OutputDir,

  # File splitting thresholds (either limit triggers rotation)
  [int]$MaxLinesPerFile = 2000000,  # ~2M lines per file
  [int]$MaxMBPerFile    = 100,      # ~100 MB per file (actual UTF-8 bytes)
  [int]$FlushEveryNLines = 50000,   # periodic flush to disk

  # Remote batch size (affects streaming granularity)
  [int]$RemoteBatchSize = 10000,

  # Safety / timeouts (0 = no overall timeout)
  [int]$OverallTimeoutSec = 0
)

begin {
  # ---------- console helpers ----------
  function Write-Info   { param([string]$m) Write-Host "[INFO ] $m" -ForegroundColor Cyan }
  function Write-Warn   { param([string]$m) Write-Host "[WARN ] $m" -ForegroundColor Yellow }
  function Write-ErrMsg { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

  # ---------- input helpers ----------
  function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $true)
    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
      $resp = Read-Host "$Prompt $suffix"
      if ([string]::IsNullOrWhiteSpace($resp)) { return $Default }
      switch -Regex ($resp.Trim()) { '^(y|yes)$' {return $true}; '^(n|no)$' {return $false}; default {Write-Warn "Please answer yes or no."} }
    }
  }
  function Read-Int {
    param([string]$Prompt, [int]$Min = 1, [int]$Max = 12, [int]$Default = 3)
    while ($true) {
      $resp = Read-Host "$Prompt [$Default]"
      if ([string]::IsNullOrWhiteSpace($resp)) { return $Default }
      if ($resp -match '^\d+$') { $val = [int]$resp; if ($val -ge $Min -and $val -le $Max) { return $val } }
      Write-Warn "Enter an integer between $Min and $Max."
    }
  }

  # ---------- safe output dir ----------
  function Resolve-SafeOutputDir {
    param([string]$OutputDirParam)
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir  = $null
    if ($scriptPath -and (Test-Path -LiteralPath $scriptPath)) { try { $scriptDir = Split-Path -Parent $scriptPath } catch {} }
    if ([string]::IsNullOrWhiteSpace($OutputDirParam)) {
      if ($scriptDir) { return (Join-Path $scriptDir 'PasswordTries') }
      else { return (Join-Path $env:USERPROFILE 'Documents\PasswordTries') }
    }
    if ([System.IO.Path]::IsPathRooted($OutputDirParam)) { return $OutputDirParam }
    else { if ($scriptDir) { return (Join-Path $scriptDir $OutputDirParam) } else { return (Join-Path (Join-Path $env:USERPROFILE 'Documents') $OutputDirParam) } }
  }

  # ---------- computers ----------
  if (-not $PSBoundParameters.ContainsKey('Computers') -or -not $Computers -or $Computers.Count -eq 0) {
    Write-Info "Enter computer names (comma or space separated). Example: depot, system-1 system-2 system-3"
    $raw = Read-Host "Computers"
    $Computers = $raw -split '[,\s]+' | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() } | Select-Object -Unique
  }
  if (-not $Computers -or $Computers.Count -eq 0) { Write-ErrMsg "No computer names provided."; break }

  # Normalize CredentialMap keys (case-insensitive lookup)
  $CredMapNorm = @{}
  if ($CredentialMap) {
    foreach ($k in $CredentialMap.Keys) {
      $name = [string]$k
      $CredMapNorm[$name.ToLower()] = $CredentialMap[$k]
    }
  }

  # ---------- length & charsets ----------
  $Length     = Read-Int  -Prompt "Password length to generate" -Min 1 -Max 12 -Default 3
  $useUpper   = Read-YesNo -Prompt "Include UPPERCASE letters (A-Z)?"            -Default $true
  $useLower   = Read-YesNo -Prompt "Include lowercase letters (a-z)?"            -Default $true
  $useDigits  = Read-YesNo -Prompt "Include digits (0-9)?"                        -Default $true
  $useSymbols = Read-YesNo -Prompt "Include special characters (!@#...)"         -Default $false

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

  # ---------- partition first chars ----------
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
      [char[]]$FirstChars,
      [char[]]$Charset,
      [int]   $Len,
      [int]   $BatchSize
    )
    $ErrorActionPreference = 'Stop'
    $n = $Charset.Count

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $count = 0L

    if ($Len -eq 1) {
      $batch = New-Object System.Collections.Generic.List[string]
      foreach ($fc in $FirstChars) {
        $batch.Add( ("{0}" -f $fc) )
        $count++
        if ($batch.Count -ge $BatchSize) {
          [pscustomobject]@{ Type='Batch'; Computer=$env:COMPUTERNAME; Data=$batch.ToArray() }
          $batch.Clear()
        }
      }
      if ($batch.Count -gt 0) { [pscustomobject]@{ Type='Batch'; Computer=$env:COMPUTERNAME; Data=$batch.ToArray() } }
      $sw.Stop()
      [pscustomobject]@{ Type='Result'; Computer=$env:COMPUTERNAME; Count=$count; DurationSec=[math]::Round($sw.Elapsed.TotalSeconds,2); RatePerSec=[math]::Round($count/[math]::Max($sw.Elapsed.TotalSeconds,0.0001),2); CharsetSize=$n; Length=$Len; AssignedFirstChars=($FirstChars -join '') }
      return
    }

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

    $perFirst = [math]::Pow($n, $Len-1)
    $batch = New-Object System.Collections.Generic.List[string]

    foreach ($fc in $FirstChars) {
      for ($t = 0L; $t -lt [int64]$perFirst; $t++) {
        $trailing = Get-TrailingString -Index $t -Base $n -Digits ($Len-1) -Chars $Charset
        $batch.Add( ("{0}{1}" -f $fc, $trailing) )
        $count++

        if ($batch.Count -ge $BatchSize) {
          [pscustomobject]@{ Type='Batch'; Computer=$env:COMPUTERNAME; Data=$batch.ToArray() }
          $batch.Clear()
        }
      }
    }

    if ($batch.Count -gt 0) { [pscustomobject]@{ Type='Batch'; Computer=$env:COMPUTERNAME; Data=$batch.ToArray() } }

    $sw.Stop()
    [pscustomobject]@{
      Type='Result'; Computer=$env:COMPUTERNAME;
      Count=$count; DurationSec=[math]::Round($sw.Elapsed.TotalSeconds,2);
      RatePerSec=[math]::Round($count/[math]::Max($sw.Elapsed.TotalSeconds,0.0001),2);
      CharsetSize=$n; Length=$Len; AssignedFirstChars=($FirstChars -join '')
    }
  }

  $jobTag = ("PwSplit_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
  $script:jobs = @()
  Write-Info "Starting parallel jobs (tag: $jobTag)..."

  # ---------- credential resolver ----------
  function Get-CredForComputer {
    param([string]$Computer)
    $key = $Computer.ToLower()
    if ($CredMapNorm.ContainsKey($key)) {
      $c = $CredMapNorm[$key]
      if ($c -is [System.Management.Automation.PSCredential]) { return $c }
    }
    if ($DefaultCredential -is [System.Management.Automation.PSCredential]) { return $DefaultCredential }
    if ($PromptForUnknownCredentials) { return Get-Credential -Message ("Enter credentials for " + $Computer) }
    return $null
  }

  # ---------- job launcher ----------
  function Start-OneJob {
    param([string]$Computer, [char[]]$FirstCharsForThisMachine)

    $credToUse = Get-CredForComputer -Computer $Computer

    # Connectivity pre-check
    try {
      if ($credToUse -is [System.Management.Automation.PSCredential]) {
        $sess = New-PSSession -ComputerName $Computer -Credential $credToUse -ErrorAction Stop
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
      } else {
        Test-WSMan -ComputerName $Computer -ErrorAction Stop | Out-Null
      }
    } catch {
      return Start-Job -Name "$jobTag`_$($Computer)_fail" -ScriptBlock {
        param($c,$e)
        [pscustomobject]@{ Type='Result'; Computer=$c; Count=0; DurationSec=$null; RatePerSec=$null; Error=("Connect: " + $e) }
      } -ArgumentList $Computer, $_.Exception.Message
    }

    # Start the worker job, adding -Credential only if we have one
    $startParams = @{
      Name        = "$jobTag`_$Computer"
      ArgumentList= @($FirstCharsForThisMachine, $charset, $Length, $RemoteBatchSize, $RemoteWork, $Computer, $credToUse)
      ScriptBlock = {
        param($FirstChars, $Charset, $Len, $BatchSize, $SB, $Target, $Cred)
        $ErrorActionPreference = 'Stop'
        try {
          $icmParams = @{
            ComputerName = $Target
            ScriptBlock  = $SB
            ArgumentList = @($FirstChars, $Charset, $Len, $BatchSize)
            ErrorAction  = 'Stop'
          }
          if ($Cred -is [System.Management.Automation.PSCredential]) { $icmParams.Credential = $Cred }
          Invoke-Command @icmParams
        } catch {
          [pscustomobject]@{ Type='Result'; Computer=$Target; Count=0; DurationSec=$null; RatePerSec=$null; Error=$_.Exception.Message }
        }
      }
    }

    if (Get-Module -ListAvailable -Name ThreadJob) { Start-ThreadJob @startParams } else { Start-Job @startParams }
  }

  # Start all jobs
  $script:jobs = $targets | ForEach-Object { Start-OneJob -Computer $_ -FirstCharsForThisMachine $slices[$_] }

  # Prepare output directory + rolling writer
  $resolvedOutDir = Resolve-SafeOutputDir -OutputDirParam $OutputDir
  try {
    if (-not (Test-Path -LiteralPath $resolvedOutDir)) { New-Item -ItemType Directory -Path $resolvedOutDir -Force | Out-Null }
  } catch { Write-ErrMsg ("Cannot create output directory '" + $resolvedOutDir + "': " + $_.Exception.Message); break }

  $script:ResolvedOutputDir = $resolvedOutDir
  $script:Encoding = [System.Text.Encoding]::UTF8

  # Rolling writer state
  $script:FIndex = 0
  $script:LinesInCurrent = 0
  $script:BytesInCurrent = 0
  $script:TotalLines = 0

  $timestamp = Get-Date -Format yyyyMMdd_HHmmss
  $script:BaseName = "tries-$timestamp"
  $script:CurrentPath = $null
  $script:Writer = $null

  function Open-NewFile {
    $script:FIndex = $script:FIndex + 1
    if ($script:Writer) { try { $script:Writer.Flush() } catch {}; try { $script:Writer.Close() } catch {} }
    $script:LinesInCurrent = 0
    $script:BytesInCurrent = 0
    $num = "{0:D3}" -f $script:FIndex
    $script:CurrentPath = Join-Path $script:ResolvedOutputDir ($script:BaseName + "-" + $num + ".txt")
    $script:Writer = New-Object System.IO.StreamWriter($script:CurrentPath, $false, $script:Encoding)
    Write-Info ("Opened output file: " + $script:CurrentPath)
  }

  function Close-Writer {
    if ($script:Writer) { try { $script:Writer.Flush() } catch {}; try { $script:Writer.Close() } catch {}; $script:Writer = $null }
  }

  function Write-LinesRolling {
    param([string[]]$Lines)
    if (-not $script:Writer) { Open-NewFile }
    foreach ($line in $Lines) {
      $script:Writer.WriteLine($line)
      $script:LinesInCurrent = $script:LinesInCurrent + 1
      $script:TotalLines = $script:TotalLines + 1
      $script:BytesInCurrent = $script:BytesInCurrent + $script:Encoding.GetByteCount($line + "`r`n")
      if ($FlushEveryNLines -gt 0 -and ($script:LinesInCurrent % $FlushEveryNLines -eq 0)) { try { $script:Writer.Flush() } catch {} }
      if (($MaxLinesPerFile -gt 0 -and $script:LinesInCurrent -ge $MaxLinesPerFile) -or
          ($MaxMBPerFile -gt 0   -and ($script:BytesInCurrent/1MB) -ge $MaxMBPerFile)) {
        Open-NewFile
      }
    }
  }

  $script:StartTime = Get-Date
}

process { }

end {
  if (-not $jobs -or $jobs.Count -eq 0) { Write-ErrMsg "No jobs started."; return }

  Write-Info "Streaming batches and polling job status..."
  $start = Get-Date

  try {
    while ($true) {
      if ($OverallTimeoutSec -gt 0 -and (Get-Date) - $start -gt [timespan]::FromSeconds($OverallTimeoutSec)) {
        Write-Warn ("Overall timeout reached (" + $OverallTimeoutSec + " s). Stopping remaining jobs...")
        foreach ($j in ($jobs | Get-Job | Where-Object { $_.State -eq 'Running' })) { try { Stop-Job -Job $j -Force } catch {} }
        break
      }

      foreach ($j in $jobs) {
        $chunks = @()
        try { $chunks = Receive-Job -Job $j -Keep -ErrorAction SilentlyContinue } catch {}
        foreach ($o in $chunks) {
          if ($null -eq $o) { continue }
          $typeProp = $o.PSObject.Properties['Type']
          if (-not $typeProp) { continue }
          switch ($typeProp.Value) {
            'Batch' { if ($o.Data -and $o.Data.Count -gt 0) { Write-LinesRolling -Lines $o.Data } }
            default { } # 'Result' handled after completion
          }
        }
      }

      $snap = $jobs | Get-Job | Select-Object Id, Name, State, HasMoreData, PSBeginTime, PSEndTime
      $snap | Format-Table -AutoSize

      if ($snap.State -contains 'Running') { Start-Sleep -Milliseconds 800 } else { break }
    }
  }
  finally { Close-Writer }

  # Final receive & cleanup
  Write-Info "Collecting final results..."
  $all = @()
  foreach ($j in $jobs) { try { $all += Receive-Job -Job $j -ErrorAction SilentlyContinue } catch {} }

  Write-Info "Cleaning up jobs..."
  foreach ($j in $jobs) {
    try { Stop-Job -Job $j -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Job -Job $j -Force -ErrorAction SilentlyContinue } catch {}
  }

  # Results
  $results = $all | Where-Object { $_.Type -eq 'Result' }
  Write-Host ""
  Write-Host "===== Generation Results =====" -ForegroundColor Green
  if ($results.Count -eq 0) {
    Write-Warn "No result rows returned."
  } else {
    $results | Select-Object Computer, Count, DurationSec, RatePerSec, AssignedFirstChars, Error |
      Sort-Object Computer | Format-Table -AutoSize

    $clusterRate = ($results | Where-Object { $_.RatePerSec } | Measure-Object RatePerSec -Sum).Sum
    if (-not $clusterRate) { $clusterRate = 0 }
    $elapsedAll  = ((Get-Date) - $script:StartTime).TotalSeconds

    Write-Host ""
    Write-Host ("Total tries generated (host view): {0:N0}" -f $script:TotalLines)
    Write-Host ("Files written under: {0}" -f $script:ResolvedOutputDir)
    Write-Host ("Overall elapsed: {0:N1}s | Cluster measured rate: {1:N0} tries/s" -f $elapsedAll, $clusterRate)

    # -------- Brute-force ETA estimator using measured rates --------
    function Estimate-BruteForceTime {
      param([int]$CharsetSize, [int]$Length, [double]$ClusterTriesPerSec)
      $total = [math]::Pow($CharsetSize, $Length)
      $rate  = [math]::Max($ClusterTriesPerSec, 0.0001)
      $secs  = $total / $rate
      [pscustomobject]@{
        CharsetSize = $CharsetSize
        Length      = $Length
        TotalCombos = [decimal]$total
        ClusterRate = [math]::Round($rate,2)
        ETA_Secs    = [math]::Round($secs,2)
        ETA_Hours   = [math]::Round($secs/3600,2)
        ETA_Days    = [math]::Round($secs/86400,2)
        ETA_Years   = [math]::Round($secs/31557600,2)
      }
    }

    Write-Host ""
    Write-Host "===== Brute-Force ETA (measured rates) =====" -ForegroundColor Green
    $eta = Estimate-BruteForceTime -CharsetSize $N -Length $Length -ClusterTriesPerSec ([double]$clusterRate)
    $eta | Format-List

    Write-Host ""
    Write-Host "Per-machine measured rates (tries/sec):" -ForegroundColor Cyan
    $results | Select-Object Computer, RatePerSec | Sort-Object Computer | Format-Table -AutoSize
  }

  # List files created
  Write-Host ""
  Write-Host "===== Files written =====" -ForegroundColor Green
  Get-ChildItem -LiteralPath $script:ResolvedOutputDir -Filter ($script:BaseName + "-*.txt") |
    Select-Object Name, @{n='SizeMB';e={[math]::Round(($_.Length/1MB),2)}}, FullName |
    Sort-Object Name | Format-Table -AutoSize

  Write-Host ""
  Write-Info "Done."
}
