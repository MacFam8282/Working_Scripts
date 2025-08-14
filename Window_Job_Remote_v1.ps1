<# 
.SYNOPSIS
  Pipeline + parallel jobs remote audit (computer info + files), with cleanup.

.DESCRIPTION
  - Accepts computer names via -Computers or prompts (can also pipe them in)
  - Uses the pipeline to Start parallel jobs: one per computer
  - Each job checks WinRM, then runs Invoke-Command on the target to gather:
      * OS caption/version/last boot
      * BIOS version/serial
      * Files in a given path (name, size, last write)
  - Displays live job status table while they run
  - Receives results, prints summaries + per-computer file tables
  - Stops & removes all jobs created by this run

.EXAMPLES
  .\Run-ParallelAudit.ps1
  @('PC-A','PC-B','PC-C','PC-D') | .\Run-ParallelAudit.ps1 -RemotePath 'C:\Logs'
  .\Run-ParallelAudit.ps1 -Computers PC-A,PC-B -PromptForCredential
#>

[CmdletBinding()]
param(
  [Parameter(ValueFromPipeline=$true)]
  [string[]]$Computers,

  [Parameter(Mandatory=$false)]
  [string]$RemotePath = 'C:\Windows\Temp',

  [Parameter(Mandatory=$false)]
  [switch]$PromptForCredential
)

begin {
  # Console helpers
  function Write-Info   { param([string]$m) Write-Host "[INFO ] $m" -ForegroundColor Cyan }
  function Write-Warn   { param([string]$m) Write-Host "[WARN ] $m" -ForegroundColor Yellow }
  function Write-ErrMsg { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

  # Prompt for computers if none were passed
  if (-not $PSBoundParameters.ContainsKey('Computers') -or -not $Computers -or $Computers.Count -eq 0) {
    Write-Info "Enter computer names (comma or space separated). Example: PC-A, PC-B PC-C PC-D"
    $raw = Read-Host "Computers"
    $Computers = $raw -split '[,\s]+' | Where-Object { $_ -and $_.Trim() } | ForEach-Object Trim | Select-Object -Unique
  }

  if (-not $Computers -or $Computers.Count -eq 0) {
    Write-ErrMsg "No computer names provided."; break
  }

  # Confirm/override remote path
  Write-Info "Remote path to list files from (default: $RemotePath)"
  $rp = Read-Host "RemotePath (press Enter to keep default)"
  if ($rp) { $RemotePath = $rp }

  # Optional credentials
  $cred = $null
  if ($PromptForCredential) {
    $cred = Get-Credential -Message "Enter credentials for remote connections"
  }

  # Choose job type (ThreadJob if available in PS7 for better perf)
  $UseThreadJob = $false
  if (Get-Module -ListAvailable -Name ThreadJob | Out-Null) { $UseThreadJob = $true }

  # Payload that runs on the remote machine
  $RemoteWork = {
    param([string]$Path)
    $ErrorActionPreference = 'Stop'

    $os   = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, LastBootUpTime
    $bios = Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion, SerialNumber

    $files = @()
    $pathExists = $false
    try {
      if (Test-Path -LiteralPath $Path) {
        $pathExists = $true
        $files = Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction Stop |
                 Select-Object Name, Length, LastWriteTime
      }
    } catch { $files = @() }

    $totalBytes = ($files | Measure-Object -Property Length -Sum).Sum
    if (-not $totalBytes) { $totalBytes = 0 }

    # Emit a summary row + 0..N file rows
    [pscustomobject]@{
      Type        = 'Summary'
      Computer    = $env:COMPUTERNAME
      OSCaption   = $os.Caption
      OSVersion   = $os.Version
      LastBoot    = $os.LastBootUpTime
      BIOS        = $bios.SMBIOSBIOSVersion
      Serial      = $bios.SerialNumber
      Path        = $Path
      PathExists  = $pathExists
      FileCount   = $files.Count
      TotalBytes  = $totalBytes
      Name        = $null
      Length      = $null
      LastWrite   = $null
    }

    foreach ($f in $files) {
      [pscustomobject]@{
        Type        = 'File'
        Computer    = $env:COMPUTERNAME
        OSCaption   = $null
        OSVersion   = $null
        LastBoot    = $null
        BIOS        = $null
        Serial      = $null
        Path        = $Path
        PathExists  = $true
        FileCount   = $null
        TotalBytes  = $null
        Name        = $f.Name
        Length      = $f.Length
        LastWrite   = $f.LastWriteTime
      }
    }
  }

  $script:jobTag = ("ParallelAudit_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
  $script:jobs = @()
  Write-Info "Starting parallel jobs (tag: $jobTag)..."

  # Define a function to start one job (works with either Start-ThreadJob or Start-Job)
  function Start-OneAuditJob {
    param([string]$Computer)

    $startParams = @{
      Name        = "$jobTag`_$Computer"
      ArgumentList= @($Computer, $RemotePath, $cred, $RemoteWork)
      ScriptBlock = {
        param($Target, $Path, $Cred, $RemoteSB)
        $ErrorActionPreference = 'Stop'
        try {
          # Quick reachability check
          try { Test-WSMan -ComputerName $Target -ErrorAction Stop | Out-Null }
          catch {
            $msg = "WSMan/WinRM check failed for $($Target): $($_.Exception.Message)"
            throw [System.Exception]::new($msg, $_.Exception)
        }


          # Invoke remote payload
          $icmParams = @{
            ComputerName = $Target
            ScriptBlock  = $RemoteSB
            ArgumentList = @($Path)
            ErrorAction  = 'Stop'
          }
          if ($Cred) { $icmParams.Credential = $Cred }

          Invoke-Command @icmParams
        }
        catch {
          # Return a single summary row with the error
          [pscustomobject]@{
            Type        = 'Summary'
            Computer    = $Target
            OSCaption   = $null
            OSVersion   = $null
            LastBoot    = $null
            BIOS        = $null
            Serial      = $null
            Path        = $Path
            PathExists  = $false
            FileCount   = 0
            TotalBytes  = 0
            Name        = $null
            Length      = $null
            LastWrite   = $null
            Error       = $_.Exception.Message
          }
        }
      }
    }

    if ($UseThreadJob) {
      Start-ThreadJob @startParams
    } else {
      Start-Job @startParams
    }
  }
}

process {
  # Accept additional names via pipeline if provided
  foreach ($c in $Computers) {
    $null = $c # ensure foreach on the array variable
    # Start job for each computer *via the pipeline* to keep it idiomatic:
    $c | ForEach-Object {
      Start-OneAuditJob -Computer $_
    } | Tee-Object -Variable script:jobs | Out-Null
  }
}

end {
  if (-not $jobs -or $jobs.Count -eq 0) {
    Write-ErrMsg "No jobs were started. Exiting."
    return
  }

  # Live status while jobs run
  Write-Info "Waiting for jobs to complete..."
  while ($true) {
    $snap = $jobs | Get-Job | Select-Object Id, Name, State, HasMoreData, PSBeginTime, PSEndTime
    $snap | Format-Table -AutoSize
    if ($snap.State -contains 'Running') {
      Start-Sleep -Seconds 2
    } else {
      break
    }
  }

  # Receive results
  Write-Info "Receiving job results..."
  $all = @()
  $failed = @()
  foreach ($j in $jobs) {
    try {
      $null = Wait-Job -Job $j -Timeout 2
      $res = Receive-Job -Job $j -ErrorAction Stop
      $all += $res
    } catch {
      $failed += [pscustomobject]@{
        JobName = $j.Name
        JobId   = $j.Id
        Error   = $_.Exception.Message
      }
    }
  }

  # Cleanup jobs (stop & remove)
  Write-Info "Cleaning up jobs..."
  foreach ($j in $jobs) {
    try { Stop-Job -Job $j -Force -ErrorAction SilentlyContinue } catch {}
    try { Remove-Job -Job $j -Force -ErrorAction SilentlyContinue } catch {}
  }

  if ($failed.Count -gt 0) {
    Write-Warn "Some jobs failed to return results:"
    $failed | Format-Table -AutoSize
  }

  if (-not $all -or $all.Count -eq 0) {
    Write-ErrMsg "No data returned."; return
  }

  # Split & display
  $summaries = $all | Where-Object { $_.Type -eq 'Summary' }
  $files     = $all | Where-Object { $_.Type -eq 'File' }

  Write-Host ""
  Write-Host "===== Computer Summaries =====" -ForegroundColor Green
  $summaries |
    Select-Object @{n='Computer';e={$_.Computer}},
                  @{n='OS';e={$_.OSCaption}},
                  OSVersion,
                  @{n='LastBoot';e={($_.LastBoot) -as [datetime]}},
                  BIOS, Serial, Path, PathExists, FileCount,
                  @{n='TotalMB'; e={[math]::Round(($_.TotalBytes/1MB),2)}},
                  Error |
    Sort-Object Computer |
    Format-Table -AutoSize

  Write-Host ""
  Write-Host "===== File Listings (per computer) =====" -ForegroundColor Green
  $files | Group-Object Computer | ForEach-Object {
    Write-Host ""
    Write-Host ("--- {0} : {1} file(s) ---" -f $_.Name, $_.Count) -ForegroundColor Cyan
    $_.Group |
      Select-Object Name,
                    @{n='SizeKB'; e={[math]::Round(($_.Length/1KB),2)}},
                    @{n='LastWrite'; e={($_.LastWrite) -as [datetime]}} |
      Sort-Object SizeKB -Descending |
      Format-Table -AutoSize
  }

  Write-Host ""
  Write-Info "Done. All started jobs were stopped and removed."
}
