#Before starting, you must run "Set-ExecutionPolicy -Scope Process Bypass -Force"

<# ================= Windows Threat-Hunting Survey (PS 5.1 compatible, no file locks) ================= #>

# Keep errors visible while stabilizing; switch to 'SilentlyContinue' later if desired
$ErrorActionPreference = 'Continue'

# ---- Run a scriptblock with a timeout (PowerShell 5.1) ----
function Invoke-WithTimeout {
  param(
    [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
    [int]$Seconds = 5
  )
  $job = Start-Job -ScriptBlock $ScriptBlock
  try {
    if (Wait-Job -Job $job -Timeout $Seconds) {
      $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
      return $result
    } else {
      Stop-Job -Job $job -Force | Out-Null
      return $null  # caller can treat as timeout
    }
  } finally {
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
  }
}

# Resolve output directory (works when run from .ps1 or pasted into console)
if ($PSScriptRoot -and (Test-Path -LiteralPath $PSScriptRoot)) {
  $dir = $PSScriptRoot
} elseif ($PSCommandPath) {
  $dir = Split-Path -LiteralPath $PSCommandPath -Parent
} else {
  $dir = (Get-Location).Path
}

# Optionally avoid Downloads/OneDrive (indexers/AV can slow/lock); write to C:\Temp\Surveys instead
try {
  if ($dir -match 'Downloads|OneDrive') {
    $dir = 'C:\Temp\Surveys'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  }
} catch { }

# Filenames
$ts   = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$hostname = $env:COMPUTERNAME
$txt  = Join-Path $dir ("WIN_SURVEY-{0}-{1}.txt" -f $hostname,$ts)
$json = Join-Path $dir ("WIN_SURVEY-{0}-{1}.json" -f $hostname,$ts)

# Simple logger: each write opens/closes file (no persistent lock)
New-Item -ItemType File -Path $txt -Force | Out-Null
function Write-Line { param([string]$s = '') Add-Content -LiteralPath $txt -Value $s }
function Write-Header { param([Parameter(Mandatory=$true)][string]$Title)
  Write-Line ''
  Write-Line '############################################################'
  Write-Line ("# {0}" -f $Title)
  Write-Line '############################################################'
}
function Write-Block { param($Object)
  if ($null -eq $Object) { Write-Line "(no data)"; return }
  $arr = @($Object)
  if ($arr.Count -eq 0) { Write-Line "(no data)"; return }
  if ($Object -is [string]) {
    if ([string]::IsNullOrWhiteSpace($Object)) { Write-Line "(no data)" } else { Write-Line $Object }
    return
  }
  $text = ($Object | Format-Table -AutoSize | Out-String)
  if ([string]::IsNullOrWhiteSpace($text)) { Write-Line "(no data)" } else { Write-Line $text.TrimEnd() }
}

# Console progress beacons
function Show-Step { param([string]$s) Write-Host ("[+] {0}" -f $s) }

# Helpers (approved verbs, PS 5.1 friendly)
function Invoke-Safely { param([scriptblock]$Script, $OnError = $null) try { & $Script } catch { $OnError } }
function Invoke-External { param([string]$Exe, [string[]]$Arguments) & $Exe @Args 2>&1 | Out-String }
function Test-CommandAvailable { param([string]$Name) if (Get-Command -Name $Name -ErrorAction SilentlyContinue) { $true } else { $false } }
function Invoke-Sysinternals { param([string]$Exe, [string[]]$Arguments = @())
  $cmd = Get-Command -Name $Exe -ErrorAction SilentlyContinue
  if ($cmd) { $cmd = $cmd.Source } else { $cmd = Join-Path $dir $Exe }
  if (Test-Path -LiteralPath $cmd) { & $cmd @Args 2>&1 | Out-String } else { "[!] Skipped: {0} not found" -f $Exe }
}

# Survey object for JSON
$Survey = [ordered]@{}
$Survey.Admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Survey.Start = Get-Date

# Start banner
Write-Host  "Writing TXT to:  $txt"
Write-Host  "Will write JSON to: $json"
Write-Line ("Windows Threat-Hunting Survey Started: {0}" -f (Get-Date))
Write-Line ("Output (TXT):  {0}" -f $txt)
Write-Line ("Output (JSON): {0}" -f $json)

# ======================= Sections =======================

# Timestamp & Host
Show-Step   "Timestamp & Host"
Write-Header "Timestamp & Host"
$os  = Invoke-Safely { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture }
$who = "{0}\{1}" -f $env:USERDOMAIN,$env:USERNAME
$hostnameInfo = [ordered]@{
  ComputerName = $env:COMPUTERNAME
  User         = $who
  Time         = Get-Date
  OS           = $os
}
$Survey.host_time = $hostnameInfo
Write-Block ($hostnameInfo | Format-List | Out-String)

# ======================= Sessions / Shares / Open Files (timeout-safe) =======================
Show-Step   "Sessions / Shares / Open Files"
Write-Header "Sessions / Shares / Open Files"

# Fast pre-check: if Server service is stopped, skip SMB cmdlets to avoid delays
$lanman = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue

$lanmanRunning = $lanman -and $lanman.Status -eq 'Running'

$shares = $null; $sessions = $null; $opens = $null

if ($lanmanRunning) {
  $shares   = Invoke-WithTimeout { Get-SmbShare   | Select-Object Name,Path,Description,ShareState,FolderEnumerationMode }  -Seconds 5
  $sessions = Invoke-WithTimeout { Get-SmbSession | Select-Object ClientComputerName,UserName,NumOpens,Dialect,Encryption } -Seconds 5
  $opens    = Invoke-WithTimeout { Get-SmbOpenFile| Select-Object ClientComputerName,UserName,Path,NumLocks }               -Seconds 5
} else {
  Write-Line "(info) LanmanServer (Server) service is not running; skipping SMB cmdlets."
}

# Fallbacks trigger if null or empty (timeout or no data)
if ($null -eq $shares   -or @($shares).Count   -eq 0) { $shares   = Invoke-External 'cmd' @('/c','net','share') }

# if ($null -eq $sessions -or @($sessions).Count -eq 0) { $sessions = Invoke-External 'cmd' @('/c','net','session') }

# No good CLI for open files on clients; leave as "(no data)" if empty

$Survey.smb_shares   = $shares
$Survey.smb_sessions = $sessions
$Survey.smb_open     = $opens

Write-Block $shares
Write-Block $sessions
Write-Block $opens

# Network config / routes / neighbors
Show-Step   "Network Configuration"
Write-Header "Network Configuration"
$Survey.ipconfig  = Invoke-Safely { Get-NetIPConfiguration }
$Survey.routes    = Invoke-Safely { Get-NetRoute | Sort-Object ifIndex,DestinationPrefix }
$Survey.neighbors = Invoke-Safely { Get-NetNeighbor | Sort-Object ifIndex,IPAddress }
Write-Block $Survey.ipconfig
Write-Block $Survey.routes
Write-Block $Survey.neighbors

# Active connections (with process)
Show-Step   "Active Connections"
Write-Header "Active Connections (with owning process)"
$cons = Invoke-Safely {
  Get-NetTCPConnection -State Established,Listen,TimeWait |
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
    Sort-Object State,LocalPort
}
if ($null -eq $cons -or @($cons).Count -eq 0) {
  $ns = Invoke-External 'cmd' @('/c','netstat','-ano')
  $Survey.netstat = $ns
  Write-Block $ns
} else {
  $consX = foreach ($c in $cons) {
    $pname = Invoke-Safely { (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName }
    New-Object psobject -Property ([ordered]@{
      LocalAddress  = $c.LocalAddress
      LocalPort     = $c.LocalPort
      RemoteAddress = $c.RemoteAddress
      RemotePort    = $c.RemotePort
      State         = $c.State
      PID           = $c.OwningProcess
      Process       = $pname
    })
  }
  $Survey.net_connections = $consX
  Write-Block $consX
}

# ARP / DNS cache
Show-Step   "ARP / DNS Cache"
Write-Header "ARP / DNS Cache"

$Survey.arp = Invoke-Safely {
    Get-NetNeighbor -AddressFamily IPv4 |
    Select-Object ifIndex,IPAddress,LinkLayerAddress,State
}

Write-Block $Survey.arp
# $Survey.dns = Invoke-External 'cmd' @('/c','ipconfig','/displaydns')
$Survey.dns = Invoke-Safely {
    Get-DnsClientCache |
    Select-Object Entry, RecordType, Data
}

Write-Block $Survey.dns

# Services
Show-Step   "Services"
Write-Header "Services"
$svcs = Invoke-Safely { Get-Service | Select-Object Status,Name,DisplayName | Sort-Object Status,Name }
if ($null -eq $svcs -or @($svcs).Count -eq 0) { $svcs = Invoke-External 'cmd' @('/c','sc','query') }
$Survey.services = $svcs
Write-Block $svcs

# Processes
Show-Step   "Processes"
Write-Header "Processes"
$procs = Get-Process -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,Path,StartTime,CPU,PM,WS
$Survey.processes = $procs
Write-Block $procs

# Drivers
Show-Step   "Loaded Drivers (kernel)"
Write-Header "Loaded Drivers (kernel)"
$drivers = Invoke-Safely { Get-CimInstance Win32_SystemDriver | Select-Object State,Name,DisplayName,PathName,StartMode }
$Survey.drivers = $drivers
Write-Block $drivers

# NBT
Show-Step   "NBT Name Cache"
Write-Header "NBT Name Cache"
$Survey.nbtstat = nbtstat -nr 
# Invoke-WithTimeout { 
#     Invoke-External 'cmd' @('/c','nbtstat','-nr') 
# } -Seconds 5

# $Survey.nbtstat = Invoke-External 'cmd' @('/c','nbtstat','-nr')
Write-Block $Survey.nbtstat

# Autoruns (Registry)
Show-Step   "Autoruns (Registry)"
Write-Header "Autoruns (Registry)"
function Get-RunKeyValues { param([string]$Path)
  Invoke-Safely { Get-Item -LiteralPath $Path -ErrorAction Stop | Get-ItemProperty | Select-Object * -ExcludeProperty PS* }
}
$autoruns = [ordered]@{
  HKCU_Run     = Get-RunKeyValues 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
  HKLM_Run     = Get-RunKeyValues 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
  HKLM_RunOnce = Get-RunKeyValues 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
  Svchost      = Invoke-Safely { Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost' | Get-ItemProperty | Select-Object * -ExcludeProperty PS* }
}
$Survey.autoruns = $autoruns
Write-Block ($autoruns.GetEnumerator() | Sort-Object Name | Format-Table -AutoSize | Out-String)

# Startup folders
Show-Step   "Startup Folders"
Write-Header "Startup Folders"
$startup = @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
) | ForEach-Object {
  if (Test-Path $_) { Get-ChildItem -Path $_ -Force | Select-Object FullName,LastWriteTime,Length }
}
$Survey.startup_folders = $startup
Write-Block $startup

# Scheduled Tasks
Show-Step   "Scheduled Tasks"
Write-Header "Scheduled Tasks (non-Microsoft first)"
$tasks = Invoke-Safely {
  Get-ScheduledTask | ForEach-Object {
    $inf = Invoke-Safely { $_ | Get-ScheduledTaskInfo }
    New-Object psobject -Property ([ordered]@{
      TaskName   = $_.TaskName
      TaskPath   = $_.TaskPath
      State      = $_.State
      Author     = $_.Author
      NextRun    = if ($inf) { $inf.NextRunTime } else { $null }
      LastRun    = if ($inf) { $inf.LastRunTime } else { $null }
      LastResult = if ($inf) { $inf.LastTaskResult } else { $null }
      Actions    = ($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() }) -join ' | '
    })
  } | Sort-Object { $_.TaskPath -notlike '\Microsoft*' }, TaskPath, TaskName
}
$Survey.scheduled_tasks = $tasks
if ($null -eq $tasks -or @($tasks).Count -eq 0) {
  Write-Line "(no data or Task Scheduler inaccessible)"
} else {
  Write-Block $tasks
}

# Console history
Show-Step   "Console History"
Write-Header "Console History (PSReadLine)"
$hist = Invoke-Safely { Get-History | Select-Object Id,CommandLine,StartExecutionTime,EndExecutionTime }
$Survey.ps_history = $hist
if ($null -eq $hist -or @($hist).Count -eq 0) {
  Write-Line "(no data - new session or history disabled)"
} else {
  Write-Block $hist
}

# Sysinternals (optional)
Show-Step   "Sysinternals"
Write-Header "Sysinternals (auto-skip if missing)"
$sys = [ordered]@{}
$sys.logonsessions = Invoke-Sysinternals 'logonsessions.exe'
Write-Block $sys.logonsessions
$sys.psfile        = Invoke-Sysinternals 'psfile.exe'
Write-Block $sys.psfile
$sys.psloggedon    = Invoke-Sysinternals 'psloggedon.exe'
Write-Block $sys.psloggedon
$sys.psservice     = Invoke-Sysinternals 'psservice.exe'
Write-Block $sys.psservice
$sys.pslist        = Invoke-Sysinternals 'pslist.exe'
Write-Block $sys.pslist
$sys.listdlls      = Invoke-Sysinternals 'listdlls.exe' @('-r')
Write-Block $sys.listdlls
$sys.handle        = Invoke-Sysinternals 'handle.exe'
Write-Block $sys.handle
$Survey.Sysinternals = $sys

# Wrap up
Show-Step   "Wrap-up"
Write-Header "Survey Complete"
Write-Line ("TXT:  {0}" -f $txt)
Write-Line ("JSON: {0}" -f $json)
$Survey.End = Get-Date

# JSON last (single write), so no lock conflicts
$Survey | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $json -Encoding UTF8

Write-Host "Done. Output saved to:`n$txt`n$json"
