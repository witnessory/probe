# Install the Witnessory probe on Windows, for the current user (no administrator rights needed).
#
#   powershell -ExecutionPolicy Bypass -File install.ps1              install and run every hour
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall   stop and remove the program (keeps keys and results)
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Purge       remove everything, including keys and results
#
# What it does: puts the probe in its own Python environment in %LOCALAPPDATA%\witnessory-probe, keeps the probe's
# keys and results in %USERPROFILE%\.witnessory-probe, and adds a scheduled task "Witnessory probe" that runs one
# cycle every hour without opening a window. Nothing else is changed. docs\PROTOCOL.md says what the probe does.
# Needs Python 3.10 or newer (python.org, or the Microsoft Store).
param(
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$NoTask,
    [string]$Package = "witnessory-probe",
    [string]$ProbeHome = (Join-Path $env:USERPROFILE ".witnessory-probe"),
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA "witnessory-probe")
)
$ErrorActionPreference = "Stop"
$TaskName = "Witnessory probe"
$Venv = Join-Path $Prefix "venv"
$Exe = Join-Path $Venv "Scripts\witnessory-probe.exe"
$PythonW = Join-Path $Venv "Scripts\pythonw.exe"

if ($Uninstall -or $Purge) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $Prefix) { Remove-Item -Recurse -Force $Prefix }
    if ($Purge) {
        if (Test-Path $ProbeHome) { Remove-Item -Recurse -Force $ProbeHome }
        Write-Output "Witnessory probe removed, with its keys and results."
    } else {
        Write-Output "Witnessory probe removed. Its keys and results are kept in $ProbeHome (remove with -Purge)."
    }
    exit 0
}

$PyExe = $null
$PyArgs = @()
foreach ($candidate in @(@("py", "-3"), @("python"), @("python3"))) {
    $cand = $candidate[0]
    $rest = @($candidate | Select-Object -Skip 1)
    try {
        $ok = & $cand @rest -c "import sys; print(1 if sys.version_info >= (3, 10) else 0)" 2>$null
        if ($ok -eq "1") { $PyExe = $cand; $PyArgs = $rest; break }
    } catch { }
}
if (-not $PyExe) { throw "Python 3.10 or newer is needed: install it from python.org or the Microsoft Store, then run this again." }

Write-Output "Installing the probe in $Prefix ..."
New-Item -ItemType Directory -Force $Prefix | Out-Null
& $PyExe @PyArgs -m venv $Venv
& (Join-Path $Venv "Scripts\python.exe") -m pip install --quiet --upgrade $Package
& $Exe --version

if (-not (Test-Path (Join-Path $ProbeHome "card.json"))) {
    & $Exe --home $ProbeHome init
}

if (-not $NoTask) {
    $action = New-ScheduledTaskAction -Execute $PythonW -Argument "-m witnessory_probe --home `"$ProbeHome`" run --once"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1)
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -Description "Witnessory probe: measures public servers' post-quantum readiness (docs\PROTOCOL.md)" -Force | Out-Null
    Write-Output "The probe runs every hour (scheduled task '$TaskName')."
}

Write-Output ""
Write-Output "Your probe:      & '$Exe' --home '$ProbeHome' me"
Write-Output "What it did:     & '$Exe' --home '$ProbeHome' log"
Write-Output "Pause / resume:  & '$Exe' --home '$ProbeHome' pause   (or resume)"
Write-Output "Remove:          powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall"
