# disables/enables vanguard
$thisScript = $MyInvocation.MyCommand.Definition
$needRestart = $false

Write-Host -ForegroundColor Yellow "Checking for Administrator principal"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host -ForegroundColor Red "PowerShell not running as administrator - Reopening..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$thisScript`"" -Verb RunAs
    Write-Host -ForegroundColor Yellow "Completed."
    exit
}

try {
    $service = Get-Service -Name "vgc"
    if ($service.StartType -eq "Manual") {
        Write-Host -ForegroundColor Yellow "VGC is set to manual, disabling..."
        $service | Set-Service -StartupType "Disabled"
        Stop-Service $service -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Green "VGC now disabled"
    }
    else {
        Write-Host -ForegroundColor Yellow "VGC is likely disabled, enabling..."
        $service | Set-Service -StartupType "Manual"
        Write-Host -ForegroundColor Red "VGC now enabled"
    }

    $service = Get-Service -Name "vgk"
    if ($service.StartType -eq "System") {
        Write-Host -ForegroundColor Yellow "VGK is set to System, disabling..."
        $service | Set-Service -StartupType "Disabled"
        Stop-Service $service -ErrorAction SilentlyContinue
        Write-Output -ForegroundColor Green "VGK is now disabled"
    }
    else {
        Write-Host -ForegroundColor Yellow "VGK is likely disabled, enabling..."
        $command = { sc.exe config vgk start= system }
        . $command | Out-Null
        $needRestart = $true
        Write-Host -ForeGroundColor Red "VGK enabled"
    }
}
catch {
    Write-Host $_
}

Write-Host -Foreground Red "Killing Vanguard Tray"
Get-Process -Name "vgtray" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if ($needRestart) {
    Write-Host -ForegroundColor Red "To load driver, restart is required."
    Write-Host -ForegroundColor Red "Read the prompt below."
    Write-Host ""
    Restart-Computer -Confirm
}

Write-Host -ForegroundColor Green -NoNewline "Script has finished."
Write-Host -ForegroundColor Yellow -NoNewline "Press any key to continue..."
[void][System.Console]::ReadKey($true)
