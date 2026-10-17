# BOMB SQUAD - static analysis demonstration
# The commands below are examples only.
# This block is never executed.

if ($false) {
    Remove-Item -LiteralPath 'demo-cache'
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-ItemProperty -Path 'HKCU:\Software\BombSquadDemo' -Name Enabled -Value 1
    Add-LocalGroupMember -Group 'Administrators' -Member 'demo-user'
    Register-ScheduledTask -TaskName 'DemoTask' -Action $action
    Invoke-Expression $dynamicSource
}
