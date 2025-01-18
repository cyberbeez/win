# Step 1: Ensure Windows Firewall is enabled and configure rules
Write-Host "Configuring Windows Firewall..."

# Enable Windows Firewall
Set-NetFirewallProfile -All -Enabled True

# Block inbound ICMP (Ping) to avoid ICMP flood-based DoS attacks
New-NetFirewallRule -DisplayName "Block ICMP Echo Request" -Direction Inbound -Protocol ICMPv4 -Action Block

# Block SMBv1 (known vulnerable protocol)
New-NetFirewallRule -DisplayName "Block SMBv1" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block

# Step 2: Disable unnecessary services
Write-Host "Disabling unnecessary services..."

# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Disable Remote Desktop if not required
Write-Host "Disabling Remote Desktop..."
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1

# Disable unnecessary Windows features (example: Print Spooler if not needed)
Write-Host "Disabling Print Spooler service..."
Stop-Service -Name "Spooler" -Force
Set-Service -Name "Spooler" -StartupType Disabled

# Disable unnecessary scheduled tasks
Write-Host "Disabling unnecessary scheduled tasks..."
Disable-ScheduledTask -TaskName "Task Scheduler" 

# Step 3: Configure Account and Authentication Protection
Write-Host "Configuring Account Protection..."

# Enforce strong password policy
Set-LocalUser -Name "Administrator" -PasswordNeverExpires $false
Set-LocalUser -Name "Administrator" -AccountNeverExpires $false

# Ensure Account Lockout Policy is configured (prevents brute force attacks)
$lockoutThreshold = 5  # Max invalid login attempts
$lockoutDuration = 15   # Duration in minutes after lockout
$resetThreshold = 15    # Reset invalid attempts after this many minutes
net accounts /lockoutthreshold:$lockoutThreshold /lockoutduration:$lockoutDuration /lockoutwindow:$resetThreshold

# Step 4: Enable and configure Windows Defender Antivirus
Write-Host "Configuring Windows Defender..."

# Ensure Windows Defender is enabled and running
Start-Service -Name WinDefend
Set-Service -Name WinDefend -StartupType Automatic

# Turn on real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable Cloud-based protection
Set-MpPreference -MAPSReporting Advanced

# Step 5: Enforce Windows Updates and Patch Management
Write-Host "Configuring Windows Updates..."

# Enable Automatic Updates
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Run Windows Update immediately to ensure the latest patches are installed
Write-Host "Running Windows Update..."
Invoke-Command -ScriptBlock {Start-Process "ms-settings:windowsupdate" -ArgumentList "/force" -Verb RunAs}

# Step 6: Monitor Event Logs for Suspicious Activity
Write-Host "Configuring event logs..."

# Enable logging for critical security events
Auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
Auditpol /set /subcategory:"Logon/Logoff" /success:disable /failure:enable

# Configure to log remote access and authentication events
Auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable

# Ensure Sysmon (System Monitor) is installed (a useful tool for monitoring malicious activity)
Write-Host "Installing Sysmon for enhanced monitoring..."
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Temp\Sysmon.zip"
Expand-Archive -Path "C:\Temp\Sysmon.zip" -DestinationPath "C:\Temp\Sysmon"
Start-Process -FilePath "C:\Temp\Sysmon\sysmon.exe" -ArgumentList "-accepteula -ia"

# Step 7: Network Security Configuration
Write-Host "Configuring network security..."

# Disable NetBIOS over TCP/IP if not needed
Set-NetIPInterface -InterfaceAlias "Ethernet" -NetBios Disabled

# Enable IPsec for secure communications (optional)
Write-Host "Enabling IPsec..."
New-NetIPsecRule -Name "Block DDoS Traffic" -LocalAddress "Any" -RemoteAddress "Any" -Protocol TCP -Action RequireEncapsulation

# Enable Windows Defender Firewall logging for suspicious traffic
Set-NetFirewallProfile -All -LogAllowed True -LogFileName "C:\FirewallLogs.txt"

# Step 8: Enforce User Account Control (UAC) settings
Write-Host "Configuring User Account Control..."

# Ensure UAC is enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1

# Step 9: Backups and Recovery
Write-Host "Configuring backup and recovery..."

# Configure automatic backups (customize as needed)
New-ScheduledTask -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command Backup-Computer") -Trigger (New-ScheduledTaskTrigger -Daily -At "02:00AM") -TaskName "Daily Backup Task" -Description "Automatic backup task for Windows Server 2019"

Write-Host "Security configurations applied successfully."
