# Step 1: Ensure Windows Firewall is enabled and configure basic rules
Write-Host "Enabling Windows Firewall and configuring rules..."

# Enable Windows Firewall if it's not enabled
Set-NetFirewallProfile -All -Enabled True

# Block ping requests (ICMP Echo Request) to reduce the surface of attack
New-NetFirewallRule -DisplayName "Block ICMP Echo Request" -Direction Inbound -Protocol ICMPv4 -Action Block

# Block SYN Floods: Limit incoming TCP connections that exceed a rate limit
New-NetFirewallRule -DisplayName "Limit SYN Flood" -Direction Inbound -Protocol TCP -LocalPort 80,443,8080 -Action Block -RemoteAddress "Any"

# Block traffic from known malicious IPs (Example: list of IPs, typically from firewall rules or threat intelligence sources)
$blockedIPs = @("192.168.1.100", "203.0.113.15")  # Replace with actual IP addresses
foreach ($ip in $blockedIPs) {
    New-NetFirewallRule -DisplayName "Block Malicious IP $ip" -Direction Inbound -Protocol TCP -RemoteAddress $ip -Action Block
}

# Step 2: Rate limiting (Limit connections from the same source IP)
Write-Host "Enabling rate limiting for TCP connections..."

# Configure TCP connection limit per IP (to mitigate SYN flood attacks)
New-NetIPsecRule -Name "SYN Flood Protection" -RemoteAddress "Any" -Protocol TCP -LocalPort 80,443 -Action Block -Inbound

# Step 3: Protect against DHCP exhaustion (Limit DHCP traffic)
Write-Host "Configuring DHCP protection..."

# Block unauthorized DHCP servers (helps prevent DDoS exhaustion of DHCP resources)
New-NetFirewallRule -DisplayName "Block Unauthorized DHCP Servers" -Direction Inbound -Protocol UDP -LocalPort 67 -Action Block -RemoteAddress "Any"

# Step 4: Enable IPsec for additional protection (only if necessary for secured communication)
Write-Host "Configuring IPsec for secure communications..."

New-NetIPsecRule -Name "Block DDoS Traffic" -LocalAddress "Any" -RemoteAddress "Any" -Protocol TCP -Action RequireEncapsulation

# Step 5: Monitor network traffic for unusual spikes (log and alert)
Write-Host "Setting up network traffic monitoring..."

# You can use PowerShell to collect network traffic data
$networkStats = Get-NetAdapterStatistics -Name "Ethernet"  # Replace 'Ethernet' with your network adapter name
$networkStats

# Monitor traffic and alert when it exceeds a certain threshold (example threshold: 100 Mbps)
$threshold = 100  # Example threshold in Mbps
if ($networkStats.InboundBytes / 1MB -gt $threshold) {
    Write-Host "High inbound traffic detected: Possible DDoS attack"
    # Log this event to Windows Event Log or send alert (customize as per requirement)
    New-EventLog -LogName Application -Source "DDoSProtection" -EntryType Warning -EventId 1001 -Message "High inbound traffic detected, possible DDoS attack detected."
}

# Step 6: Rate Limiting & Time-Based Access Control
Write-Host "Enabling rate limiting for HTTP/S services..."

# You can set up a simple time-based rate limit rule for HTTP traffic (limit access to a certain rate)
$httpThreshold = 500  # Example threshold of requests per minute
$logFile = "C:\DDoSDetection\http_request_log.txt"

# Log the access requests and count them to trigger rate-limiting actions
if (Test-Path $logFile) {
    $logs = Get-Content $logFile
    $currentTime = Get-Date
    $recentLogs = $logs | Where-Object { ($_ -gt $currentTime.AddMinutes(-1)) }
    
    if ($recentLogs.Count -gt $httpThreshold) {
        Write-Host "Rate limit exceeded. Blocking further HTTP traffic."
        # Block HTTP requests from the source IP that exceeded the rate limit (example)
        $blockedIP = "192.168.1.101"  # Replace with the offending IP
        New-NetFirewallRule -DisplayName "Block IP $blockedIP due to excessive HTTP requests" -Direction Inbound -Protocol TCP -RemoteAddress $blockedIP -Action Block
    }
}

Write-Host "DDoS Mitigation script executed successfully!"
