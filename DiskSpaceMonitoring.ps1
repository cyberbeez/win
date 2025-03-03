# Set thresholds
$warningThreshold50 = 50
$warningThreshold80 = 80
$criticalThreshold90 = 90


# Get disk information
Get-WmiObject -Class Win32_LogicalDisk | ForEach-Object {
    $drive = $_.DeviceID
    $freeSpaceGB = [Math]::Round($_.FreeSpace / 1GB, 2)
    $totalSpaceGB = [Math]::Round($_.Size / 1GB, 2)
    $usedSpaceGB = $totalSpaceGB - $freeSpaceGB
    $percentFree = [Math]::Round(($freeSpaceGB / $totalSpaceGB) * 100, 2)
    $percentUsed = 100 - $percentFree

    # Check thresholds and send alerts
    if ($percentUsed -ge $criticalThreshold90) {
        $subject = "CRITICAL: Disk space alert for $drive"
        $body = "Disk $drive is at $percentUsed% usage. Available space: $freeSpaceGB GB. Please take action immediately."
        Send-MailMessage -SmtpServer $smtpServer -From $fromAddress -To $toAddress -Subject $subject -Body $body
    } elseif ($percentUsed -ge $warningThreshold80) {
        $subject = "WARNING: Disk space alert for $drive"
        $body = "Disk $drive is at $percentUsed% usage. Available space: $freeSpaceGB GB."
        Send-MailMessage -SmtpServer $smtpServer -From $fromAddress -To $toAddress -Subject $subject -Body $body
    } elseif ($percentUsed -ge $warningThreshold50) {
         $subject = "WARNING: Disk space alert for $drive"
        $body = "Disk $drive is at $percentUsed% usage. Available space: $freeSpaceGB GB."
        Send-MailMessage -SmtpServer $smtpServer -From $fromAddress -To $toAddress -Subject $subject -Body $body
    }
}
pause
