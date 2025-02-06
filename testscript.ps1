Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Screen
{
    [DllImport("user32.dll")]
    public static extern bool SystemParametersInfo(uint action, uint param, IntPtr vparam, uint init);
}
"@

# Function to rotate screen
function Rotate-Screen {
    param (
        [int]$angle
    )
    $angles = @{
        0   = 0x00000000
        90  = 0x00000001
        180 = 0x00000002
        270 = 0x00000003
    }
    $value = $angles[$angle]
    [Screen]::SystemParametersInfo(0x005B, $value, [IntPtr]::Zero, 0)
}


$stopTime = (Get-Date).AddMinutes(5) # Run for 5 minutes
while ((Get-Date) -lt $stopTime) {
    Start-Sleep -Seconds (Get-Random -Minimum 10 -Maximum 30) # Wait randomly between 10-30 seconds
    Rotate-Screen -angle 180      Start-Sleep -Seconds 3
    Rotate-Screen -angle 0   }