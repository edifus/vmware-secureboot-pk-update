# Connect to your vCenter if not already connected
# Connect-VIServer -Server "your-vcenter-fqdn"

$AffectedVMs = Get-VM | Get-View -Property Name, Config.Firmware, Config.BootOptions, Runtime.Host, Summary.Runtime.PowerState | Where-Object {
    # Criterion 1: VM is using UEFI firmware
    $_.Config.Firmware -eq "efi" -and 
    # Criterion 2: Secure Boot is enabled
    $_.Config.BootOptions.EfiSecureBootEnabled -eq $true
}

$Report = foreach ($vmView in $AffectedVMs) {
    $vm = Get-VM -Id $vmView.MoRef
    $hasPkFixedTag = @(Get-TagAssignment -Entity $vm -ErrorAction SilentlyContinue | Where-Object {
        $_.Tag.Name -eq "PK-Fixed"
    }).Count -gt 0
    
    [PSCustomObject]@{
        VMName      = $vmView.Name
        PowerState  = $vmView.Summary.Runtime.PowerState
        Firmware    = $vmView.Config.Firmware
        SecureBoot  = $vmView.Config.BootOptions.EfiSecureBootEnabled
        FixedStatus = if ($hasPkFixedTag) { "Fixed" } else { "Not Fixed" }
    }
}

$AffectedVmCount = @($Report).Count

# Output the results to the console
Write-Host "Affected VM count: $AffectedVmCount"

if ($AffectedVmCount -gt 0) {
    $header = "{0,-30} {1,-12} {2,-10} {3,-12} {4,-10}" -f `
        "VMName", "PowerState", "Firmware", "SecureBoot", "Status"
    Write-Host $header
    Write-Host ("-" * $header.Length)

    foreach ($vm in $Report) {
        $line = "{0,-30} {1,-12} {2,-10} {3,-12} {4,-10}" -f `
            $vm.VMName, $vm.PowerState, $vm.Firmware, $vm.SecureBoot, $vm.FixedStatus

        if ($vm.FixedStatus -eq "Fixed") {
            Write-Host $line -ForegroundColor Green
        } else {
            Write-Host $line -ForegroundColor Red
        }
    }
} else {
    Write-Host "No affected VMs found."
}

# Optional: Export to CSV
# $Report | Export-Csv -Path "Affected_SecureBoot_VMs.csv" -NoTypeInformation
