<#
.SYNOPSIS
Reports Secure Boot-enabled UEFI VMs and their PK update status.

.DESCRIPTION
Lists virtual machines that use UEFI firmware with Secure Boot enabled and shows
whether each VM has the PK-Fixed tag assigned. If a VCSA hostname is provided,
the script connects to that vCenter Server before running the report.

.PARAMETER VCServer
The VCSA or vCenter Server hostname to connect to before collecting the report.

.PARAMETER ExportCsv
When specified, exports the report to ./Affected_SecureBoot_VMs.csv.

.EXAMPLE
pwsh -NoProfile -File ./Check-PkStatus.ps1 -VCServer vcsa.example.local

Connects to the specified VCSA and writes the report to the console.

.EXAMPLE
pwsh -NoProfile -File ./Check-PkStatus.ps1 -VCServer vcsa.example.local -ExportCsv

Connects to the specified VCSA, writes the report to the console, and saves the
results to ./Affected_SecureBoot_VMs.csv.

.NOTES
Requires VMware PowerCLI and permissions to read VM inventory and tag assignments.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$VCServer,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv
)

if ($VCServer) {
    Connect-VIServer -Server $VCServer | Out-Null
}

$AffectedVMs = Get-VM `
  | Get-View -Property Name, Config.Firmware, Config.BootOptions, Runtime.Host, Summary.Runtime.PowerState `
  | Sort-Object -Property Name `
  | Where-Object {
    $_.Config.Firmware -eq "efi" -and
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

if ($ExportCsv) {
    $Report | Export-Csv -Path "./Affected_SecureBoot_VMs.csv" -NoTypeInformation
}
