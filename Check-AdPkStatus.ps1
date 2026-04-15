<#
.SYNOPSIS
Validates Secure Boot PK and KEK status on Windows computers in an AD OU.

.DESCRIPTION
This script is independent from the vCenter and PK update scripts in this repo.
It queries Active Directory for Windows computer objects under a specified OU,
then uses PowerShell remoting to validate the Secure Boot state inside each
Windows guest.

The remote validation performs two checks:
1. Broadcom-style PK validation:
   - Get-SecureBootUEFI -Name PK
   - Extract the certificate payload from the PK bytes
   - Write a temporary PK.der file
   - Run certutil -dump against the extracted certificate
2. KEK validation:
   - Get-SecureBootUEFI -Name KEK
   - Convert the KEK byte array to ASCII text
   - Check for "Microsoft Corporation KEK 2K CA 2023"
3. Secure Boot servicing state validation:
   - Confirm whether Secure Boot is enabled
   - Read UEFICA2023Status and UEFICA2023Error from the Secure Boot servicing registry key
4. Event log readiness check:
   - Query the System event log for TPM-WMI Event ID 1801
   - Query the System event log for TPM-WMI Event ID 1808

The script then classifies each device into one of these buckets:
- SecureBootDisabledOrUnsupported: Secure Boot is disabled or unavailable on the system
- NeedsVmPkRemediationAndReady: PK is invalid, KEK 2023 is missing, and Event ID 1801 is present
- NeedsVmPkRemediationNotReady: PK is invalid, KEK 2023 is missing, and Event ID 1801 is not present
- UpdateInProgress: Windows Secure Boot servicing appears to be actively progressing
- NeedsMicrosoftKekUpdate: PK is valid but KEK 2023 is missing
- Healthy: PK is valid and KEK 2023 is present
- ReviewManually: PK is invalid but KEK 2023 is present
- CheckFailed: the validation could not be completed remotely

.PARAMETER SearchBase
The distinguished name of the Active Directory OU to search for Windows computer objects.

.PARAMETER ExportCsv
When specified, exports a single CSV report containing the simplified device
status results.

.EXAMPLE
pwsh -NoProfile -File ./Check-AdPkStatus.ps1 -SearchBase "OU=Servers,DC=example,DC=com"

Checks all Windows computers in the specified OU using the current user context.

.NOTES
Requirements:
- ActiveDirectory module on the machine running this script
- PowerShell remoting enabled to the target computers
- Administrative rights on the target computers to run Get-SecureBootUEFI
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SearchBase,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-ResultTable {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [ConsoleColor]$Color = [ConsoleColor]::Cyan,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Items
    )

    if ($Title) {
        Write-Host ""
        Write-Host $Title -ForegroundColor $Color
        Write-Host ("-" * $Title.Length) -ForegroundColor $Color
    }

    if ($Items.Count -eq 0) {
        Write-Host "None"
        return
    }

    $table = $Items |
        Select-Object ComputerName, DnsHostName, Status, ReadyForVmPkUpdate, SecureBootEnabled, ServicingComplete, UefiCa2023Status, Detail |
        Format-Table -AutoSize |
        Out-String

    Write-Host $table.TrimEnd()
}

function Export-PkStatusReport {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$AllResults
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportPath = Join-Path -Path (Get-Location) -ChildPath "pk-status-$timestamp.csv"

    $AllResults | Export-Csv -Path $reportPath -NoTypeInformation

    Write-Host ""
    Write-Host "CSV Export" -ForegroundColor Green
    Write-Host ("-" * "CSV Export".Length) -ForegroundColor Green
    Write-Host "Report: $reportPath"
}

function Get-DeviceStatus {
    param(
        [Parameter(Mandatory = $true)]
        $SecureBootEnabled,

        [Parameter(Mandatory = $true)]
        [bool]$PkValid,

        [Parameter(Mandatory = $true)]
        [bool]$HasRequiredKek2023,

        [Parameter(Mandatory = $true)]
        [bool]$HasEvent1801,

        [Parameter(Mandatory = $true)]
        [bool]$HasEvent1808,

        [Parameter(Mandatory = $false)]
        [string]$UefiCa2023Status,

        [Parameter(Mandatory = $false)]
        [string]$UefiCa2023Error
    )

    $hasSecureBootEvidence = (
        $PkValid -or
        $HasRequiredKek2023 -or
        $HasEvent1801 -or
        $HasEvent1808 -or
        -not [string]::IsNullOrWhiteSpace($UefiCa2023Status)
    )

    if ($SecureBootEnabled -eq $false) {
        return [PSCustomObject]@{
            Status             = "SecureBootDisabledOrUnsupported"
            Detail             = "Secure Boot is disabled or could not be confirmed on this system."
            ServicingComplete  = $false
        }
    }

    if ($null -eq $SecureBootEnabled -and -not $hasSecureBootEvidence) {
        return [PSCustomObject]@{
            Status             = "SecureBootDisabledOrUnsupported"
            Detail             = "Secure Boot could not be confirmed and no Secure Boot servicing evidence was found."
            ServicingComplete  = $false
        }
    }

    if ($null -eq $SecureBootEnabled -and $HasEvent1801 -and -not $HasEvent1808) {
        $detail = "Secure Boot could not be confirmed via cmdlet or registry, but Event ID 1801 indicates Windows attempted the update and is ready for the manual VMware PK update."
        if ($UefiCa2023Error) {
            $detail = "$detail UEFICA2023Error: $UefiCa2023Error"
        }

        return [PSCustomObject]@{
            Status            = "NeedsVmPkRemediationAndReady"
            Detail            = $detail
            ServicingComplete = $false
        }
    }

    if (-not $PkValid -and -not $HasRequiredKek2023) {
        if ($HasEvent1801) {
            $detail = "PK is invalid, Microsoft Corporation KEK 2K CA 2023 is missing, and Event ID 1801 shows the OS is ready for the manual VMware PK update."
            if ($UefiCa2023Error) {
                $detail = "$detail UEFICA2023Error: $UefiCa2023Error"
            }

            return [PSCustomObject]@{
                Status            = "NeedsVmPkRemediationAndReady"
                Detail            = $detail
                ServicingComplete = $false
            }
        }

        $detail = "PK is invalid and Microsoft Corporation KEK 2K CA 2023 is missing, but Event ID 1801 was not found."
        if ($UefiCa2023Error) {
            $detail = "$detail UEFICA2023Error: $UefiCa2023Error"
        }

        return [PSCustomObject]@{
            Status            = "NeedsVmPkRemediationNotReady"
            Detail            = $detail
            ServicingComplete = $false
        }
    }

    if ($PkValid -and -not $HasRequiredKek2023) {
        if ($UefiCa2023Status -eq "InProgress") {
            return [PSCustomObject]@{
                Status            = "UpdateInProgress"
                Detail            = "PK is valid, KEK 2023 is still missing, and Windows Secure Boot servicing is in progress."
                ServicingComplete = $false
            }
        }

        if ($UefiCa2023Status -eq "Updated" -or $HasEvent1808) {
            $detail = "Windows reports Secure Boot servicing completed, but the KEK 2023 certificate is still missing."
            if ($UefiCa2023Error) {
                $detail = "$detail UEFICA2023Error: $UefiCa2023Error"
            }

            return [PSCustomObject]@{
                Status            = "ReviewManually"
                Detail            = $detail
                ServicingComplete = $false
            }
        }

        $detail = "PK is valid, but Microsoft Corporation KEK 2K CA 2023 is missing."
        if ($UefiCa2023Error) {
            $detail = "$detail UEFICA2023Error: $UefiCa2023Error"
        }

        return [PSCustomObject]@{
            Status            = "NeedsMicrosoftKekUpdate"
            Detail            = $detail
            ServicingComplete = $false
        }
    }

    if ($PkValid -and $HasRequiredKek2023) {
        $servicingComplete = ($UefiCa2023Status -eq "Updated" -or $HasEvent1808)

        return [PSCustomObject]@{
            Status            = "Healthy"
            Detail            = "Secure Boot certificates appear healthy."
            ServicingComplete = $servicingComplete
        }
    }

    $detail = "PK appears invalid, but Microsoft Corporation KEK 2K CA 2023 is present. Review this combination manually."
    if ($UefiCa2023Error) {
        $detail = "$detail UEFICA2023Error: $UefiCa2023Error"
    }

    return [PSCustomObject]@{
        Status            = "ReviewManually"
        Detail            = $detail
        ServicingComplete = $false
    }
}

Import-Module ActiveDirectory -ErrorAction Stop

$windowsComputers = @(
    Get-ADComputer -SearchBase $SearchBase -Filter 'OperatingSystem -like "*Windows*"' -Properties DNSHostName, OperatingSystem |
    Sort-Object Name
)

if ($windowsComputers.Count -eq 0) {
    throw "No Windows computer objects were found under OU '$SearchBase'."
}

$validationScript = {
    $pkDerPath = Join-Path -Path $env:TEMP -ChildPath ("PK-{0}.der" -f ([Guid]::NewGuid().ToString("N")))

    try {
        $getSecureBootUefiAvailable = $null -ne (Get-Command Get-SecureBootUEFI -ErrorAction SilentlyContinue)
        $certutilAvailable = $null -ne (Get-Command certutil.exe -ErrorAction SilentlyContinue)

        $secureBootEnabled = $null
        try {
            $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
        }
        catch { }

        if ($null -eq $secureBootEnabled) {
            $secureBootState = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
            if ($null -ne $secureBootState -and $null -ne $secureBootState.UEFISecureBootEnabled) {
                $secureBootEnabled = [bool]$secureBootState.UEFISecureBootEnabled
            }
        }

        $pkValid = $false

        if ($getSecureBootUefiAvailable -and $certutilAvailable -and $secureBootEnabled) {
            $pkObject = $null
            try {
                $pkObject = Get-SecureBootUEFI -Name PK -ErrorAction Stop
            }
            catch { }

            $pkBytes = $null
            if ($null -ne $pkObject) {
                $pkBytes = $pkObject.Bytes
            }

            if ($null -ne $pkBytes -and $pkBytes.Length -gt 44) {
                $pkCertBytes = [byte[]]$pkBytes[44..($pkBytes.Length - 1)]
                [System.IO.File]::WriteAllBytes($pkDerPath, $pkCertBytes)

                $certutilOutputLines = @(
                    & certutil.exe -dump $pkDerPath 2>&1 | ForEach-Object { $_.ToString() }
                )
                $certutilExitCode = $LASTEXITCODE
                $pkCertutilOutput = ($certutilOutputLines -join [Environment]::NewLine)

                $hasBroadcomZeroPayload = (
                    ($pkBytes.Length -eq 45) -or
                    ($pkCertBytes.Length -eq 1 -and $pkCertBytes[0] -eq 0) -or
                    ($pkCertutilOutput -match '(?m)^\s*00\s+\.\s*$')
                )

                $certificateParsed = $false
                try {
                    $certObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $pkCertBytes)
                    if ($null -ne $certObject) {
                        $certificateParsed = $true
                    }
                }
                catch {
                    $certificateParsed = $false
                }

                if (-not $hasBroadcomZeroPayload -and $certutilExitCode -eq 0 -and $certificateParsed) {
                    $pkValid = $true
                }
            }
        }

        $hasRequiredKek2023 = $false

        if ($getSecureBootUefiAvailable -and $secureBootEnabled) {
            $kekObject = $null
            try {
                $kekObject = Get-SecureBootUEFI -Name KEK -ErrorAction Stop
            }
            catch { }

            $kekBytes = $null
            if ($null -ne $kekObject) {
                $kekBytes = $kekObject.Bytes
            }

            if ($null -ne $kekBytes) {
                $kekText = [System.Text.Encoding]::ASCII.GetString($kekBytes)
                $hasRequiredKek2023 = $kekText -match 'Microsoft Corporation KEK 2K CA 2023'
            }
        }

        $event1801 = Get-WinEvent -FilterHashtable @{
            LogName = "System"
            Id      = 1801
        } -MaxEvents 1 -ErrorAction SilentlyContinue
        $hasEvent1801 = $null -ne $event1801

        $event1808 = Get-WinEvent -FilterHashtable @{
            LogName = "System"
            Id      = 1808
        } -MaxEvents 1 -ErrorAction SilentlyContinue
        $hasEvent1808 = $null -ne $event1808

        $uefiCa2023Status = $null
        $uefiCa2023StatusItem = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "UEFICA2023Status" -ErrorAction SilentlyContinue
        if ($null -ne $uefiCa2023StatusItem) {
            $uefiCa2023Status = [string]$uefiCa2023StatusItem.UEFICA2023Status
        }

        $uefiCa2023Error = $null
        $uefiCa2023ErrorItem = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "UEFICA2023Error" -ErrorAction SilentlyContinue
        if ($null -ne $uefiCa2023ErrorItem) {
            $uefiCa2023Error = [string]$uefiCa2023ErrorItem.UEFICA2023Error
        }

        return [PSCustomObject]@{
            SecureBootEnabled  = $secureBootEnabled
            PkValid            = $pkValid
            HasRequiredKek2023 = $hasRequiredKek2023
            HasEvent1801       = $hasEvent1801
            HasEvent1808       = $hasEvent1808
            UefiCa2023Status   = $uefiCa2023Status
            UefiCa2023Error    = $uefiCa2023Error
        }
    }
    finally {
        Remove-Item -Path $pkDerPath -Force -ErrorAction SilentlyContinue
    }
}

$results = @()

foreach ($computer in $windowsComputers) {
    $targetComputerName = $computer.DNSHostName
    if ([string]::IsNullOrWhiteSpace($targetComputerName)) {
        $targetComputerName = $computer.Name
    }

    Write-Host "Checking $targetComputerName..." -ForegroundColor Yellow

    try {
        $invokeCommandParameters = @{
            ComputerName = $targetComputerName
            ScriptBlock  = $validationScript
            ErrorAction  = "Stop"
        }

        $remoteResult = Invoke-Command @invokeCommandParameters
        $deviceStatus = Get-DeviceStatus `
            -SecureBootEnabled $remoteResult.SecureBootEnabled `
            -PkValid $remoteResult.PkValid `
            -HasRequiredKek2023 $remoteResult.HasRequiredKek2023 `
            -HasEvent1801 $remoteResult.HasEvent1801 `
            -HasEvent1808 $remoteResult.HasEvent1808 `
            -UefiCa2023Status $remoteResult.UefiCa2023Status `
            -UefiCa2023Error $remoteResult.UefiCa2023Error

        $results += [PSCustomObject]@{
            ComputerName       = $computer.Name
            DnsHostName        = $computer.DNSHostName
            Status             = $deviceStatus.Status
            Detail             = $deviceStatus.Detail
            ReadyForVmPkUpdate = ($deviceStatus.Status -eq "NeedsVmPkRemediationAndReady")
            SecureBootEnabled  = $remoteResult.SecureBootEnabled
            ServicingComplete  = $deviceStatus.ServicingComplete
            UefiCa2023Status   = $remoteResult.UefiCa2023Status
        }
    }
    catch {
        $results += [PSCustomObject]@{
            ComputerName       = $computer.Name
            DnsHostName        = $computer.DNSHostName
            Status             = "CheckFailed"
            Detail             = $_.Exception.Message
            ReadyForVmPkUpdate = $false
            SecureBootEnabled  = $null
            ServicingComplete  = $false
            UefiCa2023Status   = $null
        }
    }
}

$secureBootDisabledDevices = @($results | Where-Object { $_.Status -eq "SecureBootDisabledOrUnsupported" })
$needsVmPkRemediationReadyDevices = @($results | Where-Object { $_.Status -eq "NeedsVmPkRemediationAndReady" })
$needsVmPkRemediationNotReadyDevices = @($results | Where-Object { $_.Status -eq "NeedsVmPkRemediationNotReady" })
$updateInProgressDevices = @($results | Where-Object { $_.Status -eq "UpdateInProgress" })
$needsMicrosoftKekUpdateDevices = @($results | Where-Object { $_.Status -eq "NeedsMicrosoftKekUpdate" })
$healthyDevices = @($results | Where-Object { $_.Status -eq "Healthy" })
$reviewManuallyDevices = @($results | Where-Object { $_.Status -eq "ReviewManually" })
$checkFailedDevices = @($results | Where-Object { $_.Status -eq "CheckFailed" })
$readyForVmPkUpdateDevices = @($results | Where-Object { $_.ReadyForVmPkUpdate })

Write-Host ""
Write-Host "Summary" -ForegroundColor Green
Write-Host ("-" * "Summary".Length) -ForegroundColor Green
Write-Host "Windows computers checked:      $($results.Count)"
Write-Host "Secure Boot off/unknown:        $($secureBootDisabledDevices.Count)"
Write-Host "Needs VM PK remediation ready:  $($needsVmPkRemediationReadyDevices.Count)"
Write-Host "Needs VM PK remediation wait:   $($needsVmPkRemediationNotReadyDevices.Count)"
Write-Host "Update in progress:             $($updateInProgressDevices.Count)"
Write-Host "Needs Microsoft KEK update:     $($needsMicrosoftKekUpdateDevices.Count)"
Write-Host "Healthy:                        $($healthyDevices.Count)"
Write-Host "Review manually:                $($reviewManuallyDevices.Count)"
Write-Host "Check failed:                   $($checkFailedDevices.Count)"
Write-Host "Ready for VM PK update:         $($readyForVmPkUpdateDevices.Count)"

Write-ResultTable -Title "Secure Boot Disabled Or Unsupported" -Color Yellow -Items $secureBootDisabledDevices
Write-ResultTable -Title "Needs VM PK Remediation And Ready" -Color Red -Items $needsVmPkRemediationReadyDevices
Write-ResultTable -Title "Needs VM PK Remediation But Not Ready" -Color Yellow -Items $needsVmPkRemediationNotReadyDevices
Write-ResultTable -Title "Update In Progress" -Color Cyan -Items $updateInProgressDevices
Write-ResultTable -Title "Needs Microsoft KEK Update" -Color Yellow -Items $needsMicrosoftKekUpdateDevices
Write-ResultTable -Title "Healthy Devices" -Color Green -Items $healthyDevices
Write-ResultTable -Title "Review Manually" -Color Magenta -Items $reviewManuallyDevices
Write-ResultTable -Title "Validation Failures" -Color Yellow -Items $checkFailedDevices

if ($ExportCsv) {
    Export-PkStatusReport -AllResults $results
}
