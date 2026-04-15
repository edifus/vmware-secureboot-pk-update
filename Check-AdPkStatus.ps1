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
3. Event log readiness check:
   - Query the System event log for TPM-WMI Event ID 1801
   - Record whether the event is present and capture the latest timestamp

The script then classifies each device into one of these buckets:
- NeedsVmPkRemediationAndReady: PK is invalid, KEK 2023 is missing, and Event ID 1801 is present
- NeedsVmPkRemediationNotReady: PK is invalid, KEK 2023 is missing, and Event ID 1801 is not present
- NeedsMicrosoftKekUpdate: PK is valid but KEK 2023 is missing
- Healthy: PK is valid and KEK 2023 is present
- ReviewManually: PK is invalid but KEK 2023 is present
- CheckFailed: the validation could not be completed remotely

.PARAMETER SearchBase
The distinguished name of the Active Directory OU to search for Windows
computer objects.

.PARAMETER ExportCsv
When specified, exports CSV reports for all results and each result bucket.

.PARAMETER OutputDirectory
Directory where CSV reports are written when -ExportCsv is specified.

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
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = "."
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-SectionHeader {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $false)]
        [ConsoleColor]$Color = [ConsoleColor]::Cyan
    )

    Write-Host ""
    Write-Host $Title -ForegroundColor $Color
    Write-Host ("-" * $Title.Length) -ForegroundColor $Color
}

function Write-ResultTable {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Items
    )

    if ($Items.Count -eq 0) {
        Write-Host "None"
        return
    }

    $table = $Items |
        Select-Object ComputerName, Status, PkValid, HasRequiredKek2023, HasEvent1801, Detail |
        Format-Table -AutoSize |
        Out-String

    Write-Host $table.TrimEnd()
}

function Export-PkStatusReports {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$AllResults,

        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $resolvedOutputPath = Resolve-Path -Path $DirectoryPath -ErrorAction SilentlyContinue
    if (-not $resolvedOutputPath) {
        $null = New-Item -Path $DirectoryPath -ItemType Directory -Force
        $resolvedOutputPath = Resolve-Path -Path $DirectoryPath -ErrorAction Stop
    }

    $fileMap = [ordered]@{
        "All results"                     = Join-Path -Path $resolvedOutputPath -ChildPath "pk-status-all-$timestamp.csv"
        "Needs VM PK remediation ready"   = Join-Path -Path $resolvedOutputPath -ChildPath "pk-status-needs-vm-pk-remediation-ready-$timestamp.csv"
        "Needs VM PK remediation waiting" = Join-Path -Path $resolvedOutputPath -ChildPath "pk-status-needs-vm-pk-remediation-not-ready-$timestamp.csv"
        "Needs Microsoft KEK update"      = Join-Path -Path $resolvedOutputPath -ChildPath "pk-status-needs-microsoft-kek-update-$timestamp.csv"
        "Healthy"                         = Join-Path -Path $resolvedOutputPath -ChildPath "pk-status-healthy-$timestamp.csv"
        "Review manually"                 = Join-Path -Path $resolvedOutputPath -ChildPath "pk-status-review-manually-$timestamp.csv"
        "Check failed"                    = Join-Path -Path $resolvedOutputPath -ChildPath "pk-status-check-failed-$timestamp.csv"
    }

    $AllResults | Export-Csv -Path $fileMap["All results"] -NoTypeInformation
    $AllResults | Where-Object { $_.Status -eq "NeedsVmPkRemediationAndReady" } | Export-Csv -Path $fileMap["Needs VM PK remediation ready"] -NoTypeInformation
    $AllResults | Where-Object { $_.Status -eq "NeedsVmPkRemediationNotReady" } | Export-Csv -Path $fileMap["Needs VM PK remediation waiting"] -NoTypeInformation
    $AllResults | Where-Object { $_.Status -eq "NeedsMicrosoftKekUpdate" } | Export-Csv -Path $fileMap["Needs Microsoft KEK update"] -NoTypeInformation
    $AllResults | Where-Object { $_.Status -eq "Healthy" } | Export-Csv -Path $fileMap["Healthy"] -NoTypeInformation
    $AllResults | Where-Object { $_.Status -eq "ReviewManually" } | Export-Csv -Path $fileMap["Review manually"] -NoTypeInformation
    $AllResults | Where-Object { $_.Status -eq "CheckFailed" } | Export-Csv -Path $fileMap["Check failed"] -NoTypeInformation

    Write-SectionHeader -Title "CSV Export" -Color Green
    foreach ($entry in $fileMap.GetEnumerator()) {
        Write-Host ("{0,-27} {1}" -f ($entry.Key + ":"), $entry.Value)
    }
}

function Get-DeviceStatus {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$PkValid,

        [Parameter(Mandatory = $true)]
        [bool]$HasRequiredKek2023,

        [Parameter(Mandatory = $true)]
        [bool]$HasEvent1801
    )

    if (-not $PkValid -and -not $HasRequiredKek2023) {
        if ($HasEvent1801) {
            return [PSCustomObject]@{
                Status = "NeedsVmPkRemediationAndReady"
                Detail = "PK is invalid, Microsoft Corporation KEK 2K CA 2023 is missing, and Event ID 1801 shows the OS is ready for the manual VMware PK update."
            }
        }

        return [PSCustomObject]@{
            Status = "NeedsVmPkRemediationNotReady"
            Detail = "PK is invalid and Microsoft Corporation KEK 2K CA 2023 is missing, but Event ID 1801 was not found."
        }
    }

    if ($PkValid -and -not $HasRequiredKek2023) {
        return [PSCustomObject]@{
            Status = "NeedsMicrosoftKekUpdate"
            Detail = "PK is valid, but Microsoft Corporation KEK 2K CA 2023 is missing."
        }
    }

    if ($PkValid -and $HasRequiredKek2023) {
        return [PSCustomObject]@{
            Status = "Healthy"
            Detail = "PK is valid and Microsoft Corporation KEK 2K CA 2023 is present."
        }
    }

    return [PSCustomObject]@{
        Status = "ReviewManually"
        Detail = "PK appears invalid, but Microsoft Corporation KEK 2K CA 2023 is present. Review this combination manually."
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
    if (-not (Get-Command Get-SecureBootUEFI -ErrorAction SilentlyContinue)) {
        throw "Get-SecureBootUEFI is not available on this computer."
    }

    if (-not (Get-Command certutil.exe -ErrorAction SilentlyContinue)) {
        throw "certutil.exe is not available on this computer."
    }

    $pkDerPath = Join-Path -Path $env:TEMP -ChildPath ("PK-{0}.der" -f ([Guid]::NewGuid().ToString("N")))

    try {
        $pkObject = Get-SecureBootUEFI -Name PK -ErrorAction Stop
        $pkBytes = $pkObject.Bytes
        $pkByteLength = $null
        if ($null -ne $pkBytes) {
            $pkByteLength = $pkBytes.Length
        }
        $pkCertByteLength = $null
        $pkCertutilOutput = $null
        $pkValid = $false
        $pkDetail = $null

        if ($null -eq $pkBytes) {
            $pkDetail = "Get-SecureBootUEFI returned null PK bytes."
        }
        elseif ($pkBytes.Length -le 44) {
            $pkDetail = "PK byte array is too short to contain a certificate payload."
            $pkCertByteLength = 0
        }
        else {
            $pkCertBytes = [byte[]]$pkBytes[44..($pkBytes.Length - 1)]
            $pkCertByteLength = $pkCertBytes.Length
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
                $null = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pkCertBytes)
                $certificateParsed = $true
            }
            catch {
                $certificateParsed = $false
            }

            if ($hasBroadcomZeroPayload) {
                $pkDetail = "Broadcom invalid PK pattern detected: 00 payload / 45-byte PK structure."
            }
            elseif ($certutilExitCode -ne 0) {
                $pkDetail = "certutil -dump failed for extracted PK certificate."
            }
            elseif (-not $certificateParsed) {
                $pkDetail = "Extracted PK certificate could not be parsed as X.509."
            }
            else {
                $pkValid = $true
                $pkDetail = "PK certificate extracted and parsed successfully."
            }
        }

        $kekObject = Get-SecureBootUEFI -Name KEK -ErrorAction Stop
        $kekBytes = $kekObject.Bytes
        $kekByteLength = $null
        if ($null -ne $kekBytes) {
            $kekByteLength = $kekBytes.Length
        }
        $hasRequiredKek2023 = $false
        $kekDetail = $null

        if ($null -eq $kekBytes) {
            $kekDetail = "Get-SecureBootUEFI returned null KEK bytes."
        }
        else {
            $kekText = [System.Text.Encoding]::ASCII.GetString($kekBytes)
            $hasRequiredKek2023 = $kekText -match 'Microsoft Corporation KEK 2K CA 2023'

            if ($hasRequiredKek2023) {
                $kekDetail = "Microsoft Corporation KEK 2K CA 2023 is present."
            }
            else {
                $kekDetail = "Microsoft Corporation KEK 2K CA 2023 was not found."
            }
        }

        $event1801 = Get-WinEvent -FilterHashtable @{
            LogName      = "System"
            ProviderName = "TPM-WMI"
            Id           = 1801
        } -MaxEvents 1 -ErrorAction SilentlyContinue

        $hasEvent1801 = $null -ne $event1801
        $event1801TimeCreatedUtc = $null
        $event1801Message = $null
        $event1801Detail = $null

        if ($hasEvent1801) {
            $event1801TimeCreatedUtc = $event1801.TimeCreated.ToUniversalTime().ToString("o")
            $event1801Message = $event1801.Message
            $event1801Detail = "TPM-WMI Event ID 1801 is present."
        }
        else {
            $event1801Detail = "TPM-WMI Event ID 1801 was not found."
        }

        return [PSCustomObject]@{
            PkValid            = $pkValid
            PkDetail           = $pkDetail
            PkByteLength       = $pkByteLength
            PkCertByteLength   = $pkCertByteLength
            PkCertutilOutput   = $pkCertutilOutput
            HasRequiredKek2023 = $hasRequiredKek2023
            KekDetail          = $kekDetail
            KekByteLength      = $kekByteLength
            HasEvent1801       = $hasEvent1801
            Event1801Detail    = $event1801Detail
            Event1801TimeUtc   = $event1801TimeCreatedUtc
            Event1801Message   = $event1801Message
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
        $deviceStatus = Get-DeviceStatus -PkValid $remoteResult.PkValid -HasRequiredKek2023 $remoteResult.HasRequiredKek2023 -HasEvent1801 $remoteResult.HasEvent1801

        $results += [PSCustomObject]@{
            ComputerName       = $computer.Name
            DnsHostName        = $computer.DNSHostName
            OperatingSystem    = $computer.OperatingSystem
            Status             = $deviceStatus.Status
            Detail             = $deviceStatus.Detail
            ReadyForVmPkUpdate = ($deviceStatus.Status -eq "NeedsVmPkRemediationAndReady")
            PkValid            = $remoteResult.PkValid
            PkDetail           = $remoteResult.PkDetail
            PkByteLength       = $remoteResult.PkByteLength
            PkCertByteLength   = $remoteResult.PkCertByteLength
            PkCertutilOutput   = $remoteResult.PkCertutilOutput
            HasRequiredKek2023 = $remoteResult.HasRequiredKek2023
            KekDetail          = $remoteResult.KekDetail
            KekByteLength      = $remoteResult.KekByteLength
            HasEvent1801       = $remoteResult.HasEvent1801
            Event1801Detail    = $remoteResult.Event1801Detail
            Event1801TimeUtc   = $remoteResult.Event1801TimeUtc
            Event1801Message   = $remoteResult.Event1801Message
            CheckedAtUtc       = (Get-Date).ToUniversalTime().ToString("o")
        }
    }
    catch {
        $results += [PSCustomObject]@{
            ComputerName       = $computer.Name
            DnsHostName        = $computer.DNSHostName
            OperatingSystem    = $computer.OperatingSystem
            Status             = "CheckFailed"
            Detail             = $_.Exception.Message
            ReadyForVmPkUpdate = $false
            PkValid            = $false
            PkDetail           = $null
            PkByteLength       = $null
            PkCertByteLength   = $null
            PkCertutilOutput   = $null
            HasRequiredKek2023 = $false
            KekDetail          = $null
            KekByteLength      = $null
            HasEvent1801       = $false
            Event1801Detail    = $null
            Event1801TimeUtc   = $null
            Event1801Message   = $null
            CheckedAtUtc       = (Get-Date).ToUniversalTime().ToString("o")
        }
    }
}

$needsVmPkRemediationReadyDevices = @($results | Where-Object { $_.Status -eq "NeedsVmPkRemediationAndReady" })
$needsVmPkRemediationNotReadyDevices = @($results | Where-Object { $_.Status -eq "NeedsVmPkRemediationNotReady" })
$needsMicrosoftKekUpdateDevices = @($results | Where-Object { $_.Status -eq "NeedsMicrosoftKekUpdate" })
$healthyDevices = @($results | Where-Object { $_.Status -eq "Healthy" })
$reviewManuallyDevices = @($results | Where-Object { $_.Status -eq "ReviewManually" })
$checkFailedDevices = @($results | Where-Object { $_.Status -eq "CheckFailed" })
$event1801Devices = @($results | Where-Object { $_.HasEvent1801 })

Write-SectionHeader -Title "Summary" -Color Green
Write-Host "Windows computers checked:      $($results.Count)"
Write-Host "Needs VM PK remediation ready:  $($needsVmPkRemediationReadyDevices.Count)"
Write-Host "Needs VM PK remediation wait:   $($needsVmPkRemediationNotReadyDevices.Count)"
Write-Host "Needs Microsoft KEK update:     $($needsMicrosoftKekUpdateDevices.Count)"
Write-Host "Healthy:                        $($healthyDevices.Count)"
Write-Host "Review manually:                $($reviewManuallyDevices.Count)"
Write-Host "Check failed:                   $($checkFailedDevices.Count)"
Write-Host "Event ID 1801 present:          $($event1801Devices.Count)"

Write-SectionHeader -Title "Needs VM PK Remediation And Ready" -Color Red
Write-ResultTable -Items $needsVmPkRemediationReadyDevices

Write-SectionHeader -Title "Needs VM PK Remediation But Not Ready" -Color Yellow
Write-ResultTable -Items $needsVmPkRemediationNotReadyDevices

Write-SectionHeader -Title "Needs Microsoft KEK Update" -Color Yellow
Write-ResultTable -Items $needsMicrosoftKekUpdateDevices

Write-SectionHeader -Title "Healthy Devices" -Color Green
Write-ResultTable -Items $healthyDevices

Write-SectionHeader -Title "Review Manually" -Color Magenta
Write-ResultTable -Items $reviewManuallyDevices

Write-SectionHeader -Title "Validation Failures" -Color Yellow
Write-ResultTable -Items $checkFailedDevices

if ($ExportCsv) {
    Export-PkStatusReports -AllResults $results -DirectoryPath $OutputDirectory
}
