<#
.SYNOPSIS
Automates Secure Boot PK update workflow for a vSphere VM.

.DESCRIPTION
This script performs an end-to-end Platform Key (PK) enrollment workflow for
VMware virtual machines that require Secure Boot remediation.

Main workflow:
1. Connect to vCenter Server or reuse an existing PowerCLI session.
2. Resolve a single VM target or a batch of targets from CSV.
3. Verify the VM does not already have snapshots.
4. Power off the VM if needed.
5. Copy the PK VMDK into the VM's datastore folder when necessary.
6. Attach the PK disk and create a pre-update snapshot.
7. Enable the required EFI settings for PK enrollment.
8. Power on the VM and send the HID key sequence through firmware menus.
9. Power off the VM, clear temporary EFI settings, detach the PK disk when
   possible, and power the VM back on.
10. Apply the PK-Fixed vCenter tag and append a JSONL log entry.

Use -CleanupArtifactsOnly to remove PK update artifacts after validation. In
cleanup mode, the script removes matching snapshots, detaches the PK disk, and
deletes the staged PK VMDK from the VM folder without performing the enrollment
sequence.

Provide either -VMName for a single VM or -CsvPath for batch mode.

.PARAMETER VMName
The name of a single target VM to process.

.PARAMETER CsvPath
Path to a CSV file used for batch mode. The CSV must include a VMName column.
Optional columns are PkDiskPath and SnapshotName.

.PARAMETER VCServer
The vCenter Server or VCSA hostname. If omitted, the script tries to reuse an
existing VIServer connection in the current PowerShell session or uses the
VC_SERVER environment variable when set.

.PARAMETER Username
Username used when creating a new vCenter connection. If omitted, the script may
reuse an existing connection, rely on saved PowerCLI credentials, or use the
VC_USER environment variable.

.PARAMETER Password
SecureString password paired with -Username for a new vCenter connection. If
omitted, the script may rely on saved PowerCLI credentials or the VC_PASS
environment variable.

.PARAMETER PkDiskPath
Datastore path to the PK VMDK source disk in the format
[datastore] folder/file.vmdk. Defaults to [iso] secureboot.vmdk and can also be
provided through PK_VMDK_PATH.

.PARAMETER SnapshotName
Snapshot name to use for single-VM mode. In batch mode, each row can override
this value with a SnapshotName column; otherwise a per-VM generated name is used.

.PARAMETER LogPath
Path to the append-only JSONL log file written during execution.

.PARAMETER InitialDelaySec
Delay, in seconds, before the HID enrollment sequence begins after power-on.

.PARAMETER KeyHoldMs
Duration, in milliseconds, to hold each HID key press.

.PARAMETER InterKeyMs
Delay, in milliseconds, between repeated HID key presses.

.PARAMETER StepWaitSec
Default wait time, in seconds, between major firmware navigation steps.

.PARAMETER CleanupArtifactsOnly
Runs cleanup only. This removes snapshots, detaches the PK disk, and deletes the
staged PK VMDK artifacts without re-running the PK enrollment workflow.

.EXAMPLE
pwsh -NoProfile -File ./Invoke-PkUpdate.ps1 -VCServer "vcenter.example.local" -VMName "target-vm"

Runs the PK update workflow for a single VM.

.EXAMPLE
pwsh -NoProfile -File ./Invoke-PkUpdate.ps1 -VCServer "vcenter.example.local" -CsvPath "./vms.csv"

Runs the PK update workflow for every VM listed in the CSV file.

.EXAMPLE
pwsh -NoProfile -File ./Invoke-PkUpdate.ps1 -VCServer "vcenter.example.local" -VMName "target-vm" -CleanupArtifactsOnly

Removes PK update artifacts for a single VM after validation.

.EXAMPLE
pwsh -NoProfile -File ./Invoke-PkUpdate.ps1 -VMName "target-vm"

Runs against a VM using an already-connected PowerCLI session.

.NOTES
Requires VMware PowerCLI, vCenter permissions for VM reconfiguration and
snapshots, and access to the PK VMDK datastore path. The script creates or reuses
the PK-Fixed tag in the PK Update Status category to mark successful completion.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$VMName,

    [Parameter(Mandatory = $false)]
    [Alias("csv")]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$VCServer,

    [Parameter(Mandatory = $false)]
    [string]$Username,

    [Parameter(Mandatory = $false)]
    [SecureString]$Password,

    [Parameter(Mandatory = $false)]
    [string]$PkDiskPath = "[iso] secureboot.vmdk",

    [Parameter(Mandatory = $false)]
    [string]$SnapshotName = ("pre-pk-update-" + (Get-Date -Format "yyyyMMdd-HHmmss")),

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "./pk-update-log.jsonl",

    [Parameter(Mandatory = $false)]
    [double]$InitialDelaySec = 0,

    [Parameter(Mandatory = $false)]
    [double]$KeyHoldMs = 100,

    [Parameter(Mandatory = $false)]
    [double]$InterKeyMs = 200,

    [Parameter(Mandatory = $false)]
    [double]$StepWaitSec = 0.8
,
    [Parameter(Mandatory = $false)]
    [switch]$CleanupArtifactsOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($env:VC_SERVER -and -not $PSBoundParameters.ContainsKey("VCServer")) {
    $VCServer = $env:VC_SERVER
}

if ($env:VC_USER -and -not $PSBoundParameters.ContainsKey("Username")) {
    $Username = $env:VC_USER
}

if ($env:VC_PASS -and -not $PSBoundParameters.ContainsKey("Password")) {
    $Password = ConvertTo-SecureString $env:VC_PASS -AsPlainText -Force
}

if ($env:PK_VMDK_PATH -and -not $PSBoundParameters.ContainsKey("PkDiskPath")) {
    $PkDiskPath = $env:PK_VMDK_PATH
}

if (Get-Command Set-PowerCLIConfiguration -ErrorAction SilentlyContinue) {
    Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

$runId = [Guid]::NewGuid().ToString()
$snapshotCreatedAtUtc = $null
$status = "started"
$failureMessage = $null
$sourcePkDiskPath = $PkDiskPath
$attachPkDiskPath = $PkDiskPath
$pkFixedTagName = "PK-Fixed"
$pkFixedTagCategoryName = "PK Update Status"
$openedVIServerConnection = $false
$activeVIServerConnection = $null
$currentVMName = $VMName
$batchResults = @()

function Write-Status {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ConsoleColor]$Color = [ConsoleColor]::Green
    )

    Write-Host $Message -ForegroundColor $Color
}

function Write-StatusWarning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "WARNING: $Message" -ForegroundColor Yellow
}

function Write-StatusError {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "ERROR: $Message" -ForegroundColor Red
}

function Write-RunLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage,

        [Parameter(Mandatory = $false)]
        [string]$SnapshotCreatedUtc,

        [Parameter(Mandatory = $false)]
        [string]$SnapshotNameValue
    )

    $entry = [ordered]@{
        runId                = $runId
        timestampUtc         = (Get-Date).ToUniversalTime().ToString("o")
        vcServer             = $VCServer
        vmName               = $currentVMName
        sourcePkDiskPath     = $sourcePkDiskPath
        attachPkDiskPath     = $attachPkDiskPath
        snapshotName         = $SnapshotNameValue
        snapshotCreatedAtUtc = $SnapshotCreatedUtc
        status               = $Status
        error                = $ErrorMessage
    }

    $jsonLine = $entry | ConvertTo-Json -Compress
    Add-Content -Path $LogPath -Value $jsonLine
}

function New-GeneratedSnapshotName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetVMName
    )

    return "pre-pk-update-$TargetVMName-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

function Get-TargetVmSpecs {
    param(
        [Parameter(Mandatory = $false)]
        [string]$SingleVMName,

        [Parameter(Mandatory = $false)]
        [string]$CsvFilePath
    )

    if ($SingleVMName -and $CsvFilePath) {
        throw "Specify either -VMName or -CsvPath, not both."
    }

    if (-not $SingleVMName -and -not $CsvFilePath) {
        throw "Specify -VMName for a single VM or -CsvPath for batch mode."
    }

    if ($SingleVMName) {
        return @([pscustomobject]@{
            VMName       = $SingleVMName
            PkDiskPath   = $PkDiskPath
            SnapshotName = $SnapshotName
        })
    }

    $resolvedCsvPath = Resolve-Path -Path $CsvFilePath -ErrorAction Stop
    $rows = @(Import-Csv -Path $resolvedCsvPath)
    if ($rows.Count -eq 0) {
        throw "CSV file '$resolvedCsvPath' does not contain any rows."
    }

    $targets = @()
    foreach ($row in $rows) {
        $rowVmName = $row.PSObject.Properties["VMName"]
        if (-not $rowVmName -or [string]::IsNullOrWhiteSpace([string]$rowVmName.Value)) {
            throw "CSV file '$resolvedCsvPath' must contain a non-empty 'VMName' column for every row."
        }

        $rowPkDiskPath = $PkDiskPath
        $rowSnapshotName = New-GeneratedSnapshotName -TargetVMName ([string]$rowVmName.Value)

        $pkDiskProperty = $row.PSObject.Properties["PkDiskPath"]
        if ($pkDiskProperty -and -not [string]::IsNullOrWhiteSpace([string]$pkDiskProperty.Value)) {
            $rowPkDiskPath = [string]$pkDiskProperty.Value
        }

        $snapshotProperty = $row.PSObject.Properties["SnapshotName"]
        if ($snapshotProperty -and -not [string]::IsNullOrWhiteSpace([string]$snapshotProperty.Value)) {
            $rowSnapshotName = [string]$snapshotProperty.Value
        }

        $targets += [pscustomobject]@{
            VMName       = [string]$rowVmName.Value
            PkDiskPath   = $rowPkDiskPath
            SnapshotName = $rowSnapshotName
        }
    }

    return $targets
}

function Get-LoginCredential {
    param(
        [string]$User,
        [SecureString]$Pass
    )

    if ($User -and $Pass) {
        return New-Object System.Management.Automation.PSCredential($User, $Pass)
    }

    if ($User -and -not $Pass) {
        return $null
    }

    if (-not $User -and $Pass) {
        throw "Password was provided without Username. Provide both, or neither."
    }

    return $null
}

function Get-ConnectedVIServer {
    param(
        [Parameter(Mandatory = $false)]
        [string]$ServerName
    )

    $connectedServers = @()

    $defaultVIServerVar = Get-Variable -Name DefaultVIServer -Scope Global -ErrorAction SilentlyContinue
    if ($defaultVIServerVar -and $null -ne $defaultVIServerVar.Value) {
        $connectedServers += @($defaultVIServerVar.Value)
    }

    $defaultVIServersVar = Get-Variable -Name DefaultVIServers -Scope Global -ErrorAction SilentlyContinue
    if ($defaultVIServersVar -and $null -ne $defaultVIServersVar.Value) {
        $connectedServers += @($defaultVIServersVar.Value)
    }

    $connectedServers = @(
        $connectedServers |
        Where-Object {
            $null -ne $_ -and
            $_ -isnot [string] -and
            $_.PSObject.Properties["Name"] -and
            $_.PSObject.Properties["IsConnected"] -and
            $_.IsConnected
        } |
        Sort-Object { Get-VIServerName -Server $_ } -Unique
    )

    if ($connectedServers.Count -eq 0) {
        return @()
    }

    if ($ServerName) {
        $matchedServer = $connectedServers | Where-Object { (Get-VIServerName -Server $_) -eq $ServerName } | Select-Object -First 1
        if ($null -ne $matchedServer) {
            return $matchedServer
        }

        return @()
    }

    if ($connectedServers.Count -eq 1) {
        return $connectedServers[0]
    }

    return @()
}

function Get-VIServerName {
    param(
        [Parameter(Mandatory = $true)]
        $Server
    )

    if ($null -eq $Server) {
        return $null
    }

    $nameProperty = $Server.PSObject.Properties["Name"]
    if ($nameProperty) {
        return [string]$nameProperty.Value
    }

    return [string]$Server
}

function Get-TaskErrorMessage {
    param(
        [Parameter(Mandatory = $false)]
        $TaskError
    )

    if ($null -eq $TaskError) {
        return "Unknown task error."
    }

    if ($TaskError -is [System.Array] -or $TaskError -is [System.Collections.IEnumerable] -and $TaskError -isnot [string]) {
        $messages = @()
        foreach ($item in $TaskError) {
            $itemMessage = Get-TaskErrorMessage -TaskError $item
            if ($itemMessage) {
                $messages += $itemMessage
            }
        }

        $messages = @($messages | Where-Object { $_ } | Select-Object -Unique)
        if ($messages.Count -gt 0) {
            return ($messages -join "; ")
        }
    }

    foreach ($propertyName in @("LocalizedMessage", "Message")) {
        $property = $TaskError.PSObject.Properties[$propertyName]
        if ($property -and $property.Value) {
            return [string]$property.Value
        }
    }

    $faultProperty = $TaskError.PSObject.Properties["Fault"]
    if ($faultProperty -and $faultProperty.Value) {
        return Get-TaskErrorMessage -TaskError $faultProperty.Value
    }

    return [string]$TaskError
}

function Resolve-VM {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        $VIServer
    )

    $vmMatches = @(Get-VM -Name $Name -Server $VIServer -ErrorAction Stop)
    if ($vmMatches.Count -eq 0) {
        throw "VM '$Name' was not found on vCenter '$($VIServer.Name)'."
    }

    if ($vmMatches.Count -gt 1) {
        $ids = ($vmMatches | Select-Object -ExpandProperty Id) -join ", "
        throw "Multiple VMs named '$Name' were found on vCenter '$($VIServer.Name)': $ids"
    }

    return $vmMatches[0]
}

function Get-CurrentVM {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    return Get-VM -Id $VM.Id -Server $activeVIServerConnection -ErrorAction Stop
}

function Get-CurrentVMView {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    return Get-View -Id $VM.Id -Server $activeVIServerConnection -ErrorAction Stop
}

function Set-VmTagDefinition {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TagName,

        [Parameter(Mandatory = $true)]
        [string]$CategoryName
    )

    $category = Get-TagCategory -Server $activeVIServerConnection -Name $CategoryName -ErrorAction SilentlyContinue
    if (-not $category) {
        Write-Status "Creating tag category '$CategoryName'..."
        $category = New-TagCategory -Server $activeVIServerConnection -Name $CategoryName -Cardinality Single -EntityType VirtualMachine
    }

    $tag = Get-Tag -Server $activeVIServerConnection -Name $TagName -Category $category -ErrorAction SilentlyContinue
    if (-not $tag) {
        Write-Status "Creating tag '$TagName'..."
        $tag = New-Tag -Server $activeVIServerConnection -Name $TagName -Category $category
    }

    return $tag
}

function Set-PkFixedTag {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    $tag = Set-VmTagDefinition -TagName $pkFixedTagName -CategoryName $pkFixedTagCategoryName
    $existingAssignment = Get-TagAssignment -Server $activeVIServerConnection -Entity $VM -Tag $tag -ErrorAction SilentlyContinue
    if ($existingAssignment) {
        Write-Status "Tag '$pkFixedTagName' is already assigned to VM '$($VM.Name)'."
        return
    }

    Write-Status "Assigning tag '$pkFixedTagName' to VM '$($VM.Name)'..."
    New-TagAssignment -Server $activeVIServerConnection -Entity $VM -Tag $tag | Out-Null
}

function Stop-VMIfPoweredOn {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    $vmCurrent = Get-CurrentVM -VM $VM
    if ($vmCurrent.PowerState -eq "PoweredOff") {
        return
    }

    Write-Status "Shutting down guest on VM '$($vmCurrent.Name)'..."
    try {
        Shutdown-VMGuest -VM $vmCurrent -Confirm:$false | Out-Null
    }
    catch {
        Write-StatusWarning "Guest shutdown request failed. Falling back to hard power off."
    }

    $deadline = (Get-Date).AddMinutes(5)
    do {
        Start-Sleep -Seconds 5
        $vmCurrent = Get-CurrentVM -VM $VM
    } until ($vmCurrent.PowerState -eq "PoweredOff" -or (Get-Date) -gt $deadline)

    if ($vmCurrent.PowerState -ne "PoweredOff") {
        Write-StatusWarning "Graceful shutdown timed out. Forcing power off."
        Stop-VM -VM $vmCurrent -Confirm:$false | Out-Null
        $vmCurrent = Get-CurrentVM -VM $VM
    }

    if ($vmCurrent.PowerState -ne "PoweredOff") {
        throw "VM '$($vmCurrent.Name)' did not reach PoweredOff state."
    }
}

function Start-VMIfPoweredOff {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    $vmCurrent = Get-CurrentVM -VM $VM
    if ($vmCurrent.PowerState -eq "PoweredOn") {
        return
    }

    Start-VM -VM $vmCurrent -Confirm:$false | Out-Null
}

function Stop-VMHard {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    $vmCurrent = Get-CurrentVM -VM $VM
    if ($vmCurrent.PowerState -eq "PoweredOff") {
        return
    }

    Write-Status "Powering off VM '$($vmCurrent.Name)'..."
    Stop-VM -VM $vmCurrent -Confirm:$false | Out-Null

    $vmCurrent = Get-CurrentVM -VM $VM
    if ($vmCurrent.PowerState -ne "PoweredOff") {
        throw "VM '$($vmCurrent.Name)' did not reach PoweredOff state after hard power off."
    }
}

function Set-EnterFirmwareSetup {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,

        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )

    $vmView = Get-CurrentVMView -VM $VM
    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.BootOptions = New-Object VMware.Vim.VirtualMachineBootOptions
    $spec.BootOptions.EnterBIOSSetup = $Enabled

    $taskRef = $vmView.ReconfigVM_Task($spec)
    $taskView = Get-View -Id $taskRef -Server $activeVIServerConnection

    while ($taskView.Info.State -eq "running" -or $taskView.Info.State -eq "queued") {
        Start-Sleep -Seconds 1
        $taskView = Get-View -Id $taskRef -Server $activeVIServerConnection
    }

    if ($taskView.Info.State -ne "success") {
        $errMsg = Get-TaskErrorMessage -TaskError $taskView.Info.Error
        throw "Failed to update boot options: $errMsg"
    }
}

function Set-AuthBypass {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,

        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )

    $name = "uefi.allowAuthBypass"
    $existing = Get-AdvancedSetting -Entity $VM -Name $name -ErrorAction SilentlyContinue

    if ($Enabled) {
        if ($existing) {
            Set-AdvancedSetting -AdvancedSetting $existing -Value "TRUE" -Confirm:$false | Out-Null
        }
        else {
            New-AdvancedSetting -Entity $VM -Name $name -Value "TRUE" -Confirm:$false | Out-Null
        }
    }
    elseif ($existing) {
        Remove-AdvancedSetting -AdvancedSetting $existing -Confirm:$false | Out-Null
    }
}

function ConvertFrom-DatastorePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue
    )

    $normalizedPathValue = [string]$PathValue
    if ($normalizedPathValue -notmatch '^\[(?<ds>[^\]]+)\]\s(?<rel>.+)$') {
        throw "Datastore path '$PathValue' is not in expected format: [datastore] folder/file.vmdk"
    }

    return [ordered]@{
        Datastore = $Matches.ds
        Relative  = $Matches.rel
    }
}

function Resolve-PkDiskPathForVm {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,

        [Parameter(Mandatory = $true)]
        [string]$SourceDiskPath
    )

    $sourceParts = ConvertFrom-DatastorePath -PathValue $SourceDiskPath
    $sourceFileName = ($sourceParts.Relative -split '/')[-1]

    $vmView = Get-CurrentVMView -VM $VM
    $vmPath = $vmView.Config.Files.VmPathName
    $vmPathParts = ConvertFrom-DatastorePath -PathValue $vmPath
    $vmPathTokens = $vmPathParts.Relative -split '/'

    if ($vmPathTokens.Length -lt 2) {
        throw "Unable to determine VM folder from path '$vmPath'."
    }

    $vmFolder = ($vmPathTokens[0..($vmPathTokens.Length - 2)] -join '/')
    $destinationDiskPath = "[$($vmPathParts.Datastore)] $vmFolder/$sourceFileName"

    if ($destinationDiskPath -eq $SourceDiskPath) {
        Write-Status "PK disk already on VM datastore/folder: '$destinationDiskPath'."
        return $destinationDiskPath
    }

    Write-Status "Copying PK disk to VM datastore folder..."
    Write-Status "  Source: $SourceDiskPath"
    Write-Status "  Dest:   $destinationDiskPath"

    $datacenterView = ($VM | Get-Datacenter | Select-Object -First 1 | Get-View)
    $serviceInstance = Get-View ServiceInstance
    $vdm = Get-View -Id $serviceInstance.Content.VirtualDiskManager

    try {
        $copyTaskRef = $vdm.CopyVirtualDisk_Task(
            $SourceDiskPath,
            $datacenterView.MoRef,
            $destinationDiskPath,
            $datacenterView.MoRef,
            $null,
            $false
        )

        $copyTask = Get-View -Id $copyTaskRef
        while ($copyTask.Info.State -eq "running" -or $copyTask.Info.State -eq "queued") {
            Start-Sleep -Seconds 2
            $copyTask = Get-View -Id $copyTaskRef
        }

        if ($copyTask.Info.State -ne "success") {
            $copyError = Get-TaskErrorMessage -TaskError $copyTask.Info.Error
            if ($copyError -and $copyError -match "already exists") {
                Write-Status "Destination PK disk already exists, reusing it."
            }
            else {
                throw "CopyVirtualDisk_Task failed: $copyError"
            }
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match "already exists") {
            Write-Status "Destination PK disk already exists, reusing it."
        }
        else {
            throw
        }
    }

    return $destinationDiskPath
}

function Get-VmFolderDiskPath {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,

        [Parameter(Mandatory = $true)]
        [string]$SourceDiskPath
    )

    $sourceParts = ConvertFrom-DatastorePath -PathValue $SourceDiskPath
    $sourceFileName = ($sourceParts.Relative -split '/')[-1]

    $vmView = Get-CurrentVMView -VM $VM
    $vmPath = $vmView.Config.Files.VmPathName
    $vmPathParts = ConvertFrom-DatastorePath -PathValue $vmPath
    $vmPathTokens = $vmPathParts.Relative -split '/'

    if ($vmPathTokens.Length -lt 2) {
        throw "Unable to determine VM folder from path '$vmPath'."
    }

    $vmFolder = ($vmPathTokens[0..($vmPathTokens.Length - 2)] -join '/')
    return "[$($vmPathParts.Datastore)] $vmFolder/$sourceFileName"
}

function Remove-VimTaskAndWait {
    param(
        [Parameter(Mandatory = $true)]
        $TaskRef,

        [Parameter(Mandatory = $true)]
        [string]$ActionName
    )

    $taskView = Get-View -Id $TaskRef -Server $activeVIServerConnection
    while ($taskView.Info.State -eq "running" -or $taskView.Info.State -eq "queued") {
        Start-Sleep -Seconds 2
        $taskView = Get-View -Id $TaskRef -Server $activeVIServerConnection
    }

    if ($taskView.Info.State -ne "success") {
        $errMsg = Get-TaskErrorMessage -TaskError $taskView.Info.Error
        throw "$ActionName failed: $errMsg"
    }
}

function Remove-PkArtifacts {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,

        [Parameter(Mandatory = $true)]
        [string]$SourceDiskPath,

        [Parameter(Mandatory = $false)]
        [string]$SnapshotNameFilter = "pre-pk-update-*"
    )

    $targetPath = Get-VmFolderDiskPath -VM $VM -SourceDiskPath $SourceDiskPath
    $targetLeaf = ((ConvertFrom-DatastorePath -PathValue $targetPath).Relative -split '/')[-1]
    $targetStem = [System.IO.Path]::GetFileNameWithoutExtension($targetLeaf)

    # Remove PK-update snapshots before disk detach/delete.
    $snapshots = Get-Snapshot -VM $VM -ErrorAction SilentlyContinue
    if ($snapshots) {
        $targetSnapshots = @($snapshots | Where-Object { $_.Name -like $SnapshotNameFilter })
        if ($targetSnapshots.Count -eq 0) {
            $targetSnapshots = @($snapshots)
        }

        $snapNames = ($targetSnapshots | Select-Object -ExpandProperty Name) -join ", "
        Write-Status "Removing snapshot(s): $snapNames"
        $targetSnapshots | Remove-Snapshot -Confirm:$false | Out-Null
    }

    # Match both base and snapshot-derived secureboot disk names.
    $disksToDetach = @(Get-HardDisk -VM $VM | Where-Object {
        $f = $_.Filename
        if (-not $f) { $f = $_.FileName }
        $f -and (
            $f -eq $targetPath -or
            $f.EndsWith("/$targetLeaf") -or
            $f -match "/$([regex]::Escape($targetStem))(-\d+)?\.vmdk$"
        )
    })

    if ($disksToDetach.Count -gt 0) {
        $detachPaths = ($disksToDetach | ForEach-Object { if ($_.Filename) { $_.Filename } else { $_.FileName } }) -join ", "
        Write-Status "Detaching PK disk(s): $detachPaths"
        $disksToDetach | Remove-HardDisk -Confirm:$false -DeletePermanently:$false | Out-Null
    }
    else {
        Write-Status "No attached PK disk found to detach."
    }

    $datacenterView = ($VM | Get-Datacenter | Select-Object -First 1 | Get-View)
    $serviceInstance = Get-View ServiceInstance
    $vdm = Get-View -Id $serviceInstance.Content.VirtualDiskManager

    # Delete only the staged PK disk in the VM folder.
    Write-Status "Deleting PK disk in VM folder: $targetPath"
    try {
        $deleteTaskRef = $vdm.DeleteVirtualDisk_Task($targetPath, $datacenterView.MoRef)
        Remove-VimTaskAndWait -TaskRef $deleteTaskRef -ActionName "DeleteVirtualDisk_Task"
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match "Could not find" -or $msg -match "No such file" -or $msg -match "was not found") {
            Write-Status "PK disk file already absent in VM folder."
        }
        else {
            throw
        }
    }
}

function Find-PkHardDisk {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,

        [Parameter(Mandatory = $true)]
        [string]$TargetDatastorePath
    )

    $targetParts = ConvertFrom-DatastorePath -PathValue $TargetDatastorePath
    $targetRelative = $targetParts.Relative
    $targetLeaf = ($targetRelative -split '/')[-1]

    $allDisks = Get-HardDisk -VM $VM

    $exact = $allDisks | Where-Object {
        ($_.Filename -eq $TargetDatastorePath) -or ($_.FileName -eq $TargetDatastorePath)
    }
    if ($exact) {
        return @($exact)
    }

    $byRelativePath = $allDisks | Where-Object {
        $f = $_.Filename
        if (-not $f) { $f = $_.FileName }
        $f -and $f.EndsWith($targetRelative)
    }
    if ($byRelativePath) {
        return @($byRelativePath)
    }

    $byLeaf = $allDisks | Where-Object {
        $f = $_.Filename
        if (-not $f) { $f = $_.FileName }
        $f -and $f.EndsWith("/$targetLeaf")
    }

    return @($byLeaf)
}

function New-UsbKeyEvent {
    param(
        [Parameter(Mandatory = $true)]
        [int]$UsbHidCode
    )

    $keyEvent = New-Object VMware.Vim.UsbScanCodeSpecKeyEvent
    $keyEvent.UsbHidCode = ([int64]$UsbHidCode -shl 16) -bor 7
    $mods = New-Object VMware.Vim.UsbScanCodeSpecModifierType
    $mods.LeftControl = $false
    $mods.LeftShift = $false
    $mods.LeftAlt = $false
    $mods.LeftGui = $false
    $mods.RightControl = $false
    $mods.RightShift = $false
    $mods.RightAlt = $false
    $mods.RightGui = $false
    $keyEvent.Modifiers = $mods
    return $keyEvent
}

function Send-UsbKeyPress {
    param(
        [Parameter(Mandatory = $true)]
        $VMView,

        [Parameter(Mandatory = $true)]
        [int]$UsbHidCode,

        [Parameter(Mandatory = $false)]
        [int]$Repeat = 1,

        [Parameter(Mandatory = $false)]
        [double]$HoldMs = 100,

        [Parameter(Mandatory = $false)]
        [double]$GapMs = 200,

        [Parameter(Mandatory = $false)]
        [string]$Label = ""
    )

    $spec = New-Object VMware.Vim.UsbScanCodeSpec
    for ($i = 1; $i -le $Repeat; $i++) {
        if ($Label) {
            Write-Status "Sending $Label ($i/$Repeat)"
        }

        $keyEvent = New-UsbKeyEvent -UsbHidCode $UsbHidCode
        $spec.KeyEvents = @($keyEvent)
        $null = $VMView.PutUsbScanCodes($spec)
        Start-Sleep -Milliseconds ([int]$HoldMs)
        Start-Sleep -Milliseconds ([int]$GapMs)
    }
}

function Wait-Step {
    param(
        [Parameter(Mandatory = $true)]
        [double]$Seconds,

        [Parameter(Mandatory = $false)]
        [string]$Reason = ""
    )

    if ($Reason) {
        Write-Status "Waiting $Seconds sec: $Reason"
    }
    else {
        Write-Status "Waiting $Seconds sec"
    }

    Start-Sleep -Seconds $Seconds
}

function Invoke-HidSequence {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    # USB HID keyboard usage IDs.
    $hid = @{
        ENTER = 0x28
        UP    = 0x52
        DOWN  = 0x51
    }

    $vmView = Get-CurrentVMView -VM $VM
    if ($InitialDelaySec -gt 0) {
        Write-Status "Sequence starts in $InitialDelaySec sec..."
        Start-Sleep -Seconds $InitialDelaySec
    }

    # Firmware menu navigation sequence validated for this workflow.
    Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.DOWN -Repeat 20 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "DOWN"
    Wait-Step -Seconds 1.0 -Reason "after 20 DOWN"

    Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.UP -Repeat 2 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "UP"
    Wait-Step -Seconds $StepWaitSec -Reason "after 2 UP"

    Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.ENTER -Repeat 1 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "ENTER"
    Wait-Step -Seconds $StepWaitSec -Reason "after first ENTER"

    Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.DOWN -Repeat 3 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "DOWN"
    Wait-Step -Seconds $StepWaitSec -Reason "after 3 DOWN"

    for ($enterIdx = 1; $enterIdx -le 4; $enterIdx++) {
        Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.ENTER -Repeat 1 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "ENTER"
        if ($enterIdx -lt 4) {
            Wait-Step -Seconds $StepWaitSec -Reason "after ENTER $enterIdx"
        }
    }

    Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.DOWN -Repeat 1 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "DOWN"
    Wait-Step -Seconds 1.0 -Reason "Select cert disk"

    Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.ENTER -Repeat 1 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "ENTER"
    Wait-Step -Seconds $StepWaitSec -Reason "after additional ENTER"
    Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.DOWN -Repeat 1 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "DOWN"
    Wait-Step -Seconds $StepWaitSec -Reason "after additional 1 DOWN"
    Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.ENTER -Repeat 1 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "ENTER"
    Wait-Step -Seconds $StepWaitSec -Reason "Select file"
    Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.DOWN -Repeat 1 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "DOWN"
    Wait-Step -Seconds 1.0 -Reason "Select Commit Changes and Exit"
    Send-UsbKeyPress -VMView $vmView -UsbHidCode $hid.ENTER -Repeat 1 -HoldMs $KeyHoldMs -GapMs $InterKeyMs -Label "ENTER"
    Wait-Step -Seconds $StepWaitSec -Reason "FIRE!"
}

function Invoke-PkUpdateForVm {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Target
    )

    $script:currentVMName = $Target.VMName
    $script:runId = [Guid]::NewGuid().ToString()
    $script:snapshotCreatedAtUtc = $null
    $script:status = "started"
    $script:failureMessage = $null
    $script:sourcePkDiskPath = $Target.PkDiskPath
    $script:attachPkDiskPath = $Target.PkDiskPath

    try {
        $vm = Resolve-VM -Name $Target.VMName -VIServer $activeVIServerConnection

        if ($CleanupArtifactsOnly) {
            Write-Status "Running cleanup-only mode for VM '$($Target.VMName)'..."
            Remove-PkArtifacts -VM $vm -SourceDiskPath $sourcePkDiskPath
            $script:status = "success"
            Write-Status "Cleanup-only workflow completed for VM '$($Target.VMName)'."
            return [pscustomobject]@{
                VMName = $Target.VMName
                Status = $status
                Error  = $null
            }
        }

        $existingSnapshots = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue
        if ($existingSnapshots) {
            $snapshotList = ($existingSnapshots | Select-Object -ExpandProperty Name) -join ", "
            $script:status = "aborted"
            Write-StatusError "VM '$($Target.VMName)' already has snapshot(s): $snapshotList. Aborting."
            Write-RunLog -Status $status -ErrorMessage "Existing snapshots found: $snapshotList" -SnapshotNameValue $Target.SnapshotName
            return [pscustomobject]@{
                VMName = $Target.VMName
                Status = $status
                Error  = "Existing snapshots found: $snapshotList"
            }
        }

        Stop-VMIfPoweredOn -VM $vm

        $script:attachPkDiskPath = Resolve-PkDiskPathForVm -VM $vm -SourceDiskPath $sourcePkDiskPath

        Write-Status "Attaching PK disk '$attachPkDiskPath'..."
        $pkDiskExisting = @(Find-PkHardDisk -VM $vm -TargetDatastorePath $attachPkDiskPath)
        if ($pkDiskExisting.Count -eq 0) {
            New-HardDisk -VM $vm -DiskPath $attachPkDiskPath -Confirm:$false | Out-Null
        }
        else {
            Write-Status "PK disk already attached, continuing."
        }

        Write-Status "Creating snapshot '$($Target.SnapshotName)'..."
        New-Snapshot -VM $vm -Name $Target.SnapshotName -Description "Pre Microsoft PK enrollment" -Memory:$false -Quiesce:$false | Out-Null
        $script:snapshotCreatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        Write-RunLog -Status "snapshot_created" -SnapshotCreatedUtc $snapshotCreatedAtUtc -SnapshotNameValue $Target.SnapshotName

        Write-Status "Setting uefi.allowAuthBypass=TRUE..."
        Set-AuthBypass -VM $vm -Enabled $true

        Write-Status "Forcing next boot into firmware setup..."
        Set-EnterFirmwareSetup -VM $vm -Enabled $true

        Write-Status "Powering on VM '$($Target.VMName)'..."
        Start-VMIfPoweredOff -VM $vm

        Write-Status "Running HID enrollment sequence..."
        Invoke-HidSequence -VM $vm

        Stop-VMHard -VM $vm

        Write-Status "Removing uefi.allowAuthBypass..."
        Set-AuthBypass -VM $vm -Enabled $false

        Write-Status "Clearing forced firmware setup flag..."
        Set-EnterFirmwareSetup -VM $vm -Enabled $false

        Write-Status "Detaching PK disk '$attachPkDiskPath'..."
        $postUpdateSnapshots = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue
        if ($postUpdateSnapshots) {
            Write-StatusWarning "Skipping PK disk detach because snapshot(s) exist. VMware does not allow removing a virtual disk that is part of a snapshot chain. Remove snapshot(s) first, then detach the PK disk."
        }
        else {
            $pkDisk = @(Find-PkHardDisk -VM $vm -TargetDatastorePath $attachPkDiskPath)

            if ($pkDisk.Count -eq 1) {
                $pkDisk | Remove-HardDisk -Confirm:$false -DeletePermanently:$false | Out-Null
            }
            elseif ($pkDisk.Count -gt 1) {
                $paths = ($pkDisk | ForEach-Object { if ($_.Filename) { $_.Filename } else { $_.FileName } }) -join ", "
                Write-StatusWarning "Multiple matching PK disks found: $paths. Remove manually to avoid detaching the wrong disk."
            }
            else {
                Write-StatusWarning "PK disk not found by path. Remove manually if still attached."
            }
        }

        Write-Status "Powering on VM '$($Target.VMName)'..."
        Start-VMIfPoweredOff -VM $vm

        Set-PkFixedTag -VM $vm

        $script:status = "success"
        Write-Status "PK update workflow completed for VM '$($Target.VMName)'."
        return [pscustomobject]@{
            VMName = $Target.VMName
            Status = $status
            Error  = $null
        }
    }
    catch {
        $script:status = "failed"
        $script:failureMessage = $_.Exception.Message
        Write-StatusError "VM '$($Target.VMName)' failed: $failureMessage"
        return [pscustomobject]@{
            VMName = $Target.VMName
            Status = $status
            Error  = $failureMessage
        }
    }
    finally {
        if ($status -ne "aborted") {
            Write-RunLog -Status $status -ErrorMessage $failureMessage -SnapshotCreatedUtc $snapshotCreatedAtUtc -SnapshotNameValue $Target.SnapshotName
        }
    }
}

$cred = Get-LoginCredential -User $Username -Pass $Password
$targets = @(Get-TargetVmSpecs -SingleVMName $VMName -CsvFilePath $CsvPath)

try {
    $existingConnection = @(Get-ConnectedVIServer -ServerName $VCServer)
    if ($existingConnection.Count -gt 0) {
        $activeVIServerConnection = $existingConnection[0]
        $VCServer = Get-VIServerName -Server $activeVIServerConnection
        Write-Status "Using existing vCenter connection to '$VCServer'."
        $Username = $null
        $Password = $null
        $cred = $null
    }
    else {
        if (-not $VCServer) {
            $existingConnection = @(Get-ConnectedVIServer)
            if ($existingConnection.Count -eq 1) {
                $activeVIServerConnection = $existingConnection[0]
                $VCServer = Get-VIServerName -Server $activeVIServerConnection
                Write-Status "Using existing vCenter connection to '$VCServer'."
            }
            elseif ($existingConnection.Count -gt 1) {
                throw "Multiple vCenter connections are already open. Pass -VCServer to choose which one to use."
            }
            else {
                throw "VCServer is required when no existing vCenter connection is available. Pass -VCServer or set VC_SERVER."
            }
        }

        if ($cred) {
            $activeVIServerConnection = Connect-VIServer -Server $VCServer -Credential $cred
            $openedVIServerConnection = $true
        }
        elseif ($Username) {
            try {
                $activeVIServerConnection = Connect-VIServer -Server $VCServer -User $Username -ErrorAction Stop
                $openedVIServerConnection = $true
            }
            catch {
                throw "Unable to authenticate for '$Username' on '$VCServer'. Provide -Password, set VC_PASS, or save credentials in PowerCLI credential store."
            }
        }
        else {
            throw "No existing vCenter connection was found in this PowerShell process, and no credentials were provided. If you are starting the script with 'pwsh -NoProfile -File', pass -Username/-Password (or set VC_USER/VC_PASS), or run it from the same PowerShell session that already has an active Connect-VIServer connection."
        }
    }

    if (-not $activeVIServerConnection) {
        throw "Unable to resolve an active vCenter connection for '$VCServer'."
    }

    foreach ($target in $targets) {
        Write-Status "Starting VM '$($target.VMName)'..."
        $batchResults += @(Invoke-PkUpdateForVm -Target $target)
    }

    $failedTargets = @($batchResults | Where-Object { $_.Status -eq "failed" })
    $abortedTargets = @($batchResults | Where-Object { $_.Status -eq "aborted" })
    $successfulTargets = @($batchResults | Where-Object { $_.Status -eq "success" })

    Write-Status "Batch summary: $($successfulTargets.Count) succeeded, $($abortedTargets.Count) aborted, $($failedTargets.Count) failed."

    if ($failedTargets.Count -gt 0 -or $abortedTargets.Count -gt 0) {
        $failedNames = @($failedTargets + $abortedTargets | Select-Object -ExpandProperty VMName)
        throw "One or more VM operations did not complete successfully: $($failedNames -join ', ')"
    }
}
catch {
    $status = "failed"
    $failureMessage = $_.Exception.Message
    Write-StatusError $failureMessage
    throw
}
finally {
    if ($openedVIServerConnection -and $activeVIServerConnection) {
        Disconnect-VIServer -Server $activeVIServerConnection -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
}
