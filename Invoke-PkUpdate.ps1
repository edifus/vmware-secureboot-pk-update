<#
.SYNOPSIS
Automates Secure Boot PK update workflow for a vSphere VM.

.DESCRIPTION
This script performs an end-to-end PK enrollment flow:
1) Pre-check snapshot state
2) Stage PK VMDK in VM datastore folder
3) Attach disk and snapshot VM
4) Enable EFI auth bypass + force firmware setup
5) Send HID key sequence for enrollment menus
6) Cleanup VM settings and power state

Use -CleanupArtifactsOnly to remove snapshots, detach PK disk, and delete
the staged PK VMDK from the VM folder after validation.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$VMName,

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

if (-not $VCServer) {
    throw "VCServer is required. Pass -VCServer or set VC_SERVER."
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
        vmName               = $VMName
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

function Ensure-PoweredOff {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    $vmCurrent = Get-VM -Id $VM.Id
    if ($vmCurrent.PowerState -eq "PoweredOff") {
        return
    }

    Write-Host "Shutting down guest on VM '$($vmCurrent.Name)'..."
    try {
        Shutdown-VMGuest -VM $vmCurrent -Confirm:$false | Out-Null
    }
    catch {
        Write-Warning "Guest shutdown request failed. Falling back to hard power off."
    }

    $deadline = (Get-Date).AddMinutes(5)
    do {
        Start-Sleep -Seconds 5
        $vmCurrent = Get-VM -Id $VM.Id
    } until ($vmCurrent.PowerState -eq "PoweredOff" -or (Get-Date) -gt $deadline)

    if ($vmCurrent.PowerState -ne "PoweredOff") {
        Write-Warning "Graceful shutdown timed out. Forcing power off."
        Stop-VM -VM $vmCurrent -Confirm:$false | Out-Null
        $vmCurrent = Get-VM -Id $VM.Id
    }

    if ($vmCurrent.PowerState -ne "PoweredOff") {
        throw "VM '$($vmCurrent.Name)' did not reach PoweredOff state."
    }
}

function Ensure-PoweredOn {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    $vmCurrent = Get-VM -Id $VM.Id
    if ($vmCurrent.PowerState -eq "PoweredOn") {
        return
    }

    Start-VM -VM $vmCurrent -Confirm:$false | Out-Null
}

function Force-PoweredOff {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM
    )

    $vmCurrent = Get-VM -Id $VM.Id
    if ($vmCurrent.PowerState -eq "PoweredOff") {
        return
    }

    Write-Host "Powering off VM '$($vmCurrent.Name)'..."
    Stop-VM -VM $vmCurrent -Confirm:$false | Out-Null

    $vmCurrent = Get-VM -Id $VM.Id
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

    $vmView = Get-View -Id $VM.Id
    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.BootOptions = New-Object VMware.Vim.VirtualMachineBootOptions
    $spec.BootOptions.EnterBIOSSetup = $Enabled

    $taskRef = $vmView.ReconfigVM_Task($spec)
    $taskView = Get-View -Id $taskRef

    while ($taskView.Info.State -eq "running" -or $taskView.Info.State -eq "queued") {
        Start-Sleep -Seconds 1
        $taskView = Get-View -Id $taskRef
    }

    if ($taskView.Info.State -ne "success") {
        $errMsg = $taskView.Info.Error.LocalizedMessage
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

function Parse-DatastorePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue
    )

    if ($PathValue -notmatch '^\[(?<ds>[^\]]+)\]\s(?<rel>.+)$') {
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

    $sourceParts = Parse-DatastorePath -PathValue $SourceDiskPath
    $sourceFileName = ($sourceParts.Relative -split '/')[-1]

    $vmView = Get-View -Id $VM.Id
    $vmPath = $vmView.Config.Files.VmPathName
    $vmPathParts = Parse-DatastorePath -PathValue $vmPath
    $vmPathTokens = $vmPathParts.Relative -split '/'

    if ($vmPathTokens.Length -lt 2) {
        throw "Unable to determine VM folder from path '$vmPath'."
    }

    $vmFolder = ($vmPathTokens[0..($vmPathTokens.Length - 2)] -join '/')
    $destinationDiskPath = "[$($vmPathParts.Datastore)] $vmFolder/$sourceFileName"

    if ($destinationDiskPath -eq $SourceDiskPath) {
        Write-Host "PK disk already on VM datastore/folder: '$destinationDiskPath'."
        return $destinationDiskPath
    }

    Write-Host "Copying PK disk to VM datastore folder..."
    Write-Host "  Source: $SourceDiskPath"
    Write-Host "  Dest:   $destinationDiskPath"

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
            $copyError = $copyTask.Info.Error.LocalizedMessage
            if ($copyError -and $copyError -match "already exists") {
                Write-Host "Destination PK disk already exists, reusing it."
            }
            else {
                throw "CopyVirtualDisk_Task failed: $copyError"
            }
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match "already exists") {
            Write-Host "Destination PK disk already exists, reusing it."
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

    $sourceParts = Parse-DatastorePath -PathValue $SourceDiskPath
    $sourceFileName = ($sourceParts.Relative -split '/')[-1]

    $vmView = Get-View -Id $VM.Id
    $vmPath = $vmView.Config.Files.VmPathName
    $vmPathParts = Parse-DatastorePath -PathValue $vmPath
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

    $taskView = Get-View -Id $TaskRef
    while ($taskView.Info.State -eq "running" -or $taskView.Info.State -eq "queued") {
        Start-Sleep -Seconds 2
        $taskView = Get-View -Id $TaskRef
    }

    if ($taskView.Info.State -ne "success") {
        $errMsg = $taskView.Info.Error.LocalizedMessage
        throw "$ActionName failed: $errMsg"
    }
}

function Cleanup-PkArtifacts {
    param(
        [Parameter(Mandatory = $true)]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,

        [Parameter(Mandatory = $true)]
        [string]$SourceDiskPath,

        [Parameter(Mandatory = $false)]
        [string]$SnapshotNameFilter = "pre-pk-update-*"
    )

    $targetPath = Get-VmFolderDiskPath -VM $VM -SourceDiskPath $SourceDiskPath
    $targetLeaf = ((Parse-DatastorePath -PathValue $targetPath).Relative -split '/')[-1]
    $targetStem = [System.IO.Path]::GetFileNameWithoutExtension($targetLeaf)

    Ensure-PoweredOff -VM $VM

    # Remove PK-update snapshots before disk detach/delete.
    $snapshots = Get-Snapshot -VM $VM -ErrorAction SilentlyContinue
    if ($snapshots) {
        $targetSnapshots = @($snapshots | Where-Object { $_.Name -like $SnapshotNameFilter })
        if ($targetSnapshots.Count -eq 0) {
            $targetSnapshots = @($snapshots)
        }

        $snapNames = ($targetSnapshots | Select-Object -ExpandProperty Name) -join ", "
        Write-Host "Removing snapshot(s): $snapNames"
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
        Write-Host "Detaching PK disk(s): $detachPaths"
        $disksToDetach | Remove-HardDisk -Confirm:$false -DeletePermanently:$false | Out-Null
    }
    else {
        Write-Host "No attached PK disk found to detach."
    }

    $datacenterView = ($VM | Get-Datacenter | Select-Object -First 1 | Get-View)
    $serviceInstance = Get-View ServiceInstance
    $vdm = Get-View -Id $serviceInstance.Content.VirtualDiskManager

    # Delete only the staged PK disk in the VM folder.
    Write-Host "Deleting PK disk in VM folder: $targetPath"
    try {
        $deleteTaskRef = $vdm.DeleteVirtualDisk_Task($targetPath, $datacenterView.MoRef)
        Remove-VimTaskAndWait -TaskRef $deleteTaskRef -ActionName "DeleteVirtualDisk_Task"
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match "Could not find" -or $msg -match "No such file") {
            Write-Host "PK disk file already absent in VM folder."
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

    $targetParts = Parse-DatastorePath -PathValue $TargetDatastorePath
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

    $event = New-Object VMware.Vim.UsbScanCodeSpecKeyEvent
    $event.UsbHidCode = ([int64]$UsbHidCode -shl 16) -bor 7
    $mods = New-Object VMware.Vim.UsbScanCodeSpecModifierType
    $mods.LeftControl = $false
    $mods.LeftShift = $false
    $mods.LeftAlt = $false
    $mods.LeftGui = $false
    $mods.RightControl = $false
    $mods.RightShift = $false
    $mods.RightAlt = $false
    $mods.RightGui = $false
    $event.Modifiers = $mods
    return $event
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
            Write-Host "Sending $Label ($i/$Repeat)"
        }

        $event = New-UsbKeyEvent -UsbHidCode $UsbHidCode
        $spec.KeyEvents = @($event)
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
        Write-Host "Waiting $Seconds sec: $Reason"
    }
    else {
        Write-Host "Waiting $Seconds sec"
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

    $vmView = Get-View -Id $VM.Id
    if ($InitialDelaySec -gt 0) {
        Write-Host "Sequence starts in $InitialDelaySec sec..."
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

$cred = Get-LoginCredential -User $Username -Pass $Password

try {
    if ($cred) {
        Connect-VIServer -Server $VCServer -Credential $cred | Out-Null
    }
    elseif ($Username) {
        try {
            Connect-VIServer -Server $VCServer -User $Username -ErrorAction Stop | Out-Null
        }
        catch {
            throw "Unable to authenticate for '$Username' on '$VCServer'. Provide -Password, set VC_PASS, or save credentials in PowerCLI credential store."
        }
    }
    else {
        Connect-VIServer -Server $VCServer | Out-Null
    }

    $vm = Get-VM -Name $VMName -ErrorAction Stop

    if ($CleanupArtifactsOnly) {
        Write-Host "Running cleanup-only mode..."
        Cleanup-PkArtifacts -VM $vm -SourceDiskPath $sourcePkDiskPath
        Ensure-PoweredOn -VM $vm
        $status = "success"
        Write-Host "Cleanup-only workflow completed."
        return
    }
    $existingSnapshots = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue
    if ($existingSnapshots) {
        $snapshotList = ($existingSnapshots | Select-Object -ExpandProperty Name) -join ", "
        $status = "aborted"
        Write-Error "VM '$VMName' already has snapshot(s): $snapshotList. Aborting."
        Write-RunLog -Status $status -ErrorMessage "Existing snapshots found: $snapshotList" -SnapshotNameValue $SnapshotName
        return
    }

    Ensure-PoweredOff -VM $vm

    $attachPkDiskPath = Resolve-PkDiskPathForVm -VM $vm -SourceDiskPath $sourcePkDiskPath

    Write-Host "Attaching PK disk '$attachPkDiskPath'..."
    $pkDiskExisting = @(Find-PkHardDisk -VM $vm -TargetDatastorePath $attachPkDiskPath)
    if ($pkDiskExisting.Count -eq 0) {
        New-HardDisk -VM $vm -DiskPath $attachPkDiskPath -Confirm:$false | Out-Null
    }
    else {
        Write-Host "PK disk already attached, continuing."
    }

    Write-Host "Creating snapshot '$SnapshotName'..."
    New-Snapshot -VM $vm -Name $SnapshotName -Description "Pre Microsoft PK enrollment" -Memory:$false -Quiesce:$false | Out-Null
    $snapshotCreatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    Write-RunLog -Status "snapshot_created" -SnapshotCreatedUtc $snapshotCreatedAtUtc -SnapshotNameValue $SnapshotName

    Write-Host "Setting uefi.allowAuthBypass=TRUE..."
    Set-AuthBypass -VM $vm -Enabled $true

    Write-Host "Forcing next boot into firmware setup..."
    Set-EnterFirmwareSetup -VM $vm -Enabled $true

    Write-Host "Powering on VM '$VMName'..."
    Ensure-PoweredOn -VM $vm

    Write-Host "Running HID enrollment sequence..."
    Invoke-HidSequence -VM $vm

    Force-PoweredOff -VM $vm

    Write-Host "Removing uefi.allowAuthBypass..."
    Set-AuthBypass -VM $vm -Enabled $false

    Write-Host "Clearing forced firmware setup flag..."
    Set-EnterFirmwareSetup -VM $vm -Enabled $false

    Write-Host "Detaching PK disk '$attachPkDiskPath'..."
    $postUpdateSnapshots = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue
    if ($postUpdateSnapshots) {
        Write-Warning "Skipping PK disk detach because snapshot(s) exist. VMware does not allow removing a virtual disk that is part of a snapshot chain. Remove snapshot(s) first, then detach the PK disk."
    }
    else {
        $pkDisk = @(Find-PkHardDisk -VM $vm -TargetDatastorePath $attachPkDiskPath)

        if ($pkDisk.Count -eq 1) {
            $pkDisk | Remove-HardDisk -Confirm:$false -DeletePermanently:$false | Out-Null
        }
        elseif ($pkDisk.Count -gt 1) {
            $paths = ($pkDisk | ForEach-Object { if ($_.Filename) { $_.Filename } else { $_.FileName } }) -join ", "
            Write-Warning "Multiple matching PK disks found: $paths. Remove manually to avoid detaching the wrong disk."
        }
        else {
            Write-Warning "PK disk not found by path. Remove manually if still attached."
        }
    }

    Write-Host "Powering on VM '$VMName'..."
    Ensure-PoweredOn -VM $vm

    $status = "success"
    Write-Host "PK update workflow completed."
}
catch {
    $status = "failed"
    $failureMessage = $_.Exception.Message
    throw
}
finally {
    if ($status -ne "aborted") {
        Write-RunLog -Status $status -ErrorMessage $failureMessage -SnapshotCreatedUtc $snapshotCreatedAtUtc -SnapshotNameValue $SnapshotName
    }

    $connected = @()
    $viServersVar = Get-Variable -Name DefaultVIServers -Scope Global -ErrorAction SilentlyContinue
    if ($viServersVar -and $viServersVar.Value) {
        $connected = @($viServersVar.Value | Where-Object { $_.Name -eq $VCServer })
    }

    if ($connected) {
        Disconnect-VIServer -Server $VCServer -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
}
