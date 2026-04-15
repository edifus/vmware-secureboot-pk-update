# vmware-secureboot-pk-update

PowerCLI automation for VMware Secure Boot Platform Key (PK) enrollment with snapshot-aware safety checks, HID firmware navigation, and artifact cleanup.

## Features

- Pre-checks VM snapshot state before starting.
- Copies PK VMDK to the target VM datastore folder.
- Attaches PK disk, creates snapshot, and enables required EFI settings.
- Sends USB HID keystrokes to drive firmware enrollment menus.
- Cleans up EFI settings and restores normal boot behavior.
- Supports cleanup-only mode to remove snapshots, detach disk, and delete staged PK VMDK.
- Adds a `PK-Fixed` vCenter tag to mark completed VMs.
- Writes append-only JSONL run logs.
- Supports single VM or batch mode via CSV.
- Reuses existing vCenter connection if already connected.

## Requirements

- PowerShell 7+
- VMware PowerCLI (`VMware.PowerCLI`)
- vCenter permissions for:
  - VM reconfiguration
  - Snapshot create/remove
  - Virtual disk copy/delete

## Scripts

- `Invoke-PkUpdate.ps1` - Main workflow
- `check-pk.ps1` - Status checker (lists UEFI VMs and their PK-Fixed tag status)

## Environment Variables

Optional environment-based configuration:

- `VC_SERVER`
- `VC_USER`
- `VC_PASS`
- `PK_VMDK_PATH`

Example:

```bash
export VC_SERVER="vcenter.example.local"
export VC_USER="administrator@vsphere.local"
read -rsp 'vCenter password: ' VC_PASS; echo
export VC_PASS
export PK_VMDK_PATH='[iso] secureboot.vmdk'
```

## Usage

### Single VM Mode

Run full PK update workflow:

```bash
pwsh -NoProfile -File ./Invoke-PkUpdate.ps1 -VCServer "vcenter.example.local" -VMName "target-vm"
```

Run cleanup-only mode:

```bash
pwsh -NoProfile -File ./Invoke-PkUpdate.ps1 -VCServer "vcenter.example.local" -VMName "target-vm" -CleanupArtifactsOnly
```

Override PK disk path directly:

```bash
pwsh -NoProfile -File ./Invoke-PkUpdate.ps1 -VCServer "vcenter.example.local" -VMName "target-vm" -PkDiskPath "[iso] secureboot.vmdk"
```

### Batch Mode (CSV)

Create a CSV file with the following columns:

- `VMName` (required)
- `PkDiskPath` (optional - defaults to global `-PkDiskPath`)
- `SnapshotName` (optional - auto-generated if omitted)

Example `vms.csv`:

```csv
VMName,PkDiskPath,SnapshotName
vmware-linux,[iso] secureboot.vmdk,pre-pk-update-vmware-linux-20260410
webserver-01,[iso] secureboot.vmdk,
db-server-02,
```

Run batch mode:

```bash
pwsh -NoProfile -File ./Invoke-PkUpdate.ps1 -VCServer "vcenter.example.local" -CsvPath "./vms.csv"
```

### Connection Reuse

If you already have an active vCenter connection in your PowerShell session, you can omit `-VCServer`:

```powershell
Connect-VIServer -Server "vcenter.example.local"  # once
pwsh -NoProfile -File ./Invoke-PkUpdate.ps1 -VMName "target-vm"  # reuses connection
```

## PK Disk Preparation (VMDK)

Prepare a temporary 128 MB FAT32 disk that contains the Microsoft PK certificate (`WindowsOEMDevicesPK.der`).

Linux (Ubuntu/Debian) example:

```bash
# identify new disk (example /dev/sdb)
lsblk

# format as FAT32
sudo mkfs.vfat -F 32 -n KEYUPDATE /dev/sdb

# mount and copy certificate
sudo mkdir -p /mnt/keys
sudo mount /dev/sdb /mnt/keys
sudo cp WindowsOEMDevicesPK.der /mnt/keys/

# unmount when done
sudo umount /mnt/keys
```

Windows example:

- Add a 128 MB disk.
- Format as FAT32 (Disk Management or `format /FS:FAT32 X:`).
- Copy `WindowsOEMDevicesPK.der` to the new volume.

Then place or upload the prepared VMDK in a datastore and set `PK_VMDK_PATH`.

## Tagging

On successful completion, the script adds a vCenter tag (`PK-Fixed`) to the VM in the category `PK Update Status`. This helps track which VMs have been updated.

## Status Checker

Run `check-pk.ps1` to list all UEFI VMs with Secure Boot enabled and their `PK-Fixed` status:

```bash
pwsh -NoProfile -File ./check-pk.ps1 -VCServer "vcenter.example.local"
```

Export the report to `./Affected_SecureBoot_VMs.csv`:

```bash
pwsh -NoProfile -File ./check-pk.ps1 -VCServer "vcenter.example.local" -ExportCsv
```

## Logging

Default log file:

- `./pk-update-log.jsonl`

Each run appends one JSON line including status, VM, vCenter, snapshot info, disk paths, and error details.

## Safety Notes

- Keep the pre-update snapshot until validation is complete.
- VMware does not allow detaching a disk that is part of an active snapshot chain.
- Cleanup mode removes snapshots and then detaches/deletes staged PK disk artifacts without changing VM power state.

## License

MIT

## Reference

- Broadcom KB: <https://knowledge.broadcom.com/external/article/423919/manual-update-of-secure-boot-variables-i.html>
