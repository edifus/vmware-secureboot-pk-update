# vmware-secureboot-pk-update

PowerCLI automation for VMware Secure Boot Platform Key (PK) enrollment with snapshot-aware safety checks, HID firmware navigation, and artifact cleanup.

## Features

- Pre-checks VM snapshot state before starting.
- Copies PK VMDK to the target VM datastore folder.
- Attaches PK disk, creates snapshot, and enables required EFI settings.
- Sends USB HID keystrokes to drive firmware enrollment menus.
- Cleans up EFI settings and restores normal boot behavior.
- Supports cleanup-only mode to remove snapshots, detach disk, and delete staged PK VMDK.
- Writes append-only JSONL run logs.

## Requirements

- PowerShell 7+
- VMware PowerCLI (`VMware.PowerCLI`)
- vCenter permissions for:
  - VM reconfiguration
  - Snapshot create/remove
  - Virtual disk copy/delete

## Script

- `Invoke-PkUpdate.ps1`

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

## Logging

Default log file:

- `./pk-update-log.jsonl`

Each run appends one JSON line including status, VM, vCenter, snapshot info, disk paths, and error details.

## Safety Notes

- Keep the pre-update snapshot until validation is complete.
- VMware does not allow detaching a disk that is part of an active snapshot chain.
- Cleanup mode removes snapshots and then detaches/deletes staged PK disk artifacts.

## License

MIT

## Reference

- Broadcom KB: <https://knowledge.broadcom.com/external/article/423919/manual-update-of-secure-boot-variables-i.html>
