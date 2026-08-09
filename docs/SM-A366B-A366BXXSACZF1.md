# SM-A366B A366BXXSACZF1 port analysis

Exact-build profile for the Samsung Galaxy A36 5G `SM-A366B` (Snapdragon 6
Gen 3, SM6450) derived from the shipped firmware AP. Offsets were recovered
from the exact kernel in the AP; they are not shared with any other firmware.

| Field | Value |
| --- | --- |
| Model | `SM-A366B` |
| Device | `a36xq` |
| Firmware | `A366BXXSACZF1` |
| Android | 16 / API 36 |
| Page size | 4096 |
| Kernel | `6.6.98-android15-8-33419078-abogkiA366BXXSACZF1-4k` |
| Build | `BP4A.251205.006` |
| Kernel build | `kleaf@build-host`, clang 18.0.0, GKI `android15-8` |

The kernel is built from the same `android15-6.6` GKI branch (sublevel
`33419078`) as the 6.6.98 S25 series (`pa3q`) and Z Fold 7 (`q7q`) kernels.
Samsung exact-build suffix and device configuration differ, so every offset
was derived from this firmware's own image; the 6.6.98 profiles were only
used as layout cross-checks.

## Image extraction

`boot.img` (header v4, 100597760 bytes) contains the ARM64 Image at page
`0x1000` with a 56-byte Samsung prefix. The boot header's `kernel_size`
(38644224 bytes) matches the Image size. The Image magic `ARMd` sits at file
offset `0x1038` of `boot.img`.

The raw file-offset to kernel VA mapping was recovered empirically instead of
being assumed: `linux_banner` (kallsyms VA `0xffffffc08144f980`) contains the
`Linux version 6.6.98...` string found at file offset `0x1450980`, so

```text
VA = KIMAGE_TEXT_BASE + (file_offset - 0x1000)
KIMAGE_TEXT_BASE = 0xffffffc080000000
```

Every data-pointer read below was validated against this mapping (for example
`nfulnl_logger.name`, `ashmem_misc.fops`, and all five `ashmem_fops` member
pointers).

## Recovered offsets

All symbol offsets are kallsyms VAs minus `KIMAGE_TEXT_BASE`:

| Macro | Value | Cross-check |
| --- | ---: | --- |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | `0x000d0fa4` | q7q +0xf8 |
| `NOOP_LLSEEK_OFF` | `0x003c7b24` | nm `noop_llseek` |
| `COPY_SPLICE_READ_OFF` | `0x00415044` | nm `copy_splice_read` |
| `CONFIGFS_READ_ITER_OFF` | `0x00491934` | nm |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | `0x00491e60` | nm |
| `ASHMEM_IOCTL_OFF` | `0x00d60b8c` | `ashmem_fops.unlocked_ioctl` |
| `ASHMEM_COMPAT_IOCTL_OFF` | `0x00d61248` | `ashmem_fops.compat_ioctl` |
| `ASHMEM_MMAP_OFF` | `0x00d6129c` | `ashmem_fops.mmap` |
| `ASHMEM_OPEN_OFF` | `0x00d614bc` | `ashmem_fops.open` |
| `ASHMEM_RELEASE_OFF` | `0x00d61544` | `ashmem_fops.release` |
| `ASHMEM_SHOW_FDINFO_OFF` | `0x00d615d0` | `ashmem_fops.show_fdinfo` |
| `ANON_PIPE_BUF_OPS_OFF` | `0x0123cc48` | nm |
| `ASHMEM_FOPS_OFF` | `0x013fad80` | `ashmem_misc.fops` |
| `KMALLOC_CACHES_OFF` | `0x017c5b10` | nm |
| `SYSTEM_UNBOUND_WQ_OFF` | `0x022cae60` | nm |
| `INIT_TASK_OFF` | `0x022de340` | nm |
| `ASHMEM_MISC_OFF` | `0x0244c360` | nm |
| `ROOT_TASK_GROUP_OFF` | `0x024ea580` | nm |
| `SELINUX_ENFORCING_OFF` | `0x0252c598` | `selinux_state` + BTF `enforcing` 0 |
| `SYSCTL_BOOTID_OFF` | `0x0260f1a0` | nm `sysctl_bootid` |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | `0x0174a916` | `nfulnl_logger.name` target |
| `SLIDE_NFULNL_LOGGER_OBJECT_OFF` | `0x022d2278` | nm `nfulnl_logger` |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | `0x024090c0` | `random_table` `boot_id` entry |

`ASHMEM_MISC_FOPS_OFF` is not a symbol: BTF gives
`offsetof(struct miscdevice, fops) == 0x10`, so it is
`ASHMEM_MISC_OFF + 0x10 = 0x0244c370`.

### Slide data

- `SLIDE_TRACEFS_EVENT_ID 109`: `(0x288d788 - 0x288d4c0) / 8 = 89`
  (`__event_sched_blocked_reason` after `__start_ftrace_events`), plus
  `__TRACE_LAST_TYPE 20` for this `android15-6.6` branch.
- `SLIDE_TRACEFS_WORKER_CALLER_OFF 0x000d98e4`: in `worker_thread`, the idle
  wait is `bl schedule` at `0x000d98e0`; the return address is `0x000d98e4`.
  The q7q (6.6.98) caller `0x000d97ec` plus the same +0xf8 delta seen in
  `call_usermodehelper_exec_work` corroborates the location.
- `SLIDE_PSELECT_WORD_SHIFT 0`: this kernel shares the `fs/select.c` copy
  layout with the A366W/A566E 6.6 profiles, all of which use word shift 0.

### BTF layout (this kernel)

The 6.6 layouts match the A366W and q7q profiles:

```text
file_operations: unlocked_ioctl 0x48, compat_ioctl 0x50, mmap 0x58,
  open 0x68, release 0x78, splice_read 0xb8, show_fdinfo 0xd8
task_struct: usage 0x40, prio 0x84, normal_prio 0x8c, sched_task_group 0x348,
  pi_lock 0x90c, pi_waiters 0x920, pi_top_task 0x930, pi_blocked_on 0x938
rt_mutex_waiter: task 0x50, lock 0x58
pipe_buffer: page 0x00, offset 0x08, len 0x0c, ops 0x10, flags 0x18
selinux_state.enforcing: 0x00
miscdevice.fops: 0x10
```

## Physical load

The AP archive does not contain the BL, so `sboot` could not be inspected.
`P0_KERNEL_PHYS_LOAD 0xa8000000` follows the same-SoC SM6450 A366W profile
and the 6.6.98 S25/Z Fold 7 kernels; this must be confirmed from `sboot.bin`
when the BL archive is available, per `docs/PORTING.md` section 4.

## Status

- `make TARGET=a36xq-A366BXXSACZF1 ANDROID_NDK_HOME=...` builds all three
  binaries and the 104128-byte release app payload.
- `p0_fingerprint.h` was generated from the exact Image at probe
  `0x1f0000`; the generator verified all 32 rows / 256 source qwords.
- KernelSU late-load artifacts for this exact vermagic require building from
  the Samsung `android15-6.6` sources; not produced from the AP alone.
- Not yet device-tested. This profile is exact-build support for
  `SM-A366B`/`A366BXXSACZF1` and claims no compatibility with other Galaxy
  A36 models, firmware, or kernel releases.
