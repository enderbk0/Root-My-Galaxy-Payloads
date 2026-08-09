# SKILLS.md

Reference notes for working in this repository.

## Repository overview

`Root-My-Galaxy-Payloads` is the device-specific native payload repo for
[Root My Galaxy](https://github.com/BuSung-Dev/Root-My-Galaxy): an Android app
that roots Samsung Galaxy devices via a kernel exploit (no bootloader unlock).
It contains:

- `src/` — exploit source (C, built with the Android NDK via `make TARGET=<profile>`)
- `src/targets/<device>-<firmware>/` — per-firmware `target.h` offsets + `p0_fingerprint.h`
- `src/kernelsnitch/` — KernelSnitch mm_struct bruteforce (KASLR bypass)
- `kernelsu/` — KernelSU v3.2.5 late-load modules patched for Samsung KDP/RKP/DEFEX
- `docs/` — per-firmware port records (offsets, hashes, device validation)
- `support/targets-v3.json` — app feed: payloadId, models, kernelVersions, artifact URLs
- `artifacts/` — compiled per-device exploit payloads (`cve-2026-43499-app.so`)

Upstream: <https://github.com/BuSung-Dev/Root-My-Galaxy-Payloads>

## CVE-2026-43499 ("GhostLock") — what the exploit is

- **Bug:** stack use-after-free in `kernel/locking/rtmutex.c` (`remove_waiter()`).
  Present since Linux 2.6.39, fixed in 7.1 by commit `3bfdc63936dd`
  ("rtmutex: Use waiter::task instead of current in remove_waiter()"). CWE-416,
  CVSS 7.8 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H). No runtime mitigation.
- **Root cause:** `remove_waiter()` clears `current->pi_blocked_on`. Correct on
  the self-blocking slow path, but wrong on the proxy path:
  `rt_mutex_start_proxy_lock()` (called from `futex_requeue`) rolls back a
  waiter on behalf of a *different* sleeping thread. On `-EDEADLK` rollback,
  the *waiter* keeps `pi_blocked_on` pointing at its own kernel-stack
  `rt_mutex_waiter` frame, which is freed when it returns to userspace.
- **Trigger (see `src/main.c` `waiter_thread`/`owner_thread`/`run_main_route_threads`):**
  1. waiter locks `f_pi_chain`, blocks in `FUTEX_WAIT_REQUEUE_PI(f_wait -> f_pi_target)`
  2. owner locks `f_pi_target`, blocks on `f_pi_chain` (held by waiter)
  3. main does `FUTEX_CMP_REQUEUE_PI` → PI chain walk finds the cycle →
     `-EDEADLK` → buggy rollback → waiter left with dangling `pi_blocked_on`.
     No race pressure afterwards; the UAF window is open indefinitely.
- **Initial primitive:** forge a fake `rt_mutex_waiter` on the reclaimed stack
  frame (e.g. via `prctl(PR_SET_MM_MAP)` auxv buffer / `pselect` stack frames).
  A later `sched_setattr()` PI chain walk performs `rt_mutex_dequeue` = rb-tree
  erase → **one constrained pointer write** `*(u64*)target = W0_BASE`, with
  constraints: `*(u32*)(target-8) == 0` (unlocked spinlock), `target+8` and
  `target+16` must be benign (rb_leftmost / owner).
- **x86 chain (upstream writeup):** prefetch KASLR leak → CEA (CPU entry area)
  direct-map spray → overwrite `inet6_protos[IPPROTO_UDP]` (neighbors NULL,
  constraints free) → loopback IPv6 UDP packet → CFH → ROP → "DirtyMode"
  (flip `core_pattern` ctl_table mode to world-writable) → userland root.
- **References:** <https://nebusec.ai/research/ionstack-part-2/>
  (Nebula Security writeup, July 2026; kernelCTF reward $92,337);
  upstream exploit: <https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499>
- **Note:** the first upstream fix introduced a NULL-deref (`waiter->task` not
  yet set on a non-top requeue path) — CVE-2026-53166, fixed by `40a25d59e85b`.

## How the Android/ARM64 (Samsung) chain differs from the x86 chain

Nebula's official Android port record is "IonStack part III: Rooting Android 17
with GhostLock" — <https://nebusec.ai/research/ionstack-part-3/> (July 2026).
This repo is the Samsung adaptation of that chain. The Samsung payload flow is:

1. **GhostLock trigger** (same everywhere): 3 futexes + 3 threads,
   `FUTEX_CMP_REQUEUE_PI` `-EDEADLK` rollback → waiter left with dangling
   `pi_blocked_on` into its freed kernel-stack frame.
2. **KASLR bypass differs:**
   - x86: `prefetch` timing side-channel (works because KPTI off in kernelCTF).
   - Android/ARM64: KPTI (`UNMAP_KERNEL_AT_EL0`) + `kptr_restrict` block it →
     **KernelSnitch**: futex-hash-bucket timing bruteforce of `mm_struct`
     over the physmap identity region; plus the **"slide" P0 oracle**:
     use the constrained write to repoint `/proc/sys/kernel/random/boot_id`'s
     sysctl `.data` at a slot holding a live kernel pointer
     (`loggers[0][1]` = `&nfulnl_logger`), read `boot_id` → UUID-decoded
     pointer → KASLR slide = ptr − known image offset
     (per-firmware `SLIDE_*_OFF` + `p0_fingerprint.h` candidate tables).
     Note: since 1db780bafa4c the arm64 physmap base is fixed (no linear-map
     randomization), so the physmap alias of kernel data is usable at a known
     address; but the physmap is NX, so executable addresses still need the slide.
3. **Stack-frame reclaim differs:**
   - x86: `prctl(PR_SET_MM, PR_SET_MM_MAP)` auxv stack buffer.
   - Android: **`pselect6` fd_set** stack buffer (`PSELECT_ROUTE_NFDS 320`,
     `stack_fds[256]`) — the fake `rt_mutex_waiter` fields (task/lock) are
     written into the fd_set bitmaps. Where the waiter lands inside the buffer
     is a compiler-layout property (PGO/LTO), per-SoC/per-firmware →
     `PSELECT_SHIFT` / `SLIDE_PSELECT_WORD_SHIFT` tuning, verified with kprobes.
4. **Constrained write target differs:**
   - x86: `inet6_protos[IPPROTO_UDP]` → CEA spray → ROP → DirtyMode.
   - Android: overwrite **`ashmem_misc.fops`** (miscdevice fops slot;
     `target−8` reads as unlocked spinlock in the misc struct, constraints
     satisfied) → point it at a **fake `file_operations`** table (sprayed in
     `sk_buff` data via `sendmsg`, located with KernelSnitch + cross-cache
     reuse) in the physmap.
5. **CFI bypass (Android-only):** Clang CFI (+ BTI/PAC on newer) blocks
   arbitrary function-pointer hijack. The fake fops table therefore points
   `read_iter`/`write_iter` at the **real `configfs_read_iter` /
   `configfs_bin_write_iter`** — same signature
   `ssize_t (struct kiocb *, struct iov_iter *)` → same CFI hash, so the
   indirect call passes. `ASHMEM_SET_NAME` controls
   `ashmem_file->private_data` = fake `configfs_buffer` (`page`/`bin_buffer`
   pointers) → `read()`/`write()` become a **constrained arbitrary kernel
   read/write** (`copy_{to,from}_user`, length-limited). CFI swap works even
   on Rust-rewritten ashmem (GKI 6.12).
6. **R/W upgrade:** same as x86 conceptually — forge a `pipe_buffer` (overwrite
   `pipe_buffer.page` via the configfs write) → full arbitrary physical
   read/write through the pipe; VA→`struct page` via fixed VMEMMAP.
7. **Root on Samsung is the hard part** — see below.

### Samsung-specific hardening (RKP / KDP / DEFEX)

Samsung adds three EL2/Knox layers that a stock-root path fails on:

- **RKP**: hypervisor keeps page tables read-only at Stage 2; no new executable
  mappings, no kernel page-table writes, no writable-remap of kernel text.
- **KDP**: `cred` / `task_security_struct` / SELinux state live on physically
  isolated pages that are read-only to the EL1 kernel; creds must go through a
  hypervisor-validated allocator (`kdp_usecount_*`, `prepare_ro_creds`,
  `kdp_assign_pgd`). Forged creds in normal memory are rejected by the
  RKP security hooks — you *cannot* just patch your `cred` to uid 0.
- **DEFEX**: signed allowlist; intercepts syscalls, execve of root processes
  (SafePlace), credential transitions (PED), module loading. Root UID without
  an allowed binary is useless.

**How Root My Galaxy gets root anyway:**
- write `selinux_state.enforcing = 0` (single byte) to silence SELinux.
- inject a fake `work_struct` into **`system_unbound_wq`** whose `func` is
  `call_usermodehelper_exec_work`, pointing at `/data/local/tmp/cve-2026-43499-root`
  (the `su_daemon.c` helper) — the kernel executes it as uid 0 outside DEFEX's
  normal execve gates (see `src/root.c` `install_workqueue_umh_root`).
- the helper (optionally via `ksud late-load`) installs the **patched KernelSU
  module**: `kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch`
  swaps stock cred handling for KDP helpers, syncs the DEFEX credential tuple,
  and avoids live text patching on Exynos EL2 (which panics).
- root is **temporary** ("soft root"): gone on reboot, must be re-applied.

### Why only certain models work

- Snapdragon targets (S25/S24/A56/A36/S23U/etc.) with kernels 5.10/6.1/6.6:
  the pselect/waiter stack layout and offsets are per-firmware; each needs an
  exact `target.h` + `p0_fingerprint.h` (recovered from the exact firmware
  boot.img via vmlinux-to-elf + BTF, see `docs/` and `docs/PORTING.md`).
- Exynos devices are mostly excluded: PAC/BTI/SCS expand the futex stack frame
  (e.g. ~0xA70 vs pselect's 0x620 on some devices) so the reclaimed frame no
  longer overlaps — architectural blocker, not just offsets.
- S26-series ships a newer kernel where the vulnerability is fixed/immune.
- Samsung's August 2026 security patch is expected to close the window.

### Community reference ports (similar chains)

- OnePlus/OPPO locked-bootloader GhostLock ports (also pselect-based, UMH root
  via C-ashmem `misc_fops`, `PSELECT_SHIFT` tuning, ksud late-load):
  `JoinChang/ghostlock-oneplus`, `pubglite55/oppo-ghostlock`
  (Android 16, perf-based KASLR bypass), `fusiondrive/CVE-2026-43499-A36`.
- A hardened OPPO device (PLS120) defeated the chain via
  `SLAB_FREELIST_HARDENED` + MTE + CFI + `CHECKPOINT_RESTORE=n` (no
  PR_SET_MM_MAP) + blocked perf/wchan/nfulnl leaks — useful list of what
  breaks each stage.

## This repo's port at a glance

- **KernelSnitch** (`src/kernelsnitch/`): futex-hash-bucket timing side-channel
  bruteforce of `mm_struct` over the direct-map identity region
  (`KERNELSNITCH_IDENTITY_START/END`) to defeat KASLR.
- **P0 slide oracle** (`src/slide.c`, `slide_app.c`): per-firmware
  `p0_fingerprint.h` + `SLIDE_P0_OFFSET_CANDIDATES` recover the KASLR slide
  (nfnetlink_log/random_table boot_id oracle, `SLIDE_*_OFF` per target).
- **Pipe physmap R/W** (`src/pipe.c`): fake `pipe_buffer` on reclaimed
  kmalloc pages (skb/ashmem name spraying, `PIPE_*` cache shaping macros)
  → arbitrary physical read/write via the direct map.
- **fops/CFI stage** (`src/fops.c`): fake `file_operations` at
  `ASHMEM_MISC_FOPS` redirecting to `configfs_bin_write_iter` /
  `copy_splice_read` to complete the physical write chain.
- **Privesc** (`src/root.c`): forge `struct subprocess_info` work item on
  `system_unbound_wq`, flip SELinux enforcing → 0, queue
  `call_usermodehelper_exec_work` → runs `/data/local/tmp/cve-2026-43499-root`
  (`su_daemon.c`) as root; socket handshake at `/data/local/tmp/temp_su.sock`.

## Build / commands

```sh
make TARGET=essi-A566EXXSCCZG6 ANDROID_NDK_HOME=/path/to/android-ndk   # exploit payloads
make TARGET=essi-S721NKSSCDZF3 ANDROID_NDK_HOME=/path/to/android-ndk release  # release .so (truncated to 104128 B)
```

- Outputs: `build/<profile>/cve-2026-43499`, `cve-2026-43499-app.so`, `cve-2026-43499-root`
- `APP_PAYLOAD=1` compiles the app-side (physical-P0 oracle) variant.
- Known supported targets (kernel versions): S25 series 6.6.98 (device-tested),
  S24 Ultra 6.1.145 (in progress), S24+ 6.1.157 (tested), A56 6.6.102 (tested),
  A36 6.6.46 (tested), A36 SM-A366B 6.6.98 (port complete, awaiting device
  validation; see `docs/SM-A366B-A366BXXSACZF1.md`), S23 Ultra 5.15.189
  (in progress), A15 5.10.226, S24/S24FE 6.1.
- A36B CZF1 port facts: kernel `6.6.98-android15-8-33419078-abogkiA366BXXSACZF1-4k`
  (same GKI sublevel as S25/Z Fold 7 6.6.98); Image mapping
  `VA = 0xffffffc080000000 + (boot.img_offset - 0x1000)`; slide params
  `EVENT_ID 109`, `WORKER_CALLER_OFF 0x000d98e4`, `PSELECT_WORD_SHIFT 0`.

## KernelSU notes

- Modules are KernelSU v3.2.5 (commit `b0bc817b4e966aa6aa830834eaf6ef765d821d40`)
  patched for Samsung: KDP cred helpers (`kdp_usecount_dec_and_test`),
  RKP syscall-table, DEFEX cred tuple sync, no live text patching on Exynos EL2.
- Shipped as `ksud-<target>-kdp` late-load binaries embedding the `.ko`;
  vermagic must match the exact target release (e.g. `6.1.157-android14-11`).
- Generic stock KernelSU panics on Samsung (KDP `put_cred()` external abort;
  RKP/dispatcher; DEFEX; ksud staging). See `kernelsu/README.md`.

## Support feed schema (support/targets-v3.json)

- One entry per payload: `payloadId`, `displayName`, `models` (exact
  `Build.MODEL`), `kernelVersions`, `url` + `size` for exploit and KernelSU
  artifacts. `requiresFreshP0Session` disables per-boot P0 cache in the app.
- App resolves the repo's current commit, then fetches from that immutable
  commit. `targets-v2.json` retained for released 0.2.3 clients.
