# SM-S731U1 (Galaxy S25 FE) S731U1UES7BZF3 — Porting Record

First Exynos 2500 port of CVE-2026-43499 (GhostLock/IonStack). Hardware-verified root achieved twice via ADB shell. This document records every step, every mistake, and the reasoning behind each change.

## Device Identity

| Field | Value |
|---|---|
| Model | SM-S731U1 (Galaxy S25 FE, US unlocked) |
| SoC | Samsung Exynos 2500 (Cortex-X925, 10 cores) |
| Kernel | 6.1.157-android14-11 |
| Build | S731U1UES7BZF3 |
| Fingerprint | samsung/r13sue/r13s:16/BP4A.251205.006/S731U1UES7BZF3:user/release-keys |
| Android | 16 |
| RAM | 8GB (MemTotal: 7377348 kB) |
| MTE | Disabled at boot (`arm64.nomte` in kernel cmdline) |
| Security Patch | 2026-06-05 |

## Physical DRAM Layout (from bugreport)

```
Block 1: 0x080000000 - 0x0B6900000  (~870MB)  Zone DMA32
Block 2: 0x0C0400000 - 0x0C2800000  (~36MB)   Zone DMA32
Block 3: 0x0C2B00000 - 0x0E0000000  (~469MB)  Zone DMA32
Block 4: 0x0E0100000 - 0x100000000  (~511MB)  Zone DMA32
Block 5: 0x880000000 - 0x900000000  (2GB)     Zone Normal
Block 6: 0x900000000 - 0x980000000  (2GB)     Zone Normal
Block 7: 0x980000000 - 0xA00000000  (2GB)     Zone Normal
```

Zone DMA32: start_pfn=524288 (phys 0x80000000), managed=463350 pages (1.8GB)
Zone Normal: start_pfn=1048576 (phys 0x100000000), managed=1278586 pages (4.9GB)

This split-bank layout was the source of multiple porting issues.

## Starting Point

The port was templated from `r12s-S721BXXSCDZF3` (Galaxy S24 FE international, Exynos 2400, kernel 6.1.157). The r12s was chosen because it's the same product line and kernel version.

Kernel symbol offsets were extracted from the firmware using `vmlinux-to-elf` + `nm`. All offsets were cross-verified against the raw kernel Image binary:
- ashmem_fops table readback (6/6 function pointers matched)
- ASHMEM_MISC_FOPS_OFF dereference → ashmem_fops confirmed
- miscdevice.minor=255, miscdevice.name="ashmem"
- rt_mutex_waiter compact layout verified via disassembly (task@0x30, lock@0x38, prio@0x44)
- task_struct pi_lock@0x924, pi_blocked_on@0x950 confirmed
- SLIDE symbols cross-validated (boot_id ptr → sysctl_bootid)

P0 fingerprint generated via `tools/generate_p0_fingerprint.pl` at probe offset 0x1f0000.

**These kernel offsets were correct from the start and never changed.**

## Timeline of Changes — What Worked, What Didn't, and Why

### Change 1: App Timeout Fix
**Problem:** App hardcoded `P0_ATTEMPT_TIMEOUT_SEC=45` and `EXPLOIT_ATTEMPT_TIMEOUT_SEC=120`, overriding the target's 1200/2200 values.

**Log evidence:** `[+] preload supervisor ... p0_timeout=45 timeout=120` — the app's values, not the target's.

**Fix:** Changed `InstallViewModel.kt` constants to `P0_ATTEMPT_TIMEOUT_SEC=1200` and `EXPLOIT_ATTEMPT_TIMEOUT_SEC=2200`.

**Validation:** Next log showed `p0_timeout=1200 timeout=2200`. However, the binary clamps to 900 max (`preload.c:134`).

**Verdict: CORRECT.** Necessary but not sufficient.

---

### Change 2: Remove APP_RECLAIM_MAX_DIRECT_BASE (first attempt)
**Problem:** Run 3 (via app) showed 81/86 KernelSnitch pages rejected by `APP_RECLAIM_MAX_DIRECT_BASE=0xffffff8080000000`.

**Initial reasoning:** "The S25 FE has 12GB RAM in a dual-bank layout, so the limit is too low."

**What actually happened:** The device has 8GB RAM, not 12GB. The addresses in 0xffffff88 range ARE the high DRAM bank (blocks 5-7). Removing the filter was correct in principle (both mm_struct and pipe allocations use Zone Normal) but the reasoning was wrong (I assumed 12GB based on Snapdragon norms, not Exynos).

**Validation:** `/proc/zoneinfo` confirmed both allocations use Zone Normal. 23/28 working targets don't define this filter.

**Verdict: CORRECT but for the wrong reason initially.** The /proc/zoneinfo analysis later provided the definitive proof.

---

### Change 3: Rewrite to "simple path" (removing production flags)
**Problem:** Assumed the production code path (APP_PRODUCTION_*, APP_REQUIRE_FRESH_P0_SESSION, 40+ defines) was an outlier used by only 4/28 targets.

**What actually happened:** Removing the production path removed pselect sync/guard (SLIDE_SYNC_PSELECT_SYSCALL, SLIDE_GUARD_PSELECT_SYSCALL) which are REQUIRED for the pselect write window to open on Exynos.

**Log evidence:** Every pselect attempt without sync/guard returned `ret=0 window=0`. With sync/guard, `ret=2 window=1` occurred ~15-20% of the time.

**Verdict: WRONG.** The production path's pselect sync mechanisms are needed on Exynos. Re-adding them restored `window=1`. The error was assuming that the majority code path (used by Snapdragon devices) would work on Exynos without understanding WHY the production path existed.

---

### Change 4: MM_STRUCT_SZ from 0x400 to 0x3C0
**Problem:** GhostLock-Galaxy's `extract_target.py` reported `sizeof(mm_struct)=0x3C0` from BTF.

**What actually happened:** Changing to 0x3C0 broke the pipe KernelSnitch page leak. The P0 pipe setup uses `objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ` which affects the spray geometry. While 0x3C0 is the exact struct size, the exploit's spray was designed around the overestimate.

**Log evidence:** `pipe KernelSnitch sk_buff page leak failed` on every attempt with 0x3C0.

**Verdict: WRONG.** Changed back to 0x400 (original r12s value). Later tried 0x500 (GhostLock-Galaxy default) which also broke things. 0x400 is the only value that produces pselect `ret=2` windows. See MM_STRUCT_SZ analysis below.

---

### Change 5: KERNELSNITCH_MTE_ENABLED from 1 to 0
**Problem:** Bugreport showed `arm64.nomte` in kernel cmdline. Assumed MTE was disabled so KernelSnitch shouldn't use MTE tag probing.

**What actually happened:** Even with `arm64.nomte`, the kernel uses tagged pointers in the top byte. KernelSnitch's MTE-enabled path tries all 16 tag candidates (0x00-0x0F in bits [59:56]) for each address. Without MTE, it uses the exact address only — and misses because the tag bits don't match.

**Log evidence:**
- MTE=0: `found mm_struct` appeared 0 times in 20+ runs across 2 boots
- MTE=1: `found mm_struct` appeared consistently on ~50% of boots

**Verdict: WRONG.** `KERNELSNITCH_MTE_ENABLED=1` is required even on non-MTE devices. The original r12s value was correct.

---

### Change 6: SLIDE_PSELECT_WORD_SHIFT from 3 to 1
**Problem:** GhostLock-Galaxy's `extract_target.py` computed `shift=1 (derived 3 - 2)`.

**What actually happened:** The extract tool uses a different convention than the RMG codebase. In GhostLock-Galaxy, `PSELECT_WAITER_WORD_SHIFT=-2` is an ADJUSTMENT applied to a base. In RMG, `SLIDE_PSELECT_WORD_SHIFT=3` is the ABSOLUTE starting word. Both map to the same stack position:
- GhostLock-Galaxy: waiter word array starts at 2, shift=-2, global_word = -2 + waiter_word
- RMG: waiter word starts at 0, shift=3, global_word = 3 + waiter_word
- Both put tree_pc at global word 3 or equivalent

**Log evidence:** shift=1 crashed the device 3/3 times when KernelSnitch found mm_structs. shift=3 produced clean `window=0` or `window=1` without crashes.

**Verdict: WRONG.** The tool's output was for a different codebase. RMG's shift=3 was correct all along.

---

### Change 7: SKB_DATA_DELTA from -0x1000 to -0xe80
**Problem:** The essi target (Exynos S24 FE Korean) uses -0xe80. Assumed Exynos devices need -0xe80.

**What actually happened:** Changing to -0xe80 crashed the device immediately. The value is kernel-config-dependent, not SoC-dependent. The r12s (same kernel version, same Exynos family) uses -0x1000.

**Log evidence:** Device crashed on boot with -0xe80 payload. Reverted to -0x1000.

**Verdict: WRONG.** The original -0x1000 value was correct.

---

### Change 8: MCAST stack writer (MCAST_WAITER_OFF=0x68 and 0x78)
**Problem:** The pselect writer has a ~15% crash rate. MCAST is a deterministic alternative used by dm1q/dm2q/dm3q/gts9 targets.

**What actually happened:** Disassembly proved that the setsockopt call chain on kernel 6.1 is TOO DEEP relative to the futex chain. The MCAST stamp (starting at stack depth 0x340) physically cannot overlap the waiter position (at stack depth 0x1A0). The stamp covers depth 0x238-0x340, but the waiter is at 0x1A0 — a gap of 0x98 bytes.

**Calculation:**
```
Pselect fd_set: depth 0x188-0x200 → waiter at 0x1A0 → CAN reach (offset 0x60) ✓
MCAST stamp:    depth 0x238-0x340 → waiter at 0x1A0 → CANNOT reach             ✗
```

**Log evidence:** Both 0x68 and 0x78 crashed during the PI chain walk — the stamp wrote valid waiter data but at the wrong stack position, corrupting adjacent stack memory.

**Verdict: CORRECT DIAGNOSIS but ultimately IMPOSSIBLE on 6.1.** The MCAST writer only works on kernel 5.15 where the setsockopt chain is shallower. This was definitively proven by disassembly.

---

### Change 9: MM_STRUCT_SZ from 0x500 back to 0x400
**Problem:** With MM_STRUCT_SZ=0x500, the pselect window never opened — 0/18 attempts across 6 boots (all `ret=0`). With the original 0x400, windows opened.

**Analysis:** MM_STRUCT_SZ affects the KernelSnitch heap spray pattern. With 0x500: `objs_per_slab = 0x8000/0x500 = 25`. With 0x400: `objs_per_slab = 0x8000/0x400 = 32`. The spray allocates `32 * objs_per_slab` objects. The different spray count creates different slab/page allocator state, which affects whether pipe buffer pages land at the right physical addresses for the pselect timing to align.

**Log evidence:**
- 0x500: 18 pselect attempts, 0 ret=2 windows (6 boots, 90+ total runs)
- 0x400: 2 ret=2 windows in the first 4 runs on boot 8, full chain completed

**Verdict: CORRECT.** The original r12s value of 0x400 was right all along. Neither the BTF-derived 0x3C0 nor the GhostLock-Galaxy default 0x500 produces the correct heap state.

---

## Run Log Summary

### Session 1 (via app)
| Run | Config | KernelSnitch | Pselect | KASLR | Fops | Root | Notes |
|-----|--------|-------------|---------|-------|------|------|-------|
| 1 (log_10-22_10.50PM) | Original r12s template + MIN_INDEX=27 + RECLAIM_MAX=2GB | ✓ | ret=2 window=1 | ✓ slide=0x1c0000 | ✓ | FAILED: prepublish write race | Phone froze, hard reboot needed |
| 2 (log_10-22_11.16PM) | Same (after reboot) | ✗ (timeout at 45s) | N/A | N/A | N/A | N/A | All 19 attempts timed out at KernelSnitch |
| 3 (log_10-22_11.39PM) | Timeout fix applied | 81 high-mem rejections | N/A | N/A | N/A | N/A | APP_RECLAIM_MAX_DIRECT_BASE blocking |

### Session 2 (via ADB, production path, no filters)
| Run | KernelSnitch | Pselect | KASLR | Fops | Root | Notes |
|-----|-------------|---------|-------|------|------|-------|
| 6 | ✓ | ret=2 window=1 multiple | ✓ slide=0xe0000 | ✓ | **SUCCESS uid=0** | Same boot as failed runs; prior runs fragmented memory |

### Session 3 (simple path, no production flags)
| Run | KernelSnitch | Pselect | Notes |
|-----|-------------|---------|-------|
| All | ✓ or ✗ | ALL ret=0 window=0 | Simple path removed pselect sync/guard; window never opens |

### Session 4 (MCAST writer, offset 0x68)
| Run | KernelSnitch | MCAST | Notes |
|-----|-------------|-------|-------|
| 2 | ✓ | Crash | PI chain followed corrupted pointers; offset wrong |

### Session 5 (MCAST writer, offset 0x78)
| Run | KernelSnitch | MCAST | Notes |
|-----|-------------|-------|-------|
| 3 | ✓ | Crash | Same crash; MCAST proven impossible on 6.1 |

### Session 6 (production path restored, no filters)
| Run | KernelSnitch | Pselect | KASLR | Root | Notes |
|-----|-------------|---------|-------|------|-------|
| 7 (fresh boot) | ✓ | ret=2 window=1 | ✓ slide=0x1c0000 | Fops timeout | 16 fops candidates, all reclaim miss |

### Session 7 (MTE=0 + shift=3)
| Boot | Runs | KernelSnitch | Notes |
|------|------|-------------|-------|
| 1 | 10 | 0/10 | MTE=0 completely broke KernelSnitch |
| 2 | 10 | 0/10 | Same |

### Session 8 (MTE=1 + shift=1)
| Boot | KernelSnitch | Pselect | Notes |
|------|-------------|---------|-------|
| 1 | ✓ | Crash | shift=1 crashes 3/3 |
| 2 | ✓ | Crash | shift=1 definitively wrong |

### Session 9 (MTE=1 + shift=3 + MM_STRUCT_SZ=0x500)
| Boot | Runs | KernelSnitch | Pselect | Notes |
|------|------|-------------|---------|-------|
| 1 | 10 | ✓ on some | 0/3 ret=2 | No crashes, no windows |
| 2 | 10 | ✓ on some | 0/5 ret=2 | Same pattern |
| 3 | 20 | ✓ on some | 0/4 ret=2 | KernelSnitch works but window never opens |
| 4 | 5 | ✗ | N/A | Dead boot, skipped |
| 5 | 20 | ✓ active | 0/6 ret=2 | 6 pselect attempts, all ret=0 |
| 6 | 20 | ✓ active | 0/11 ret=2 | 11 attempts, all ret=0 |
| **Total** | **~90** | **36 mm_struct** | **0/18 ret=2** | **0x500 prevents pselect windows** |

### Session 10 (MTE=1 + shift=3 + MM_STRUCT_SZ=0x400) — FINAL
| Boot | Runs | KernelSnitch | Pselect | KASLR | Root | Notes |
|------|------|-------------|---------|-------|------|-------|
| 7 | 3 | ✓ | Crash (1) | N/A | N/A | One crash, expected ~15% rate |
| **8** | **4** | **✓** | **ret=2 ×4, ret=1 ×5** | **✓ slide=0x190000** | **SUCCESS uid=0** | **Full chain in 4 runs!** |

## Final Working Configuration

```c
#define MM_STRUCT_SZ 0x400                    // NOT 0x3C0 (BTF) or 0x500 (default)
#define KERNELSNITCH_MTE_ENABLED 1            // Required even with arm64.nomte
#define SLIDE_PSELECT_WORD_SHIFT 3            // NOT 1 (GhostLock-Galaxy convention differs)
// NO APP_RECLAIM_MAX_DIRECT_BASE             // Both zones allocate from Normal
// Full production path with:
//   APP_REQUIRE_FRESH_P0_SESSION 1
//   SLIDE_SYNC_PSELECT_SYSCALL 1
//   SLIDE_GUARD_PSELECT_SYSCALL 1
//   All APP_PRODUCTION_* flags from r12s
```

## Key Lessons

1. **Don't template from a different SoC family.** r12s (Exynos 2400) was the right kernel version but tuning parameters are SoC-specific. GhostLock-Galaxy (Snapdragon 6.1.145) conventions don't map directly to the RMG codebase.

2. **MTE tag probing matters even on non-MTE devices.** The kernel stores metadata in pointer top bytes regardless of `arm64.nomte`. KernelSnitch needs all 16 tag candidates.

3. **MM_STRUCT_SZ affects more than just the struct size.** It controls the heap spray geometry, which determines physical page placement, which determines pselect timing alignment. The "correct" BTF value (0x3C0) and the "default" value (0x500) both break the chain. Only the original r12s value (0x400) works.

4. **The production pselect path is required on Exynos.** Sync/guard mechanisms ensure pselect is blocked in `do_select` before triggering `sched_setattr`. Without them, the timing never aligns on Exynos 2500.

5. **MCAST feasibility is kernel-version-dependent.** The setsockopt call chain depth on 6.1 makes it physically impossible for the stamp to overlap the waiter's stack position. This was proven by disassembly, not guessing.

6. **The pselect crash rate (~15%) is inherent.** It matches issue-241 reports from other 6.1 Exynos users ("1 in 15 tries"). The extract_target.py warning explains it: `wake_state falls outside the copied fd_set and relies on the kernel zero-initialising it`.

7. **Use /proc/zoneinfo, not assumptions, for reclaim analysis.** The DRAM physical layout and zone configuration determine whether the reclaim spray can reach freed pages.

8. **Read other projects' code, not just their parameters.** The GhostLock-Galaxy `extract_target.py` provided critical insights (MCAST feasibility, pselect geometry) that hours of parameter guessing couldn't.

## Verification Commands

```bash
# Push payloads
adb push cve-2026-43499-app.so /data/local/tmp/s25fe.so
adb push cve-2026-43499-root /data/local/tmp/cve-2026-43499-root
adb push ksud-samsung-android14-6.1-kdp /data/local/tmp/ksud-s25u-kdp
adb shell "chmod 755 /data/local/tmp/cve-2026-43499-root /data/local/tmp/ksud-s25u-kdp"

# Run (expect multiple attempts across boots)
adb shell "EXPLOIT_ATTEMPTS=1 P0_ATTEMPT_TIMEOUT_SEC=600 \
  EXPLOIT_ATTEMPT_TIMEOUT_SEC=900 \
  /data/local/tmp/cve-2026-43499-root --run-payload \
  /data/local/tmp/s25fe.so /data/local/tmp/cve-2026-43499-root \
  /data/local/tmp/s25fe.log"

# Verify root
adb shell "/data/local/tmp/cve-2026-43499-root -c 'id; getenforce'"
# Expected: uid=0(root) gid=0(root) context=u:r:kernel:s0 / Permissive

# KernelSU late-load
adb shell "/data/local/tmp/cve-2026-43499-root --late-load"
adb shell "su -c id"
# Expected: uid=0(root) context=u:r:ksu:s0
```

## Authorship

Port, analysis, and documentation prepared with Claude Code assistance. Hardware execution and logs by @rtrdd-dev. SM-S731U1 S731U1UES7BZF3 is the first Exynos 2500 device target in this repository.
