package com.yqsh.protector.packer.elf;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 16K page-size ELF alignment check.
 *
 * <p>Starting November 1, 2025, Google Play requires all new apps and updates
 * targeting Android 15+ to support 16 KB memory pages. A native shared library
 * is compatible when every PT_LOAD program header has {@code p_align >= 0x4000}.
 * {@code libc++_shared.so} is only 16K-aligned when built with NDK r28+;
 * project-built SOs get there via {@code -Wl,-z,max-page-size=16384}.</p>
 */
public final class ElfAlignment {
    /** 16 KB page size. */
    public static final long PAGE_16K = 0x4000L;

    private ElfAlignment() {
    }

    /**
     * Minimum {@code p_align} across all PT_LOAD segments, or {@code -1} if the
     * file has no PT_LOAD segments / cannot be parsed as ELF.
     */
    public static long minLoadAlignment(File soFile) {
        if (soFile == null || !soFile.isFile()) return -1;
        try (ReadElf elf = new ReadElf(soFile)) {
            List<Long> aligns = elf.getLoadSegmentAlignments();
            if (aligns.isEmpty()) return -1;
            long min = Long.MAX_VALUE;
            for (long a : aligns) {
                if (a < min) min = a;
            }
            return min;
        } catch (IOException | RuntimeException e) {
            return -1;
        }
    }

    /** True when every PT_LOAD segment has {@code p_align >= 0x4000}. */
    public static boolean is16kAligned(File soFile) {
        long min = minLoadAlignment(soFile);
        return min >= PAGE_16K;
    }

    /**
     * Returns the names of {@code .so} files under {@code abiDir} whose
     * PT_LOAD alignment is below 16K, as {@code "<abi>/<name> (minAlign=0x…)"}.
     */
    public static List<String> findMisaligned(File abiDir) {
        List<String> bad = new ArrayList<>();
        if (abiDir == null || !abiDir.isDirectory()) return bad;
        File[] sos = abiDir.listFiles((d, n) -> n.endsWith(".so"));
        if (sos == null) return bad;
        for (File so : sos) {
            long min = minLoadAlignment(so);
            if (min < PAGE_16K) {
                bad.add(abiDir.getName() + "/" + so.getName()
                        + " (minAlign=" + (min < 0 ? "n/a" : "0x" + Long.toHexString(min)) + ")");
            }
        }
        return bad;
    }

    /**
     * True for ELF64 files. Only 64-bit ABIs can execute on 16K-page devices
     * (AArch32/x86-32 cannot use a 16K translation granule), so the 16K
     * requirement — and the fail-fast gate — applies to 64-bit SOs only.
     */
    public static boolean is64BitElf(File soFile) {
        if (soFile == null || !soFile.isFile()) return false;
        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(soFile, "r")) {
            byte[] ident = new byte[5];
            if (raf.read(ident) != ident.length) return false;
            return ident[0] == 0x7f && ident[1] == 'E' && ident[2] == 'L'
                    && ident[3] == 'F' && ident[4] == 2;
        } catch (java.io.IOException e) {
            return false;
        }
    }

    /**
     * Fail-fast gate for shell libraries shipped by this project, 64-bit only.
     * A misaligned 64-bit shell SO (e.g. a 4K-aligned {@code libc++_shared.so}
     * from NDK &lt; r28) would crash on 16K-page devices, so refuse to continue
     * with an actionable message instead of producing a broken APK.
     * 32-bit SOs are skipped: they cannot load on 16K-page devices at all, and
     * NDK r28+ still ships their {@code libc++_shared.so} 4K-aligned.
     */
    public static void require16kAlignedIf64Bit(File soFile, String role) {
        if (!is64BitElf(soFile)) return;
        require16kAligned(soFile, role);
    }

    /**
     * Fail-fast gate for shell libraries shipped by this project. A misaligned
     * shell SO (e.g. a 4K-aligned {@code libc++_shared.so} from NDK &lt; r28)
     * would crash on 16K-page devices, so refuse to continue with an actionable
     * message instead of producing a broken APK.
     */
    public static void require16kAligned(File soFile, String role) {
        if (is16kAligned(soFile)) return;
        long min = minLoadAlignment(soFile);
        throw new IllegalStateException(
                String.format(Locale.US,
                        "%s is NOT 16K page-size aligned (min PT_LOAD p_align=%s). "
                                + "Rebuild :native with NDK r28+ (ndkVersion=\"28.2.13676358\"), "
                                + "re-run exportShellFiles, and retry. File: %s",
                        role,
                        min < 0 ? "n/a" : "0x" + Long.toHexString(min),
                        soFile == null ? "null" : soFile.getAbsolutePath()));
    }
}
