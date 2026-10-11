#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_elf_alignment.py — 16K page-size ELF alignment checker.

Checks that every PT_LOAD program header of each .so has p_align >= 0x4000
(16 KB), as required by Google Play for apps targeting Android 15+
(effective Nov 1, 2025).

Usage:
    python check_elf_alignment.py app.apk
    python check_elf_alignment.py path/to/lib          # extracted lib/ dir
    python check_elf_alignment.py libfoo.so libbar.so

Exit code: 0 = all aligned, 1 = at least one .so misaligned, 2 = usage error.
No NDK / readelf needed — pure-python ELF parser.
"""
import os
import struct
import sys
import tempfile
import zipfile

MIN_ALIGN = 0x4000
ELF_MAGIC = b"\x7fELF"


def load_aligns(path):
    """Return list of p_align for PT_LOAD segments. Raises on non-ELF."""
    with open(path, "rb") as f:
        ident = f.read(16)
        if ident[:4] != ELF_MAGIC:
            raise ValueError("not an ELF file")
        is64 = ident[4] == 2
        le = ident[5] == 1
        endian = "<" if le else ">"
        if is64:
            ehdr = f.read(48)  # rest of Elf64_Ehdr after e_ident
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize,
             e_phnum, _e_shentsize, _e_shnum, _e_shstrndx) = struct.unpack(
                endian + "HHIQQQIHHHHHH", ehdr)
            ph_fmt, ph_size = endian + "IIQQQQQQ", 56
        else:
            ehdr = f.read(36)  # rest of Elf32_Ehdr after e_ident
            (e_type, e_machine, e_version, e_entry, e_phoff,
             e_shoff, e_flags, e_ehsize, e_phentsize,
             e_phnum, _e_shentsize, _e_shnum, _e_shstrndx) = struct.unpack(
                endian + "HHIIIIIHHHHHH", ehdr)
            ph_fmt, ph_size = endian + "IIIIIIII", 32
        aligns = []
        for i in range(e_phnum):
            f.seek(e_phoff + i * e_phentsize)
            raw = f.read(ph_size)
            if len(raw) < ph_size:
                break
            fields = struct.unpack(ph_fmt, raw)
            p_type = fields[0]
            if p_type != 1:  # PT_LOAD
                continue
            p_align = fields[-1]
            aligns.append(p_align)
        return aligns


def check_so(path, label):
    try:
        aligns = load_aligns(path)
    except (OSError, ValueError, struct.error) as e:
        print("SKIP  %-60s (%s)" % (label, e))
        return True
    if not aligns:
        print("SKIP  %-60s (no PT_LOAD)" % label)
        return True
    ok = all(a >= MIN_ALIGN for a in aligns)
    worst = min(aligns)
    status = "OK    " if ok else "MISALIGNED"
    print("%s %-60s min_align=0x%x" % (status, label, worst))
    return ok


def collect_sos(targets):
    """Yield (path, label) for every .so found in the given targets."""
    for t in targets:
        if os.path.isfile(t):
            if t.lower().endswith(".apk") or t.lower().endswith(".zip"):
                tmp = tempfile.mkdtemp(prefix="elfalign_")
                with zipfile.ZipFile(t) as z:
                    for name in z.namelist():
                        if name.startswith("lib/") and name.endswith(".so"):
                            out = os.path.join(tmp, name.replace("/", os.sep))
                            os.makedirs(os.path.dirname(out), exist_ok=True)
                            with z.open(name) as src, open(out, "wb") as dst:
                                dst.write(src.read())
                            yield out, name
            elif t.lower().endswith(".so"):
                yield t, os.path.basename(t)
            else:
                print("SKIP  %-60s (not .apk/.so)" % t)
        elif os.path.isdir(t):
            for root, _dirs, files in os.walk(t):
                for fn in sorted(files):
                    if fn.endswith(".so"):
                        full = os.path.join(root, fn)
                        yield full, os.path.relpath(full, t)
        else:
            print("SKIP  %-60s (not found)" % t)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    total, bad = 0, 0
    for path, label in collect_sos(argv[1:]):
        total += 1
        if not check_so(path, label):
            bad += 1
    print("-" * 72)
    print("checked=%d misaligned=%d (require min PT_LOAD p_align >= 0x4000)" % (total, bad))
    if total == 0:
        print("no .so files found")
        return 2
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
