#include "common/elf_util.h"
#include "common/log.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <new>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace protector {

/** Bypass libc fopen hooks (business_so may spoof /proc/self/maps for OSG). */
// XOP 2026-10-11: fopen_maps_raw removed — fdopen() traps fdsan on Android 17
// during the loadLibrary window. Use maps_raw_open()/read_maps_record(MapsRawFile*).

// ---- raw (stdio-free) maps reader -----------------------------------------
// Android 17 traps fdsan during the System.loadLibrary window: fopen() AND
// fdopen() both call android_fdsan_exchange_owner_tag, which resolves through
// the linker's __loader_shared_globals trap stub (SIGILL). Early-startup code
// must read /proc files with raw read() only.

MapsRawFile* maps_raw_open() {
    int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, "/proc/self/maps",
                                      O_RDONLY | O_CLOEXEC));
    if (fd < 0) return nullptr;
    MapsRawFile* mf = new (std::nothrow) MapsRawFile();
    if (mf == nullptr) { close(fd); return nullptr; }
    mf->fd = fd;
    return mf;
}

void maps_raw_close(MapsRawFile* mf) {
    if (mf == nullptr) return;
    // XOP 2026-10-11: libc close() goes through android_fdsan_close_with_tag
    // which traps via __loader_shared_globals on Android 17 inside the
    // loadLibrary/JNI_OnLoad window. Raw syscall only.
    if (mf->fd >= 0) {
#if defined(__NR_close)
        syscall(__NR_close, mf->fd);
#else
        close(mf->fd);
#endif
    }
    delete mf;
}

bool read_maps_record(MapsRawFile* mf, std::string* line) {
    if (mf == nullptr || mf->fd < 0 || line == nullptr) return false;
    line->clear();
    for (;;) {
        size_t nl = mf->buf.find('\n');
        if (nl != std::string::npos) {
            line->append(mf->buf, 0, nl + 1);
            mf->buf.erase(0, nl + 1);
            return true;
        }
        if (mf->eof) {
            if (mf->buf.empty()) return false;
            line->append(mf->buf);
            mf->buf.clear();
            return true;
        }
        char chunk[8192];
        ssize_t r = read(mf->fd, chunk, sizeof(chunk));
        if (r < 0) {
            if (errno == EINTR) continue;
            mf->eof = true;
            continue;
        }
        if (r == 0) {
            mf->eof = true;
            continue;
        }
        mf->buf.append(chunk, static_cast<size_t>(r));
    }
}

bool read_maps_record(FILE* fp, std::string* line) {
    if (fp == nullptr || line == nullptr) return false;
    line->clear();
    char chunk[4096];
    while (fgets(chunk, sizeof(chunk), fp) != nullptr) {
        line->append(chunk);
        if (!line->empty() && line->back() == '\n') return true;
        if (line->size() >= static_cast<size_t>(PATH_MAX) + 256) {
            int c = 0;
            while ((c = fgetc(fp)) != EOF && c != '\n') {}
            if (line->empty() || line->back() != '\n') line->push_back('\n');
            return true;
        }
    }
    return !line->empty();
}

bool maps_pathname(const std::string& line, std::string* path) {
    if (path == nullptr) return false;
    path->clear();
    const char* s = line.c_str();
    for (int field = 0; field < 5; ++field) {
        while (*s == ' ' || *s == '\t') ++s;
        if (*s == '\0' || *s == '\n') return false;
        while (*s != '\0' && *s != ' ' && *s != '\t' && *s != '\n') ++s;
    }
    while (*s == ' ' || *s == '\t') ++s;
    if (*s == '\0' || *s == '\n') return false;
    const char* end = s;
    while (*end != '\0' && *end != '\n' && *end != '\r') ++end;
    while (end > s && (end[-1] == ' ' || end[-1] == '\t')) --end;
    static constexpr char kDeleted[] = " (deleted)";
    constexpr size_t kDeletedLen = sizeof(kDeleted) - 1;
    if (static_cast<size_t>(end - s) >= kDeletedLen
            && memcmp(end - kDeletedLen, kDeleted, kDeletedLen) == 0) {
        end -= kDeletedLen;
        while (end > s && (end[-1] == ' ' || end[-1] == '\t')) --end;
    }
    size_t n = static_cast<size_t>(end - s);
    if (n >= static_cast<size_t>(PATH_MAX)) n = static_cast<size_t>(PATH_MAX) - 1;
    path->assign(s, n);
    return !path->empty();
}

std::string find_so_path(const char* so_name) {
    if (so_name == nullptr || so_name[0] == 0) return {};
    MapsRawFile* fp = maps_raw_open();
    if (!fp) return {};

    // Prefer protector so_plain mirror (plaintext) over /data/app packaged ciphertext.
    std::string plain_hit;
    std::string any_hit;
    std::string line;
    int lines = 0;
    while (read_maps_record(fp, &line) && lines++ < 10000) {
        std::string path;
        if (!maps_pathname(line, &path)) continue;
        const char* base = strrchr(path.c_str(), '/');
        base = base != nullptr ? base + 1 : path.c_str();
        if (strcmp(base, so_name) != 0) continue;
        if (path.find("/lib_mirror/") != std::string::npos
                || path.find("/so_plain/") != std::string::npos) {
            plain_hit = std::move(path);
            break;
        }
        if (any_hit.empty()) any_hit = std::move(path);
    }
    maps_raw_close(fp);
    return !plain_hit.empty() ? plain_hit : any_hit;
}

void get_elf_section(Elf_Shdr* target, const char* elf_path, const char* sh_name) {
    if (target == nullptr || elf_path == nullptr || sh_name == nullptr) return;
    memset(target, 0, sizeof(Elf_Shdr));

    FILE* fp = fopen(elf_path, "rb");
    if (!fp) {
        PLOGW("cannot open elf: %s", elf_path);
        return;
    }

    Elf_Ehdr ehdr{};
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)
        || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0
        || ehdr.e_shoff == 0
        || ehdr.e_shentsize != sizeof(Elf_Shdr)
        || ehdr.e_shnum == 0) {
        fclose(fp);
        return;
    }

    if (fseek(fp, static_cast<long>(ehdr.e_shoff), SEEK_SET) != 0) {
        fclose(fp);
        return;
    }
    std::vector<Elf_Shdr> shdrs(ehdr.e_shnum);
    if (fread(shdrs.data(), sizeof(Elf_Shdr), ehdr.e_shnum, fp) != ehdr.e_shnum) {
        fclose(fp);
        return;
    }

    if (ehdr.e_shstrndx >= ehdr.e_shnum) {
        fclose(fp);
        return;
    }
    const Elf_Shdr& shstr = shdrs[ehdr.e_shstrndx];
    if (shstr.sh_size == 0 || shstr.sh_size > 1024 * 1024) {
        fclose(fp);
        return;
    }
    std::vector<char> shstrtab(shstr.sh_size);
    if (fseek(fp, static_cast<long>(shstr.sh_offset), SEEK_SET) != 0
        || fread(shstrtab.data(), 1, shstr.sh_size, fp) != shstr.sh_size) {
        fclose(fp);
        return;
    }
    fclose(fp);

    for (const auto& sh : shdrs) {
        if (sh.sh_name >= shstr.sh_size) continue;
        const char* name = shstrtab.data() + sh.sh_name;
        if (strcmp(name, sh_name) == 0) {
            *target = sh;
            PLOGD("found section %s size=%u", sh_name, static_cast<unsigned>(sh.sh_size));
            return;
        }
    }
    PLOGW("section not found: %s in %s", sh_name, elf_path);
}

bool get_first_pt_load_vaddr(const char* elf_path, uint64_t* out_vaddr) {
    if (elf_path == nullptr || out_vaddr == nullptr) return false;
    *out_vaddr = 0;
    FILE* fp = fopen(elf_path, "rb");
    if (!fp) return false;
    Elf_Ehdr ehdr{};
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)
        || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0
        || ehdr.e_phoff == 0
        || ehdr.e_phentsize != sizeof(Elf_Phdr)
        || ehdr.e_phnum == 0) {
        fclose(fp);
        return false;
    }
    if (fseek(fp, static_cast<long>(ehdr.e_phoff), SEEK_SET) != 0) {
        fclose(fp);
        return false;
    }
    bool found = false;
    uint64_t min_vaddr = UINT64_MAX;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf_Phdr ph{};
        if (fread(&ph, 1, sizeof(ph), fp) != sizeof(ph)) break;
        if (ph.p_type != PT_LOAD) continue;
        if (ph.p_vaddr < min_vaddr) {
            min_vaddr = ph.p_vaddr;
            found = true;
        }
    }
    fclose(fp);
    if (!found) return false;
    *out_vaddr = min_vaddr;
    return true;
}

bool find_so_load_bias(const char* so_name, uintptr_t* out_bias) {
    if (so_name == nullptr || so_name[0] == 0 || out_bias == nullptr) return false;
    std::string path = find_so_path(so_name);
    if (path.empty()) return false;

    MapsRawFile* fp = maps_raw_open();
    if (!fp) return false;
    uintptr_t map_start = 0;
    bool found_map = false;
    std::string line;
    while (read_maps_record(fp, &line)) {
        // Prefer exact path match for the resolved ELF (so_plain over packaged).
        bool path_hit = !path.empty() && line.find(path) != std::string::npos;
        if (!path_hit) continue;
        if (line.find('/') == std::string::npos) continue;
        unsigned long start = 0;
        if (sscanf(line.c_str(), "%lx-", &start) == 1) {
            map_start = static_cast<uintptr_t>(start);
            found_map = true;
            break;
        }
    }
    maps_raw_close(fp);
    if (!found_map) return false;

    uint64_t p_vaddr = 0;
    if (!get_first_pt_load_vaddr(path.c_str(), &p_vaddr)) {
        *out_bias = map_start; // best-effort fallback
        return true;
    }
    *out_bias = map_start - static_cast<uintptr_t>(p_vaddr);
    return true;
}

} // namespace protector
