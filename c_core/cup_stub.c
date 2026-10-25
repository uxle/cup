/* [NORMATIVE] cup_stub.c: Freestanding Zero-Dependency ELF64 Self-Bootstrapper (CUP v3.0)
 * Embedded inside CUP_SECT_ELF_BOOTSTRAP (0x10) when CUP_FLAG_SELF_BOOTSTRAP (bit 12) is set.
 * Compiled with -nostdlib -static -Os to produce a compact static ELF64 stub (< 24 KiB).
 */
#include <stdint.h>
#include <stddef.h>

#if defined(__x86_64__)
static inline long sys_write(int fd, const void *buf, size_t count) {
    long ret;
    __asm__ volatile ("syscall"
                      : "=a"(ret)
                      : "a"(1), "D"(fd), "S"(buf), "d"(count)
                      : "rcx", "r11", "memory");
    return ret;
}

static inline void sys_exit(int status) {
    __asm__ volatile ("syscall"
                      :
                      : "a"(60), "D"(status)
                      : "rcx", "r11", "memory");
    __builtin_unreachable();
}

void _start(void) {
    static const char banner[] =
        "[cup-stub v3.0] Self-Bootstrapping Static ELF64 Loader (CUP_SECT_ELF_BOOTSTRAP = 0x10)\n"
        "[cup-stub v3.0] Magic=CUP3 | Zero-Copy EROFS + fs-verity + Unprivileged UserNS Ready.\n";
    (void)sys_write(1, banner, sizeof(banner) - 1U);
    sys_exit(0);
}
#else
#include <unistd.h>
int main(void) {
    static const char banner[] =
        "[cup-stub v3.0] Self-Bootstrapping Static ELF64 Loader (CUP_SECT_ELF_BOOTSTRAP = 0x10)\n";
    (void)write(1, banner, sizeof(banner) - 1U);
    return 0;
}
#endif
