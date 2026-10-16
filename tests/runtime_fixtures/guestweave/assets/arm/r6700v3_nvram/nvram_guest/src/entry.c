#include <stddef.h>

extern int guest_main(void);

enum {
    SYS_EXIT = 1,
    SYS_WRITE = 4,
};

static const char MSG_BOOT[] = "[guest] entering libnvram probe\n";
static const char MSG_DONE[] = "[guest] probe finished\n";

static long sys_write(int fd, const void *buffer, unsigned long size)
{
    register long r0 __asm__("r0") = fd;
    register const void *r1 __asm__("r1") = buffer;
    register unsigned long r2 __asm__("r2") = size;
    register long r7 __asm__("r7") = SYS_WRITE;

    __asm__ volatile(
        "svc #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r7)
        : "memory");

    return r0;
}

__attribute__((noreturn))
static void sys_exit(int status)
{
    register long r0 __asm__("r0") = status;
    register long r7 __asm__("r7") = SYS_EXIT;

    __asm__ volatile(
        "svc #0"
        :
        : "r"(r0), "r"(r7)
        : "memory");

    __builtin_unreachable();
}

__attribute__((noreturn, visibility("default")))
void _start(void)
{
    sys_write(1, MSG_BOOT, sizeof(MSG_BOOT) - 1);
    (void)guest_main();
    sys_write(1, MSG_DONE, sizeof(MSG_DONE) - 1);
    sys_exit(0);
}