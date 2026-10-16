/* Freestanding x86_64 Linux guest. No firmware names, libc, or network. */
static long call3(long n, long a, long b, long c) {
    long out;
    __asm__ volatile("syscall" : "=a"(out) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return out;
}
static long call4(long n, long a, long b, long c, long d) {
    register long r10 __asm__("r10") = d;
    long out;
    __asm__ volatile("syscall" : "=a"(out) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return out;
}
static void done(long status) { call3(60, status, 0, 0); __builtin_unreachable(); }
#define CHECK(test, code) do { if (!(test)) done(code); } while (0)
static char buf[16];
long data_marker = 7;
#ifndef CHILD
__attribute__((noinline)) long native_answer(void) { return 0x5a; }
__attribute__((noinline)) long probe_hook(void) { return -1; }
#endif
void _start(void) {
#ifdef CHILD
    /* Duplicates of one OFD must share both inherited data and cursor. */
    CHECK(call3(0, 7, (long)buf, 1) == 1 && buf[0] == 'Y', 31);
    CHECK(call3(0, 8, (long)buf, 1) == 1 && buf[0] == 'Z', 32);
    CHECK(call3(8, 7, 0, 0) == 0, 33);
    CHECK(call3(0, 8, (long)buf, 3) == 3 && buf[0]=='X' && buf[1]=='Y' && buf[2]=='Z', 34);
    CHECK(call3(0, 9, (long)buf, 1) == -9, 35); /* CLOEXEC */
    long fresh = call3(2, (long)"/dev/contract-state", 0, 0);
    CHECK(fresh >= 0, 36);
    CHECK(call3(0, fresh, (long)buf, 1)==1 && buf[0]=='I', 37); /* new OFD */
    long file = call3(2, (long)FILE_PATH, 0, 0);
    CHECK(file >= 0 && call3(0, file, (long)buf, 1)==1 && buf[0]=='F', 38);
    CHECK(call3(1, 1, (long)"contract-child-ok\n", 18)==18, 39);
    done(0);
#else
    CHECK(probe_hook() == 0x5a, 11); /* native call + invalid data target check */
    long fd = call3(2, (long)"/dev/contract-state", 2 | 0x80000, 0);
    CHECK(fd >= 0, 12);
    CHECK(call3(1, fd, (long)"XYZ", 3)==3, 13);
    CHECK(call3(8, fd, 1, 0)==1, 14);
    CHECK(call3(33, fd, 7, 0)==7 && call3(33, fd, 8, 0)==8, 15);
    CHECK(call3(33, fd, 9, 0)==9 && call3(72, 9, 2, 1)==0, 16);
    long file = call3(2, (long)FILE_PATH, 1|64|512, 0600);
    CHECK(file >= 0 && call3(1, file, (long)"F", 1)==1, 17);
    CHECK(call3(3, file, 0, 0)==0, 18);
#ifdef FORK_CHILD
    long pid = call3(57, 0, 0, 0);
    CHECK(pid >= 0, 19);
    if (pid) {
        int status = -1;
        CHECK(call4(61, pid, (long)&status, 0, 0)==pid && status==0, 20);
        done(0);
    }
#endif
    static const char *argv[] = {CHILD_PATH, 0};
    static const char *env[] = {0};
    call3(59, (long)CHILD_PATH, (long)argv, (long)env);
    done(21);
#endif
}
