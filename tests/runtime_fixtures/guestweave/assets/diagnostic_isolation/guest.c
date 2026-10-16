/* Freestanding x86_64 guest: stdio belongs to the guest, including after exec. */
static long call3(long n, long a, long b, long c) {
    long out;
    __asm__ volatile("syscall" : "=a"(out) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return out;
}
static long wait_child(long pid, int *status) {
    register long r10 __asm__("r10") = 0;
    long out;
    __asm__ volatile("syscall" : "=a"(out) : "a"(61), "D"(pid), "S"(status), "d"(0), "r"(r10) : "rcx", "r11", "memory");
    return out;
}
static void done(long code) { call3(60, code, 0, 0); __builtin_unreachable(); }
#define CHECK(expr, code) do { if (!(expr)) done(code); } while (0)
#define WRITE(fd, text) CHECK(call3(1, fd, (long)text, sizeof(text)-1)==sizeof(text)-1, 30)
__attribute__((used, noreturn)) static void guest_main(long *initial_stack) {
#ifdef EXPECT_QEMU_LOG_FILENAME
    const char **entry_env = (const char **)(initial_stack + initial_stack[0] + 2);
    int found = 0;
    for (; *entry_env; entry_env++) {
        const char *actual = *entry_env, *expected = EXPECT_QEMU_LOG_FILENAME;
        while (*actual && *actual == *expected) { actual++; expected++; }
        if (!*actual && !*expected) found = 1;
    }
    CHECK(found, 25);
#endif
    /* Neither a spare low fd nor a high reserved diagnostic fd is safe. */
    CHECK(call3(33, 1, 2, 0)==2, 10);
    CHECK(call3(33, 1, 128, 0)==128, 11);
    CHECK(call3(436, 3, 0xffffffffUL, 0)==0, 12); /* close_range */
    WRITE(2, "guest-stderr\n");
#ifdef CHILD
    WRITE(1, "child-body\n");
#ifdef CRASH
    *(volatile long *)0 = 7;
#endif
    done(0);
#else
#ifdef DROP_UID
    CHECK(call3(106, 12345, 0, 0)==0, 23);
    CHECK(call3(105, 12345, 0, 0)==0, 24);
#endif
#ifdef LOG_FAILURE
    CHECK(call3(82, (long)TRACE_DIR, (long)MOVED_DIR, 0)==0, 21);
    long blocker = call3(2, (long)TRACE_DIR, 1|64, 0600);
    CHECK(blocker>=0, 26);
    call3(3, blocker, 0, 0);
    WRITE(1, "during-log-failure\n");
    CHECK(call3(87, (long)TRACE_DIR, 0, 0)==0, 27);
    CHECK(call3(82, (long)MOVED_DIR, (long)TRACE_DIR, 0)==0, 22);
#endif
    static const char *argv[] = {CHILD_PATH, 0};
    static const char *env[] = {0};
    CHECK(call3(59, (long)"/missing-diagnostic-fixture", (long)argv, (long)env)==-2, 13);
    WRITE(2, "after-exec-fallback\n");
    long pid = call3(57, 0, 0, 0);
    CHECK(pid>=0, 14);
    if (!pid) {
        call3(59, (long)CHILD_PATH, (long)argv, (long)env);
        done(15);
    }
    int status = -1;
    CHECK(wait_child(pid, &status)==pid, 16);
    long result = call3(2, (long)STATUS_PATH, 1|64|512, 0600);
    CHECK(result>=0 && call3(1, result, (long)&status, sizeof(status))==sizeof(status), 19);
    call3(3, result, 0, 0);
#ifdef CRASH
    CHECK(status!=0, 17); /* QEMU may translate a guest signal into a host exit. */
#else
    CHECK(status==0, 18);
#endif
    WRITE(1, "parent-complete\n");
    done(0);
#endif
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile("mov %rsp, %rdi\n\tand $-16, %rsp\n\tcall guest_main");
}
