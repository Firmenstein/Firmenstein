/* Generic freestanding x86_64 TCP guest for Runner child attribution. */
static long call3(long n, long a, long b, long c) {
    long out;
    __asm__ volatile("syscall" : "=a"(out) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return out;
}
static void done(long code) { call3(60, code, 0, 0); __builtin_unreachable(); }
#define CHECK(expr, code) do { if (!(expr)) done(code); } while (0)
#define WRITE(fd, text) CHECK(call3(1, fd, (long)text, sizeof(text)-1)==sizeof(text)-1, 30)

struct address {
    unsigned short family;
    unsigned short port;
    unsigned int ipv4;
    char padding[8];
};

__attribute__((used, noreturn)) static void guest_main(void) {
    /* AF_INET / SOCK_STREAM; 0xA046 stores network-order port 18080 on LE. */
    struct address address = {2, 0xa046, 0, {0}};
    long server = call3(41, 2, 1, 0);
    CHECK(server >= 0, 10);
    CHECK(call3(49, server, (long)&address, sizeof(address)) == 0, 11);
    CHECK(call3(50, server, 8, 0) == 0, 12);
#ifdef UNRELATED_CRASH
    long unrelated = call3(57, 0, 0, 0);
    CHECK(unrelated >= 0, 13);
    if (unrelated == 0) {
        *(volatile long *)0 = 1;
        done(14);
    }
#endif
    for (;;) {
        long client = call3(43, server, 0, 0);
        CHECK(client >= 0, 15);
        long child = call3(57, 0, 0, 0);
        CHECK(child >= 0, 16);
        if (child == 0) {
            CHECK(call3(33, client, 0, 0) == 0, 17);
            CHECK(call3(33, client, 1, 0) == 1, 18);
            call3(3, client, 0, 0);
            char request[128];
            CHECK(call3(0, 0, (long)request, sizeof(request)) > 0, 19);
#ifdef REQUEST_CRASH
            WRITE(1, "HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\npartial page");
            *(volatile long *)0 = 7;
#else
            WRITE(1, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK");
#endif
            done(0);
        }
        call3(3, client, 0, 0);
    }
}

__attribute__((naked, noreturn)) void _start(void) {
    __asm__ volatile("and $-16, %rsp\n\tcall guest_main");
}
