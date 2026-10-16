/*
 * x86_64 IIB demo guest.
 *
 * Mirrors the ARM R6700v3 nvram demo but is fully self-contained: the
 * nvram_* functions live inside this ELF (not in a separate .so). They
 * are declared non-inline and visibility("default") so the intervention
 * can hook them at fixed VAs resolved via readelf.
 *
 * Without intervention the nvram_* bodies all "fail" (return -1 / NULL,
 * reference a nonexistent device path). The intervention stubs replace
 * them with an in-memory KV store.
 *
 * _start uses inline x86_64 syscalls (SYS_WRITE=1, SYS_EXIT=60) to keep
 * the ELF flat — no libc, no dynamic linker, no startup files. Built
 * with `-static -nostdlib -nostartfiles -ffreestanding -no-pie` so the
 * resulting image is ET_EXEC with all functions at fixed VAs.
 */

#define IFNAMSIZ 16

/* ---- inline x86_64 syscalls ---- */

enum {
    SYS_WRITE = 1,
    SYS_EXIT  = 60,
};

static long sys_write(int fd, const void *buffer, unsigned long size)
{
    long ret;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "0"((long)SYS_WRITE), "D"((long)fd), "S"(buffer), "d"(size)
        : "rcx", "r11", "memory");
    return ret;
}

__attribute__((noreturn))
static void sys_exit(int status)
{
    __asm__ volatile(
        "syscall"
        :
        : "a"((long)SYS_EXIT), "D"((long)status)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static const char MSG_BOOT[] = "[guest] entering libnvram probe\n";
static const char MSG_DONE[] = "[guest] probe finished\n";
static const char MSG_NVRAM_INIT_FAIL[] = "[guest] nvram_init fallback fired\n";

/* ---- demo observation state ---- */

struct NestedIibDemoState {
    char ifname[IFNAMSIZ];
    int guard_rc;
    int apply_rc;
    int nvram_stage_rc;
    int init_rc;
    int set_rc;
    char *value_ptr;
    int commit_rc;
};

__attribute__((used, visibility("default")))
volatile struct NestedIibDemoState g_nested_iib_demo_state;

static void store_ifname(const char *ifname)
{
    int index = 0;

    while (index < IFNAMSIZ - 1 && ifname[index] != '\0') {
        g_nested_iib_demo_state.ifname[index] = ifname[index];
        index++;
    }

    while (index < IFNAMSIZ) {
        g_nested_iib_demo_state.ifname[index] = '\0';
        index++;
    }
}

/* ---- nvram functions (stubbable by IIB intervention) ----
 *
 * Default implementations would fail in the emulator: nvram_init
 * prints a marker, nvram_get/set/commit return -1/NULL. The intervention
 * is expected to replace all four.
 */

__attribute__((noinline, used, visibility("default")))
int nvram_init(void)
{
    sys_write(1, MSG_NVRAM_INIT_FAIL, sizeof(MSG_NVRAM_INIT_FAIL) - 1);
    return -1;
}

__attribute__((noinline, used, visibility("default")))
int nvram_set(const char *name, const char *value)
{
    (void)name;
    (void)value;
    return -1;
}

__attribute__((noinline, used, visibility("default")))
char *nvram_get(const char *name)
{
    (void)name;
    return (char *)0;
}

__attribute__((noinline, used, visibility("default")))
int nvram_commit(void)
{
    return -1;
}

/* ---- demo business logic ---- */

__attribute__((noinline, used, visibility("default")))
int sync_nvram_cache(const char *key, const char *value)
{
    g_nested_iib_demo_state.init_rc = nvram_init();
    g_nested_iib_demo_state.set_rc = nvram_set(key, value);
    g_nested_iib_demo_state.value_ptr = nvram_get(key);
    g_nested_iib_demo_state.commit_rc = nvram_commit();

    if (g_nested_iib_demo_state.value_ptr != 0) {
        g_nested_iib_demo_state.nvram_stage_rc = 0;
        return 0;
    }
    if (g_nested_iib_demo_state.commit_rc != 0) {
        g_nested_iib_demo_state.nvram_stage_rc = g_nested_iib_demo_state.commit_rc;
        return g_nested_iib_demo_state.commit_rc;
    }
    if (g_nested_iib_demo_state.set_rc != 0) {
        g_nested_iib_demo_state.nvram_stage_rc = g_nested_iib_demo_state.set_rc;
        return g_nested_iib_demo_state.set_rc;
    }

    g_nested_iib_demo_state.nvram_stage_rc = g_nested_iib_demo_state.init_rc;
    return g_nested_iib_demo_state.init_rc;
}

__attribute__((noinline, used, visibility("default")))
int apply_runtime_profile(const char *ifname)
{
    int apply_rc;

    store_ifname(ifname);
    apply_rc = sync_nvram_cache("fmst_probe_key", ifname);
    g_nested_iib_demo_state.apply_rc = apply_rc;
    return apply_rc;
}

__attribute__((noinline, used, visibility("default")))
int guarded_network_startup(const char *ifname)
{
    int guard_rc;

    store_ifname(ifname);
    /*
     * Without intervention this falls straight through to
     * apply_runtime_profile. The outer hook in the intervention
     * replaces this whole function and issues native_call into
     * apply_runtime_profile, exercising the nested bidirectional flow.
     */
    guard_rc = apply_runtime_profile(ifname);
    g_nested_iib_demo_state.guard_rc = guard_rc;
    return guard_rc;
}

__attribute__((noinline, used, visibility("default")))
int guest_main(void)
{
    return guarded_network_startup("fmst0");
}

__attribute__((noreturn, visibility("default")))
void _start(void)
{
    sys_write(1, MSG_BOOT, sizeof(MSG_BOOT) - 1);
    (void)guest_main();
    sys_write(1, MSG_DONE, sizeof(MSG_DONE) - 1);
    sys_exit(0);
}
