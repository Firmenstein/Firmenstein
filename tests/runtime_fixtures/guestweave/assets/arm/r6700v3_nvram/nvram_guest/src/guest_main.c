#include "libnvram_abi.h"

#define IFNAMSIZ 16
#define AF_INET 2
#define SOCK_DGRAM 2
#define SIOCGIFFLAGS 0x8913UL

int socket(int domain, int type, int protocol);
int ioctl(int fd, unsigned long request, ...);
int close(int fd);

struct FmstIfreq {
    char ifr_name[IFNAMSIZ];
    union {
        short flags;
        char raw[24];
    } ifr_ifru;
};

struct NestedIibDemoState {
    char ifname[IFNAMSIZ];
    int guard_rc;
    int ioctl_socket_fd;
    int ioctl_rc;
    unsigned short ioctl_flags;
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

__attribute__((noinline, used, visibility("default")))
int firmware_netif_ioctl_precheck(const char *ifname)
{
    struct FmstIfreq ifreq = {0};
    int index = 0;
    int socket_fd;
    int ioctl_rc;

    while (index < IFNAMSIZ - 1 && ifname[index] != '\0') {
        ifreq.ifr_name[index] = ifname[index];
        index++;
    }

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    g_nested_iib_demo_state.ioctl_socket_fd = socket_fd;
    if (socket_fd < 0) {
        g_nested_iib_demo_state.ioctl_rc = socket_fd;
        return socket_fd;
    }

    ioctl_rc = ioctl(socket_fd, SIOCGIFFLAGS, &ifreq);
    g_nested_iib_demo_state.ioctl_rc = ioctl_rc;
    if (ioctl_rc >= 0) {
        g_nested_iib_demo_state.ioctl_flags = (unsigned short)ifreq.ifr_ifru.flags;
    }

    close(socket_fd);
    return ioctl_rc;
}

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
    guard_rc = firmware_netif_ioctl_precheck(ifname);
    g_nested_iib_demo_state.guard_rc = guard_rc;
    if (guard_rc < 0) {
        return guard_rc;
    }

    return apply_runtime_profile(ifname);
}

int guest_main(void)
{
    return guarded_network_startup("fmst0");
}