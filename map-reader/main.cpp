#include <android/log.h>
#include <cstdio>
#include <cstdint>
#include <dlfcn.h>
#include <linux/bpf.h>
#include <string_view>
#include <sys/unistd.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>

#define system_property_get __system_property_get
#define system_property_set __system_property_set
#define system_property_find __system_property_find
#define system_property_serial __system_property_serial
#define system_property_wait __system_property_wait

#define BPF_FS "/sys/fs/bpf"
#define PROG_NAME "ebpf_demo"


inline int bpf(bpf_cmd cmd, const bpf_attr &attr) {
    return syscall(__NR_bpf, cmd, &attr, sizeof(attr));
}

int bpf_obj_get(const char *pathname, uint32_t flags = 0) {
    return bpf(BPF_OBJ_GET, {
        .pathname = (uintptr_t) pathname,
        .file_flags = flags
    });
}

int bpf_map_get_next_key(int fd, const void *key, void *next_key) {
    return bpf(BPF_MAP_GET_NEXT_KEY, {
        .map_fd = (uint32_t) fd,
        .key = (uintptr_t) key,
        .next_key = (uintptr_t) next_key
    });
}

int bpf_map_lookup_elem(int fd, const void *key, void *value) {
    return bpf(BPF_MAP_LOOKUP_ELEM, {
        .map_fd = (uint32_t) fd,
        .key = (uintptr_t) key,
        .value = (uintptr_t) value
    });
}


extern "C" {

[[gnu::weak]] uint32_t system_property_serial(const prop_info* _Nonnull pi);

//[[gnu::weak]] int bpf_obj_get(const char *pathname);
//[[gnu::weak]] int bpf_map_get_next_key(int map_fd, const void *key, void *next_key);
//[[gnu::weak]] int bpf_map_lookup_elem(int map_fd, const void *key, void *value);
//[[gnu::weak]] int bpf_attach_tracepoint(int prog_fd, const char *category, const char *name);

}


void WaitForBpfProgsLoaded() {
    static auto prop_name = std::string_view("bpf.progs_loaded");

    char buffer[64] = {0};

    while (true) {
        const prop_info *prop = system_property_find(prop_name.data());

        if (!prop) {
            system_property_set(prop_name.data(), "0");
            continue;
        }

        system_property_get(prop_name.data(), buffer);

        if (std::string_view(buffer) == "1") {
            break;
        }

        uint32_t serial = system_property_serial(prop);
        system_property_wait(prop, serial, &serial, nullptr);
    }

    printf("bpf progs loaded.\n");
    fflush(stdout);
}


bool AttachTracepointProgram(std::string_view event_category, std::string_view event_name) {
    static void *handle = nullptr;
    static int (*bpf_attach_tracepoint)(int prog_fd, const char *category, const char *name) = nullptr;

    if (handle == nullptr) {
        handle = dlopen("libbpf_android.so", RTLD_LAZY);

        if (handle == nullptr) {
            perror("LoadAndroidBpfLibrary");
            return false;
        }

        bpf_attach_tracepoint = (decltype(bpf_attach_tracepoint)) dlsym(handle, "bpf_attach_tracepoint");

        if (bpf_attach_tracepoint == nullptr) {
            perror("DlsymBpfAttachTracepoint");
            return false;
        }
    }

    char program[128];
    sprintf(program, BPF_FS "/prog_" PROG_NAME "_tracepoint_%s_%s", event_category.data(), event_name.data());

    int prog_fd = bpf_obj_get(program);

    if (prog_fd < 0) {
        perror("RetrieveProgramFd");
        return false;
    }

    if (bpf_attach_tracepoint(prog_fd, event_category.data(), event_name.data()) < 0) {
        perror("AttachTracepoint");
        return false;
    }

    return true;
}


void ReadInitChildrenMap() {
    int mapfd = bpf_obj_get(BPF_FS "/map_" PROG_NAME "_init_children_map");
    printf("mapfd: %d\n", mapfd);

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
    for (;;) {
        int *key = nullptr;
        int count = 0;

        if (isatty(STDOUT_FILENO)) {
            printf("\r\x1b[2K");
        }

        printf("children of init: ");

        while (bpf_map_get_next_key(mapfd, key, key) != -1) {
#pragma clang diagnostic push
#pragma ide diagnostic ignored "NullDereference"
            printf("%d ", *key);
#pragma clang diagnostic pop

            count++;
        }

        printf("(%d items)", count);

        if (!isatty(STDOUT_FILENO)) {
            printf("\n");
        }

        fflush(stdout);
        sleep(1);
    }
#pragma clang diagnostic pop
}


int main() {
    WaitForBpfProgsLoaded();

    if (!AttachTracepointProgram("sched", "sched_process_fork")) {
        perror("AttachTracepointProgram(sched:sched_process_fork)");
        return 1;
    }

    if (!AttachTracepointProgram("sched", "sched_process_exit")) {
        perror("AttachTracepointProgram(sched:sched_process_exit)");
        return 1;
    }

    ReadInitChildrenMap();
}
