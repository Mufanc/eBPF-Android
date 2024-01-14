#include <cstdio>
#include <string>
#include <sys/syscall.h>
#include <sys/unistd.h>
#include <sys/wait.h>
#include <linux/bpf.h>


inline int bpf(bpf_cmd cmd, const bpf_attr &attr) {
    return syscall(__NR_bpf, cmd, &attr, sizeof(attr));
}

int bpf_obj_get(const char *pathname) {
    return bpf(BPF_OBJ_GET, {
        .pathname = (uintptr_t) pathname
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


int main() {
    int mapfd = bpf_obj_get("/sys/fs/bpf/map_ebpf_demo_init_children_map");
    printf("mapfd: %d\n", mapfd);

    int *key = nullptr;

    printf("childrens of init: ");

    while (bpf_map_get_next_key(mapfd, key, key) != -1) {
#pragma clang diagnostic push
#pragma ide diagnostic ignored "NullDereference"
        printf("%d ", *key);
#pragma clang diagnostic pop
    }

    printf("\n");

    return 0;
}
