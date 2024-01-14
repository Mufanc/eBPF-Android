#define AID_ROOT 0
#define AID_SYSTEM 1000

#include "aosp/bpf_helpers.h"


struct process_fork_args {
    char _ignore[8];
    char parent_comm[16];
    int parent_pid;
    char child_comm[16];
    int child_pid;
};


struct process_exit_args {
    char _ignore[8];
    char comm[16];
    int pid;
    int prio;
};


DEFINE_BPF_MAP(init_children_map, HASH, int, int, 64);


DEFINE_BPF_PROG("tracepoint/sched/sched_process_fork", AID_ROOT, AID_SYSTEM, tp_sched_process_fork)
(struct process_fork_args *args) {
    int child_pid = args->child_pid;

    if (args->parent_pid == 1) {
        bpf_init_children_map_update_elem(&child_pid, &child_pid, 0);
    }

    return 1;
}


DEFINE_BPF_PROG("tracepoint/sched/sched_process_exit", AID_ROOT, AID_SYSTEM, tp_sched_process_exit)
(struct process_exit_args *args) {
    int pid = args->pid;

    bpf_init_children_map_delete_elem(&pid);

    return 1;
}


LICENSE("GPL");
