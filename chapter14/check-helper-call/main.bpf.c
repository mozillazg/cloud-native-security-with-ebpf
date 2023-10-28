#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


SEC("kprobe/check_helper_call")
int BPF_KPROBE(kprobe_check_helper_call, struct bpf_verifier_env *env, struct bpf_insn *insn) {
    int func_id = (int)BPF_CORE_READ(insn, imm);
    bpf_printk("bpf helper function id %d", func_id);
    return 0;
}

char _license[] SEC("license") = "GPL";
