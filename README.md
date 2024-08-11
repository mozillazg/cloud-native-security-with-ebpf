# cloud-native-security-with-ebpf

《eBPF 云原生安全：原理与实践》书中示例程序的完整源代码。


## 链接

* 豆瓣：
* 京东：
* 天猫：
* 当当：


## 目录

| 章节   | 目录                                                                                                                                                                                                                                                                 |
|------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 第8章  | [chapter08](chapter08)                                                                                                                                                                                                                                             |
| 8.1.1 | [chapter08/kprobe](chapter08/kprobe)                                                                                                                                                                                                                               |
| 8.1.2 | [chapter08/fentry](chapter08/fentry)                                                                                                                                                                                                                               |
| 8.1.3 | [chapter08/ksyscall](chapter08/ksyscall)                                                                                                                                                                                                                           |
| 8.1.4 | [chapter08/tracepoint](chapter08/tracepoint)                                                                                                                                                                                                                       |
| 8.2.1 | [chapter08/bpf_send_signal](chapter08/bpf_send_signal)                                                                                                                                                                                                             |
| 8.2.2 | [chapter08/bpf_override_return](chapter08/bpf_override_return)                                                                                                                                                                                                     |
| 第9章  | [chapter09](chapter09)                                                                                                                                                                                                                                             |
| 9.1.1 | [chapter09/kprobe](chapter09/kprobe)                                                                                                                                                                                                                               |
| 9.1.2 | [chapter09/tracepoint](chapter09/tracepoint)                                                                                                                                                                                                                       |
| 9.1.3 | [chapter09/lsm](chapter09/lsm)                                                                                                                                                                                                                                     |
| 9.2.1 | [chapter09/bpf_send_signal](chapter09/bpf_send_signal)                                                                                                                                                                                                             |
| 9.2.2 | [chapter09/bpf_override_return](chapter09/bpf_override_return)                                                                                                                                                                                                     |
| 9.2.3 | [chapter09/lsm-block](chapter09/lsm-block)                                                                                                                                                                                                                         |
| 第10章 | [chapter10](chapter10)                                                                                                                                                                                                                                             |
| 10.1.1 | [chapter10/lsm-file_open](chapter10/lsm-file_open), [chapter10/lsm-bprm_check_security](chapter10/lsm-bprm_check_security)                                                                                                                                         |
| 10.1.2 | [chapter10/kprobe](chapter10/kprobe)                                                                                                                                                                                                                               |
| 10.2 | [chapter10/lsm-block](chapter10/lsm-block)                                                                                                                                                                                                                         |
| 第11章 | [chapter11](chapter11)                                                                                                                                                                                                                                             |
| 11.1.1 | [chapter11/socket-filter](chapter11/socket-filter), [chapter11/socket-filter-userspace-parse](chapter11/socket-filter-userspace-parse)                                                                                                                             |
| 11.1.2 | [chapter11/tc](chapter11/tc), [chapter11/tc-userspace-parse](chapter11/tc-userspace-parse)                                                                                                                                                                         |
| 11.1.3 | [chapter11/xdp-userspace-parse](chapter11/xdp-userspace-parse)                                                                                                                                                                                                     |
| 11.1.4 | [chapter11/kprobe](chapter11/kprobe)                                                                                                                                                                                                                               |
| 11.2.1 | [chapter11/tc-block](chapter11/tc-block)                                                                                                                                                                                                                           |
| 11.2.2 | [chapter11/xdp-block](chapter11/xdp-block)                                                                                                                                                                                                                         |
| 第12章 | [chapter12](chapter12)                                                                                                                                                                                                                                             |
| 12.1.1 | [chapter12/process-context](chapter12/process-context)                                                                                                                                                                                                             |
| 12.1.2 | [chapter12/net-context](chapter12/net-context)                                                                                                                                                                                                                     |
| 第13章 | [chapter13](chapter13)                                                                                                                                                                                                                                             |
| 13.1 | [chapter13/memfd-create](chapter13/memfd-create), [chapter13/lsm-bprm_creds_from_file](chapter13/lsm-bprm_creds_from_file)                                                                                                                                         |
| 13.2 | [chapter13/reverse-shell](chapter13/reverse-shell)                                                                                                                                                                                                                 |
| 第14章 | [chapter14](chapter14)                                                                                                                                                                                                                                             |
| 14.1.1 | [chapter14/read-file](chapter14/read-file), [chapter14/add-sudo](chapter14/add-sudo), [chapter14/execve-hijack](chapter14/execve-hijack), [chapter14/hide-pid](chapter14/hide-pid)                                                                                 |
| 14.1.2 | [chapter14/pipe-hijack](chapter14/pipe-hijack), [chapter14/modify-incoming-traffic](chapter14/modify-incoming-traffic), [chapter14/hide-incoming-traffic](chapter14/hide-incoming-traffic), [chapter14/hijack-tcp-to-send-data](chapter14/hijack-tcp-to-send-data) |
| 14.3.2 | [chapter14/inspect-ebpf-helpers](chapter14/inspect-ebpf-helpers)                                                                                                                                                                                                   |
| 14.3.3 | [chapter14/check-helper-call](chapter14/check-helper-call)                                                                                                                                                                                                         |
