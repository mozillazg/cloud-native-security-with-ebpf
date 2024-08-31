# eBPF 云原生安全：原理与实践

<img src="cover.jpg" height=250 alt="eBPF 云原生安全：原理与实践" />


《eBPF 云原生安全：原理与实践》书中示例程序的完整源代码。


## 链接

<!-- * 豆瓣： -->
* 天猫：<https://detail.tmall.com/item.htm?id=822518924758>
* 京东：<https://item.jd.com/10111206687256.html>


## 目录


<details><summary>书籍目录：</summary>

* 前言
* 目录
* 第一部分 eBPF 助力云原生安全
  * 第 1 章 云原生安全概述
    * 1.1 云原生安全的挑战
      * 1.1.1 云原生平台基础设施的安全风险
      * 1.1.2 DevOps 软件供应链的安全风险
      * 1.1.3 云原生应用范式的安全风险
    * 1.2 云原生安全的演进
    * 1.3 云原生安全的理论基础
      * 1.3.1 威胁建模
      * 1.3.2 坚守安全准则
      * 1.3.3 安全观测和事件响应
    * 1.4 云原生安全的方法论
      * 1.4.1 CNCF 云原生安全架构
      * 1.4.2 云原生应用保护平台
    * 1.5 本章小结
  * 第 2 章 初识 eBPF
    * 2.1 eBPF 历史
    * 2.2 eBPF 的关键特性和应用场景
      * 2.2.1 Linux 内核
      * 2.2.2 eBPF 的关键特性
      * 2.2.3 eBPF 的应用场景
    * 2.3 eBPF 的架构
    * 2.4 本章小结
  * 第 3 章 eBPF 技术原理详解
    * 3.1 eBPF“Hello World”程序
    * 3.2 eBPF 技术原理
      * 3.2.1 eBPF Map 数据结构
      * 3.2.2 eBPF 虚拟机
      * 3.2.3 eBPF 验证器
      * 3.2.4 bpf() 系统调用
      * 3.2.5 eBPF 程序和附着类型
    * 3.3 eBPF 程序的开发模式
      * 3.3.1 BCC 模式
      * 3.3.2 CO-RE+ libbpf 模式
    * 3.4 本章小结
  * 第 4 章 eBPF 技术在云原生安全领域的应用
    * 4.1 针对云原生应用的攻击
    * 4.2 eBPF 和云原生安全的契合点
      * 4.2.1 容器中的基础隔离
      * 4.2.2 传统安全架构
      * 4.2.3 eBPF 提升云原生应用运行时安全
      * 4.2.4 eBPF 伴随云原生应用生命周期
    * 4.3 eBPF 云原生安全开源项目
      * 4.3.1 Falco
      * 4.3.2 Tracee
      * 4.3.3 Tetragon
    * 4.4 双刃剑
    * 4.5 本章小结
* 第二部分 云原生安全项目详解
  * 第 5 章 云原生安全项目 Falco 详解
    * 5.1 项目介绍
      * 5.1.1 功能
      * 5.1.2 使用场景
    * 5.2 安装
      * 5.2.1 使用包管理工具
      * 5.2.2 下载二进制包
      * 5.2.3 Kubernetes 环境
    * 5.3 使用示例
      * 5.3.1 规则引擎
      * 5.3.2 告警输出
      * 5.3.3 事件源
    * 5.4 架构和实现原理
      * 5.4.1 架构
      * 5.4.2 驱动
      * 5.4.3 用户态模块
    * 5.5 本章小结
  * 第 6 章 云原生安全项目 Tracee 详解
    * 6.1 项目介绍
    * 6.2 安装
    * 6.3 使用示例
      * 6.3.1 事件追踪
      * 6.3.2 制品捕获
      * 6.3.3 风险探测
      * 6.3.4 外部集成
    * 6.4 架构和实现原理
      * 6.4.1 架构
      * 6.4.2 tracee-ebpf 实现原理
    * 6.5 本章小结
  * 第 7 章 云原生安全项目 Tetragon 详解
    * 7.1 项目介绍
    * 7.2 安装
    * 7.3 使用示例
      * 7.3.1 事件观测
      * 7.3.2 风险拦截
    * 7.4 架构和实现原理
      * 7.4.1 架构
      * 7.4.2 事件观测
      * 7.4.3 风险拦截
    * 7.5 本章小结
* 第三部分 eBPF 安全技术实战
  * 第 8 章 使用 eBPF 技术审计和拦截命令执行操作
    * 8.1 审计命令执行操作
      * 8.1.1 基于 eBPF Kprobe 和 Kretprobe 实现
      * 8.1.2 基于 eBPF Fentry 和 Fexit 实现
      * 8.1.3 基于 eBPF Ksyscall 和 Kretsyscall 实现
      * 8.1.4 基于 eBPF Tracepoint 实现
    * 8.2 拦截命令执行操作
      * 8.2.1 基于 bpf_send_signal 实现
      * 8.2.2 基于 bpf_override_return 实现
    * 8.3 本章小结
  * 第 9 章 使用 eBPF 技术审计和拦截文件读写操作
    * 9.1 审计文件读写操作
      * 9.1.1 基于 eBPF Kprobe 和 Kretprobe 实现
      * 9.1.2 基于 eBPF Tracepoint 实现
      * 9.1.3 基于 eBPF LSM 实现
    * 9.2 拦截文件读写操作
      * 9.2.1 基于 bpf_send_signal 实现
      * 9.2.2 基于 bpf_override_return 实现
      * 9.2.3 基于 eBPF LSM 实现
    * 9.3 本章小结
  * 第 10 章 使用 eBPF 技术审计和拦截权限提升操作
    * 10.1 审计权限提升操作
      * 10.1.1 基于 eBPF LSM 实现
      * 10.1.2 基于 eBPF Kprobe 实现
    * 10.2 拦截权限提升操作
    * 10.3 本章小结
  * 第 11 章 使用 eBPF 技术审计和拦截网络流量
    * 11.1 审计网络流量
      * 11.1.1 基于 eBPF 套接字过滤器实现
      * 11.1.2 基于 eBPF TC 实现
      * 11.1.3 基于 eBPF XDP 实现
      * 11.1.4 基于 Kprobe 实现
    * 11.2 拦截网络流量
      * 11.2.1 基于 eBPF TC 实现
      * 11.2.2 基于 eBPF XDP 实现
    * 11.3 本章小结
  * 第 12 章 为事件关联上下文信息
    * 12.1 进程信息
      * 12.1.1 进程操作事件
      * 12.1.2 网络事件
    * 12.2 容器和 Pod 信息
      * 12.2.1 进程操作事件
      * 12.2.2 网络事件
    * 12.3 本章小结
* 第四部分 eBPF 安全进阶
  * 第 13 章 使用 eBPF 技术审计复杂的攻击手段
    * 13.1 审计使用无文件攻击技术实现的命令执行操作
    * 13.2 审计反弹 Shell 操作
    * 13.3 本章小结
  * 第 14 章 使用 eBPF 技术探测恶意eBPF 程序
    * 14.1 恶意 eBPF 程序
      * 14.1.1 常规程序
      * 14.1.2 网络程序
    * 14.2 防护恶意 eBPF 程序
    * 14.3 探测和审计恶意 eBPF 程序
      * 14.3.1 文件分析
      * 14.3.2 bpftool
      * 14.3.3 内核探测
    * 14.4 本章小结
</details>



源码目录：


| 章节   | 源代码                                                                                                                                                                                                                                                                 |
|------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 第8章 使用 eBPF 技术审计和拦截命令执行操作 | [chapter08](chapter08)                                                                                                                                                                                                                                             |
| 8.1 审计命令执行操作  | |
| 8.1.1  | [chapter08/kprobe](chapter08/kprobe)                                                                                                                                                                                                                               |
| 8.1.2 | [chapter08/fentry](chapter08/fentry)                                                                                                                                                                                                                               |
| 8.1.3 | [chapter08/ksyscall](chapter08/ksyscall)                                                                                                                                                                                                                           |
| 8.1.4 | [chapter08/tracepoint](chapter08/tracepoint)                                                                                                                                                                                                                       |
| 8.2 拦截命令执行操作  | |
| 8.2.1 | [chapter08/bpf_send_signal](chapter08/bpf_send_signal)                                                                                                                                                                                                             |
| 8.2.2 | [chapter08/bpf_override_return](chapter08/bpf_override_return)                                                                                                                                                                                                     |
| 第9章 使用 eBPF 技术审计和拦截文件读写操作 | [chapter09](chapter09)                                                                                                                                                                                                                                             |
| 9.1 审计文件读写操作  | |
| 9.1.1 | [chapter09/kprobe](chapter09/kprobe)                                                                                                                                                                                                                               |
| 9.1.2 | [chapter09/tracepoint](chapter09/tracepoint)                                                                                                                                                                                                                       |
| 9.1.3 | [chapter09/lsm](chapter09/lsm)                                                                                                                                                                                                                                     |
| 9.2 拦截文件读写操作  | |
| 9.2.1 | [chapter09/bpf_send_signal](chapter09/bpf_send_signal)                                                                                                                                                                                                             |
| 9.2.2 | [chapter09/bpf_override_return](chapter09/bpf_override_return)                                                                                                                                                                                                     |
| 9.2.3 | [chapter09/lsm-block](chapter09/lsm-block)                                                                                                                                                                                                                         |
| 第10章 使用 eBPF 技术审计和拦截权限提升操作 | [chapter10](chapter10)                                                                                                                                                                                                                                             |
| 10.1 审计权限提升操作  | |
| 10.1.1 | [chapter10/lsm-file_open](chapter10/lsm-file_open), [chapter10/lsm-bprm_check_security](chapter10/lsm-bprm_check_security)                                                                                                                                         |
| 10.1.2 | [chapter10/kprobe](chapter10/kprobe)                                                                                                                                                                                                                               |
| 10.2 拦截权限提升操作  | |
| 10.2 | [chapter10/lsm-block](chapter10/lsm-block)                                                                                                                                                                                                                         |
| 第11章 使用 eBPF 技术审计和拦截网络流量 | [chapter11](chapter11)                                                                                                                                                                                                                                             |
| 11.1 审计网络流量  | |
| 11.1.1 | [chapter11/socket-filter](chapter11/socket-filter), [chapter11/socket-filter-userspace-parse](chapter11/socket-filter-userspace-parse)                                                                                                                             |
| 11.1.2 | [chapter11/tc](chapter11/tc), [chapter11/tc-userspace-parse](chapter11/tc-userspace-parse)                                                                                                                                                                         |
| 11.1.3 | [chapter11/xdp-userspace-parse](chapter11/xdp-userspace-parse)                                                                                                                                                                                                     |
| 11.1.4 | [chapter11/kprobe](chapter11/kprobe)                                                                                                                                                                                                                               |
| 11.2 拦截网络流量  | |
| 11.2.1 | [chapter11/tc-block](chapter11/tc-block)                                                                                                                                                                                                                           |
| 11.2.2 | [chapter11/xdp-block](chapter11/xdp-block)                                                                                                                                                                                                                         |
| 第12章 为事件关联上下文信息 | [chapter12](chapter12)                                                                                                                                                                                                                                             |
| 12.1 进程信息  | |
| 12.1.1 | [chapter12/process-context](chapter12/process-context)                                                                                                                                                                                                             |
| 12.1.2 | [chapter12/net-context](chapter12/net-context)                                                                                                                                                                                                                     |
| 第13章 使用 eBPF 技术审计复杂的攻击手段 | [chapter13](chapter13)                                                                                                                                                                                                                                             |
| 13.1 审计使用无文件攻击技术实现的命令执行操作  | |
| 13.1 | [chapter13/memfd-create](chapter13/memfd-create), [chapter13/lsm-bprm_creds_from_file](chapter13/lsm-bprm_creds_from_file)                                                                                                                                         |
| 13.2 审计反弹 Shell 操作  | |
| 13.2 | [chapter13/reverse-shell](chapter13/reverse-shell)                                                                                                                                                                                                                 |
| 第14章 使用 eBPF 技术探测恶意 eBPF 程序 | [chapter14](chapter14)                                                                                                                                                                                                                                             |
| 14.1 恶意 eBPF 程序  | |
| 14.1.1 | [chapter14/read-file](chapter14/read-file), [chapter14/add-sudo](chapter14/add-sudo), [chapter14/execve-hijack](chapter14/execve-hijack), [chapter14/hide-pid](chapter14/hide-pid)                                                                                 |
| 14.1.2 | [chapter14/pipe-hijack](chapter14/pipe-hijack), [chapter14/modify-incoming-traffic](chapter14/modify-incoming-traffic), [chapter14/hide-incoming-traffic](chapter14/hide-incoming-traffic), [chapter14/hijack-tcp-to-send-data](chapter14/hijack-tcp-to-send-data) |
| 14.3 探测和审计恶意 eBPF 程序  | |
| 14.3.2 | [chapter14/inspect-ebpf-helpers](chapter14/inspect-ebpf-helpers)                                                                                                                                                                                                   |
| 14.3.3 | [chapter14/check-helper-call](chapter14/check-helper-call)                                                                                                                                                                                                         |
