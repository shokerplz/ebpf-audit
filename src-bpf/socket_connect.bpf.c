// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2025 ebpf-audit Ivan Kovalev ivan@ikovalev.nl

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 160 * 16384);
} events SEC(".maps");

struct sock_conn_event {
  __u64 timestamp;
  __u32 pid;
  char comm[TASK_COMM_LEN];
  char exe[MAX_PATH_LEN];
  __u8 dst_ip[4];
};

SEC("lsm/socket_connect")
int BPF_PROG(inspect_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
  if (ret != 0)
  {
    return ret;
  }

  struct sock_conn_event *event = bpf_ringbuf_reserve(&events, sizeof(struct sock_conn_event), 0);
  if (!event) {
    return 0;
  }
  
  event->timestamp = bpf_ktime_get_ns();

  event->pid = bpf_get_current_pid_tgid() >> 32;
  
  bpf_get_current_comm(event->comm, TASK_COMM_LEN);

  struct task_struct *task = bpf_get_current_task_btf();
  struct mm_struct *mm = task->mm;
  
  if (mm) {
    struct file *exe_file = mm->exe_file;
    if (exe_file) {
      bpf_d_path(&exe_file->f_path, event->exe, MAX_PATH_LEN);
    }
  }

  if (address->sa_family == AF_INET) {

    u8 dst_ip[4];
    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    event->dst_ip[0] = (addr->sin_addr.s_addr << 24) >> 24;
    event->dst_ip[1] = (addr->sin_addr.s_addr >> 8) & 0xFF;
    event->dst_ip[2] = (addr->sin_addr.s_addr >> 16) & 0xFF;
    event->dst_ip[3] = addr->sin_addr.s_addr >> 24;

    bpf_ringbuf_submit(event, 0);
  } else {
    bpf_ringbuf_discard(event, 0);
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
