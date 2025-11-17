// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2025 ebpf-audit Ivan Kovalev ivan@ikovalev.nl

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 288 * 16384);
} events SEC(".maps");

struct file_open_event {
  __u64 timestamp;
  __u32 pid;
  char comm[TASK_COMM_LEN];
  char exe[MAX_PATH_LEN];
  char path[MAX_PATH_LEN];
};


SEC("lsm/file_open")
int BPF_PROG(trace_file_open, struct file *file)
{

    struct file_open_event *event = bpf_ringbuf_reserve(&events, sizeof(struct file_open_event), 0);
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

    bpf_d_path(&file->f_path, event->path, MAX_PATH_LEN);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
