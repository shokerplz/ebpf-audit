// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2025 ebpf-audit Ivan Kovalev ivan@ikovalev.nl

use libc::c_char;

#[repr(C)]
#[derive(Debug)]
pub struct SocketEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub comm: [c_char; 16],
    pub exe: [c_char; 128],
    pub dst_ip: [u8; 4],
}

#[repr(C)]
#[derive(Debug)]
pub struct FileEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub comm: [c_char; 16],
    pub exe: [c_char; 128],
    pub path: [c_char; 128],
}
