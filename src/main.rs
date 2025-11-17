// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2025 ebpf-audit Ivan Kovalev ivan@ikovalev.nl

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use std::time::Duration;
use tokio::signal;

mod data;
mod file;
mod net;
use file::TraceOpenProgram;
use net::SocketConnectProgram;

// Needed for versions less than 5.17
fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = bump_memlock_rlimit();

    let file_prog = TraceOpenProgram::new()
        .context("Failed to initialize trace open bpf")
        .unwrap();

    let net_prog = SocketConnectProgram::new()
        .context("Failed to initialize socket connect bpf")
        .unwrap();

    let trace_open_poller = tokio::spawn(file_prog.poll(Duration::from_millis(100)));
    let socket_connect_poller = tokio::spawn(net_prog.poll(Duration::from_millis(1000)));

    tokio::select! {
        _ = signal::ctrl_c() => {
            println!("Ctrl+C was pressed. Shutting down");
        }
    }

    trace_open_poller.abort();
    socket_connect_poller.abort();

    Ok(())
}
