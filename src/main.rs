// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2025 ebpf-audit Ivan Kovalev ivan@ikovalev.nl

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use env_logger::Env;
use file::TraceOpenProgram;
use log::info;
use net::SocketConnectProgram;
use std::time::Duration;
use tokio::signal;
use tokio_rusqlite::Connection;

mod data;
mod file;
mod net;

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
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stdout)
        .init();

    let conn = Connection::open("result.db").await?;

    conn.call(|c| {
        let tx = c.transaction()?;
        tx.execute(
            "create table if not exists files_opened (timestamp integer, pid integer, comm text, exe text, path text, PRIMARY KEY (timestamp, pid, path))",
            [],
        )?;
        tx.execute(
            "create table if not exists sockets_opened (timestamp integer, pid integer, comm text, exe text, dst_ip text, PRIMARY KEY (timestamp, pid, dst_ip))",
            [],
        )?;
        tx.commit()
    })
    .await?;

    bump_memlock_rlimit()?;

    let file_prog =
        TraceOpenProgram::new(conn.clone()).context("Failed to initialize trace open bpf")?;

    let net_prog =
        SocketConnectProgram::new(conn.clone()).context("Failed to initialize socket connect bpf")?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    let trace_open_poller =
        tokio::spawn(file_prog.poll(Duration::from_millis(50), shutdown_rx.clone()));
    let socket_connect_poller =
        tokio::spawn(net_prog.poll(Duration::from_millis(1000), shutdown_rx.clone()));

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Ctrl+C was pressed. Shutting down");
            let _ = shutdown_tx.send(());
        }
    }

    let _ = tokio::join!(trace_open_poller, socket_connect_poller);

    Ok(())
}
