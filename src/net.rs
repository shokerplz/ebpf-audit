// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2025 ebpf-audit Ivan Kovalev ivan@ikovalev.nl

use crate::data::*;
use anyhow::Context;
use anyhow::Result;
use exec_skel::*;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::RingBufferBuilder;
use log::{debug, error, warn};
use rusqlite::params;
use std::mem;
use std::mem::MaybeUninit;
use std::time::Duration;
use tokio_rusqlite::Connection;

const MAX_EVENTS: usize = 1024;
const BATCH_SIZE: usize = 1024;

mod exec_skel {
    include!(concat!(env!("OUT_DIR"), "/socket_connect_skel.rs"));
}

pub struct SocketConnectProgram {
    ringbuf: libbpf_rs::RingBuffer<'static>,
    _skel: &'static mut SocketConnectSkel<'static>,
    db_conn: Connection,
    rx: tokio::sync::mpsc::Receiver<RustSocketEvent>,
}

async fn write_batch(db_conn: &Connection, batch: &mut Vec<RustSocketEvent>) {
    if batch.is_empty() {
        return;
    }

    debug!("Writing batch of {} socket events to DB", batch.len());
    let db_batch = mem::take(batch);
    let res = db_conn
        .call(move |c| {
            let tx = c.transaction()?;
            for event in &db_batch {
                tx.execute(
                    "INSERT INTO sockets_opened (timestamp, pid, comm, exe, dst_ip) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![event.timestamp, event.pid, &event.comm, &event.exe, &event.dst_ip],
                )?;
            }
            tx.commit()
        })
        .await;

    if let Err(res) = res {
        error!("Failed to write batch to DB: {}", res);
    }
}

impl SocketConnectProgram {
    pub fn new(db_conn: Connection) -> Result<Self> {
        let skel_builder = SocketConnectSkelBuilder::default();
        let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
        let open_skel = skel_builder
            .open(open_object)
            .context("Failed to open skel")?;
        let mut skel = open_skel.load().context("Failed to load skel")?;
        skel.attach().context("Failed to attach skel")?;
        let skel = Box::leak(Box::new(skel));

        let mut builder = RingBufferBuilder::new();

        let (tx, rx) = tokio::sync::mpsc::channel::<RustSocketEvent>(MAX_EVENTS);

        let callback = move |data: &[u8]| -> i32 {
            if data.len() < std::mem::size_of::<SocketEvent>() {
                warn!("Data with wrong size was sent to ring buffer");
                return 0;
            }
            let event = unsafe { &*(data.as_ptr() as *const SocketEvent) };
            let comm = unsafe { std::ffi::CStr::from_ptr(event.comm.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            let exe = unsafe { std::ffi::CStr::from_ptr(event.exe.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            let dst_ip: String = format!(
                "{}.{}.{}.{}",
                event.dst_ip[0], event.dst_ip[1], event.dst_ip[2], event.dst_ip[3]
            );

            let new_event = RustSocketEvent {
                timestamp: event.timestamp,
                pid: event.pid,
                comm,
                exe,
                dst_ip,
            };

            if tx.try_send(new_event).is_err() {
                warn!("Failed to send event to channel, buffer is full");
            }
            0
        };

        builder
            .add(&skel.maps.events, callback)
            .context("Failed to attach callback to Ringbuffer")?;
        let ringbuf = builder.build().context("Failed to build Ringbuffer")?;

        Ok(Self {
            ringbuf,
            _skel: skel,
            db_conn,
            rx,
        })
    }

    pub async fn poll(
        mut self,
        timeout: Duration,
        mut shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) {
        let mut batch = Vec::with_capacity(BATCH_SIZE);
        let batch_timeout = Duration::from_millis(500);

        loop {
            if let Err(e) = self.ringbuf.poll(timeout) {
                error!("Failed to poll ring buffer: {}", e);
            }

            while let Ok(event) = self.rx.try_recv() {
                batch.push(event);
                if batch.len() >= BATCH_SIZE {
                    write_batch(&self.db_conn, &mut batch).await;
                }
            }

            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    if !batch.is_empty() {
                        write_batch(&self.db_conn, &mut batch).await;
                    }
                    break;
                }
                _ = tokio::time::sleep(batch_timeout), if !batch.is_empty() => {
                    write_batch(&self.db_conn, &mut batch).await;
                }
            }
        }
    }
}
