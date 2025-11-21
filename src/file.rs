// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2025 ebpf-audit Ivan Kovalev ivan@ikovalev.nl

use anyhow::Context;
use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder as _;
use log::{warn, error};
use std::process;
use std::mem::ManuallyDrop;
use std::mem::MaybeUninit;
use std::time::Duration;
use tokio_rusqlite::Connection;
use rusqlite::params;

use crate::data::*;

mod exec_skel {
    include!(concat!(env!("OUT_DIR"), "/trace_open_skel.rs"));
}

use exec_skel::*;

pub struct TraceOpenProgram<'obj> {
    ringbuf: libbpf_rs::RingBuffer<'obj>,
    _skel: ManuallyDrop<TraceOpenSkel<'obj>>,
    db_conn: Connection,
    rx: tokio::sync::mpsc::UnboundedReceiver<RustFileEvent>,
}

impl<'obj> TraceOpenProgram<'obj> {
    pub fn new(db_conn: Connection) -> Result<Self> {
        let skel_builder = TraceOpenSkelBuilder::default();
        let mut open_object = Box::new(MaybeUninit::uninit());
        let skel = {
            let open_skel = skel_builder
                .open(&mut *open_object)
                .context("Failed to open skel")?;

            open_skel.maps.rodata_data.PID_TARGET = process::id() as i32;

            let mut skel = ManuallyDrop::new(open_skel.load().context("Failed to load skel")?);
            skel.attach().context("Failed to attach skel")?;
            // Unfortunately due to the fact that rust is so notorious about lifetimes
            // I have to use this black magic to cast normal type into a static one
            // Without that it just wouldn't work. Probably it's safe tho
            unsafe {
                std::mem::transmute::<
                    ManuallyDrop<TraceOpenSkel<'_>>,
                    ManuallyDrop<TraceOpenSkel<'static>>,
                >(skel)
            }
        };

        let mut builder = RingBufferBuilder::new();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<RustFileEvent>();

        let callback = move |data: &[u8]| -> i32 {
            if data.len() < std::mem::size_of::<FileEvent>() {
                warn!("Data with wrong size was sent to ring buffer");
                return 0;
            }
            let event = unsafe { &*(data.as_ptr() as *const FileEvent) };
            let comm = unsafe { std::ffi::CStr::from_ptr(event.comm.as_ptr()) }.to_string_lossy().into_owned();
            let exe = unsafe { std::ffi::CStr::from_ptr(event.exe.as_ptr()) }.to_string_lossy().into_owned();
            let path = unsafe { std::ffi::CStr::from_ptr(event.path.as_ptr()) }.to_string_lossy().into_owned();

            let new_event = RustFileEvent{
                timestamp: event.timestamp,
                pid: event.pid,
                comm,
                exe,
                path,
            };

            let _ = tx.send(new_event);
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
            rx
        })
    }

    pub async fn poll(mut self, timeout: Duration) {
        loop {
            let _ = self
                .ringbuf
                .poll(timeout)
                .context("Failed to poll Ringbuffer");

            while let Ok(event) = self.rx.try_recv() {
                let res = self.db_conn.call(move |c| {
                    c.execute("INSERT INTO files_opened (timestamp, pid, comm, exe, path) VALUES (?1, ?2, ?3, ?4, ?5)", params![event.timestamp, event.pid, event.comm, event.exe, event.path])
                }).await;
                if let Err(res) = res {
                    error!("Failed to write to DB: {}", res);
                }
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}
