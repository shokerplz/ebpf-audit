// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2025 ebpf-audit Ivan Kovalev ivan@ikovalev.nl

use anyhow::Context;
use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder as _;
use log::{info, warn};
use std::mem::ManuallyDrop;
use std::mem::MaybeUninit;
use std::time::Duration;

use crate::data::*;

mod exec_skel {
    include!(concat!(env!("OUT_DIR"), "/trace_open_skel.rs"));
}

use exec_skel::*;

pub struct TraceOpenProgram<'obj> {
    ringbuf: libbpf_rs::RingBuffer<'obj>,
    _skel: ManuallyDrop<TraceOpenSkel<'obj>>,
}

impl<'obj> TraceOpenProgram<'obj> {
    pub fn new() -> Result<Self> {
        let skel_builder = TraceOpenSkelBuilder::default();
        let mut open_object = Box::new(MaybeUninit::uninit());
        let skel = {
            let open_skel = skel_builder
                .open(&mut *open_object)
                .context("Failed to open skel")?;
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

        builder
            .add(&skel.maps.events, Self::callback)
            .context("Failed to attach callback to Ringbuffer")?;
        let ringbuf = builder.build().context("Failed to build Ringbuffer")?;

        Ok(Self {
            //            open_object,
            ringbuf,
            _skel: skel,
        })
    }

    fn callback(data: &[u8]) -> i32 {
        if data.len() < 288 {
            warn!("Data with wrong size was sent to ring buffer");
            return 0;
        }
        let event = unsafe { &*(data.as_ptr() as *const FileEvent) };
        let comm = unsafe { std::ffi::CStr::from_ptr(event.comm.as_ptr()) };
        let exe = unsafe { std::ffi::CStr::from_ptr(event.exe.as_ptr()) };
        let path = unsafe { std::ffi::CStr::from_ptr(event.path.as_ptr()) };
        info!(
            "[{}] PID:{} Exe:{:?} Comm:{:?} Path: {:?}",
            event.timestamp, event.pid, exe, comm, path
        );
        0
    }

    pub async fn poll(self, timeout: Duration) {
        loop {
            // Not sure about context here since we're not returning any value
            let _ = self
                .ringbuf
                .poll(timeout)
                .context("Failed to poll Ringbuffer");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}
