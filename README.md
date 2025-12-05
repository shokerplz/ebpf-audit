# ebpf-audit

A lightweight Linux system monitoring tool built with eBPF that tracks file access and network connections in real-time.

## Overview

`ebpf-audit` uses eBPF (Extended Berkeley Packet Filter) to monitor system activity with minimal overhead. It tracks:
- **File Operations**: Which processes open which files and stores them in a SQLite database.
- **Network Connections**: Which processes connect to which IP addresses and stores them in a SQLite database.

All monitoring happens in kernel space for maximum efficiency and minimal performance impact.

## Features

- **Real-time Monitoring**: Instant visibility into file access and network connections
- **Low Overhead**: eBPF runs in the kernel with minimal performance impact
- **Process Details**: Track process ID, executable path, and command name
- **Asynchronous Processing**: Built with Tokio for efficient event handling
- **No Dependencies on External Tooling**: Self-contained binary
- **Data Persistence**: All captured events are stored in a SQLite database for later analysis.

## Requirements

- Linux kernel 5.8+ (5.17+ recommended to avoid memory limit configuration)
- Root privileges (required for eBPF)
- Rust toolchain (for building)
- libbpf development libraries

### Nix Users

If you're using Nix, a `flake.nix` is provided for easy environment setup:

```bash
nix develop
```

### Non-Nix Users

If you don't have Nix installed, you can use the provided Dockerfile to create a consistent development environment.

1. **Build the Docker image:**

```bash
docker build -t ebpf-audit-dev .
```

2. **Start the development shell:**

```bash
docker run --rm -it \
  -v $(pwd):/app \
  ebpf-audit-dev
```

> **Note:** To *run* the `ebpf-audit` binary (which requires kernel privileges), you must run the container with `--privileged`:
>
> ```bash
> docker run --rm -it \
>   -v $(pwd):/app \
>   --privileged \
>   ebpf-audit-dev
> ```

## Generate vmlinux

To build BPF binaries you would need to create vmlinux.h first

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src-bpf/vmlinux.h
```

## Building

```bash
cargo build
```

The build process automatically compiles the eBPF programs and embeds them into the binary.

## Usage

Run with root privileges in `CollectData` mode (default, storing events in `result.db`):

```bash
sudo ./target/debug/ebpf-audit --mode collect-data
```

The program will start monitoring and store events in `result.db`. Console output will show status messages.

Press `Ctrl+C` to stop monitoring gracefully.

## Analysys Mode

In `Analysys` mode, `ebpf-audit` monitors file access and network connections but instead of writing all events to the database, it compares incoming events against the existing `result.db`. If an event (file open or socket connection) is detected that is *not* already present in the database, it will be logged to the console as a "new event." This mode is useful for detecting unusual or unauthorized activity against a known baseline.

To run in `Analysys` mode:

```bash
sudo ./target/debug/ebpf-audit --mode analysys
```

When running in Analysys mode, events are not persisted to the database.

## How It Works

The project consists of two main components:

1. **eBPF Programs** (in `src-bpf/`):
   - `trace_open.bpf.c`: Hooks into file open operations
   - `socket_connect.bpf.c`: Hooks into socket connect operations

2. **Userspace Program** (in `src/`):
   - Loads eBPF programs into the kernel
   - Attaches them to appropriate hook points
   - Polls ring buffers for events
   - Writes data to sqlite DB in batches

Events are sent from kernel space to user space via eBPF ring buffers for efficient, lock-free communication.

## Architecture

```
┌─────────────────────────────────────┐
│         Kernel Space                │
│  ┌──────────────┐  ┌──────────────┐ │
│  │ trace_open   │  │socket_connect│ │
│  │  (eBPF)      │  │   (eBPF)     │ │
│  └──────┬───────┘  └──────┬───────┘ │
│         │                 │         │
│         └────┬───────┬────┘         │
│              │ Ring  │              │
│              │Buffers│              │
└──────────────┼───────┼──────────────┘
               │       │
┌──────────────┼───────┼──────────────┐
│              ▼       ▼              │
│         User Space                  │
│  ┌─────────────────────────────┐    │
│  │   Tokio Async Runtime       │    │
│  │  ┌─────────┐  ┌───────────┐ │    │
│  │  │File Poll│  │Net Poll   │ │    │
│  │  └─────────┘  └───────────┘ │    │
│  └─────────────────────────────┘    │
│              │                      │
│              ▼                      │
│          SQLite DB                  │
└─────────────────────────────────────┘
```

## Security Considerations

This tool requires root privileges and has deep system access. Use responsibly and only on systems you own or have permission to monitor.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.
