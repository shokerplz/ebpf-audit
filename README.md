# ebpf-audit

A lightweight Linux system monitoring tool built with eBPF that tracks file access and network connections in real-time.

## Overview

`ebpf-audit` uses eBPF (Extended Berkeley Packet Filter) to monitor system activity with minimal overhead. It tracks:
- **File Operations**: Which processes open which files
- **Network Connections**: Which processes connect to which IP addresses

All monitoring happens in kernel space for maximum efficiency and minimal performance impact.

## Features

- **Real-time Monitoring**: Instant visibility into file access and network connections
- **Low Overhead**: eBPF runs in the kernel with minimal performance impact
- **Process Details**: Track process ID, executable path, and command name
- **Asynchronous Processing**: Built with Tokio for efficient event handling
- **No Dependencies on External Tooling**: Self-contained binary

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

Run with root privileges:

```bash
sudo ./target/debug/ebpf-audit
```

If you're using NixOS you would need to run:

```bash
sudo env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" ./target/debug/ebpf-audit
```

The program will start monitoring and display events as they occur:

```
[1234567890] PID:1234 Exe:"/usr/bin/cat" Comm:"cat" Path: "/etc/passwd"
[1234567891] PID:5678 Exe:"/usr/bin/curl" Comm:"curl" DST_IP:93.184.216.34
```

Press `Ctrl+C` to stop monitoring gracefully.

Note: piping is currently not supported, at the moment program will crash on pipe closure

## Output Format

### File Events
```
[timestamp] PID:<pid> Exe:"<executable_path>" Comm:"<command_name>" Path: "<file_path>"
```

### Network Events
```
[timestamp] PID:<pid> Exe:"<executable_path>" Comm:"<command_name>" DST_IP:<ip_address>
```

## How It Works

The project consists of two main components:

1. **eBPF Programs** (in `src-bpf/`):
   - `trace_open.bpf.c`: Hooks into file open operations
   - `socket_connect.bpf.c`: Hooks into socket connect operations

2. **Userspace Program** (in `src/`):
   - Loads eBPF programs into the kernel
   - Attaches them to appropriate hook points
   - Polls ring buffers for events
   - Formats and displays the output

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
│  ┌─────────────────────────────┐   │
│  │   Tokio Async Runtime       │   │
│  │  ┌─────────┐  ┌───────────┐ │   │
│  │  │File Poll│  │Net Poll   │ │   │
│  │  └─────────┘  └───────────┘ │   │
│  └─────────────────────────────┘   │
│              │                      │
│              ▼                      │
│         Console Output              │
└─────────────────────────────────────┘
```

## Project Structure

```
ebpf-audit/
├── src/
│   ├── main.rs           # Main entry point
│   ├── file.rs           # File monitoring logic
│   ├── net.rs            # Network monitoring logic
│   └── data.rs           # Shared data structures
├── src-bpf/
│   ├── trace_open.bpf.c      # eBPF file monitoring
│   ├── socket_connect.bpf.c  # eBPF network monitoring
│   ├── bpf.h                 # Headers
├── build.rs              # Build script for eBPF compilation
├── Cargo.toml
├── flake.nix            # Nix development environment
└── README.md
```

## Future Enhancements

- SQLite database backend for event storage
- Filtering and search capabilities
- Web dashboard for visualization
- Additional event types (process execution, privilege escalation, etc.)
- Detecting unusual patterns

## Security Considerations

This tool requires root privileges and has deep system access. Use responsibly and only on systems you own or have permission to monitor.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.
