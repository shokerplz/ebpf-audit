# Development Notes

## Build Process

The project uses `libbpf-cargo` to automatically compile eBPF programs during the build process.

### Manual eBPF Compilation (for reference)

If you need to manually compile eBPF programs:

```bash
clang -g -O2 -target bpf -I/path/to/libbpf/include -c src-bpf/socket_connect.bpf.c -o build/socket_connect.bpf.o
```

### Manual eBPF Loading (for debugging)

To manually load and attach a compiled eBPF program:

```bash
# Load and attach
sudo bpftool prog load trace_open.bpf.o /sys/fs/bpf/trace_file_open autoattach

# Detach
sudo rm /sys/fs/bpf/trace_file_open
```

## Running

```bash
sudo env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" ./target/debug/ebpf-audit
```

## TODO / Future Enhancements

- [ ] SQLite database backend for event storage
- [ ] Event filtering capabilities
- [ ] Additional protocol support (IPv6, Unix sockets)
- [ ] Web dashboard for real-time monitoring
- [ ] Configuration file support
- [ ] Export to various formats (JSON, CSV, etc.)

## Architecture Notes

### eBPF Programs

- `trace_open.bpf.c` - LSM hook for file operations
- `socket_connect.bpf.c` - LSM hook for socket connections

### Ring Buffers

Events are communicated from kernel to userspace via eBPF ring buffers:
- File events: 288 bytes × 16384 entries
- Socket events: 160 bytes × 16384 entries

### Event Structures

See `src/data.rs` for the C-compatible structures used for kernel-userspace communication.
