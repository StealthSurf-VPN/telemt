# Telemt — MTProxy on Rust + Tokio

## Project Overview

Production-grade Telegram MTProxy server implementing the official MTProto proxy protocol with TLS-fronting, anti-replay, traffic masking, and a management API.

- **Language:** Rust (edition 2024)
- **Async runtime:** Tokio
- **Version:** 3.3.15 (Cargo.toml)
- **Minimum Rust:** 1.91+
- **Config format:** TOML (`config.toml` — basic, `config.full.toml` — all options)

## Build & Run

```bash
cargo build --release          # Release build (lto = "thin")
cargo build                    # Debug build
cargo test                     # Run tests
cargo bench                    # Run benchmarks (criterion)
cargo clippy                   # Lint (do NOT run cargo fmt unless explicitly asked)
```

Run: `telemt config.toml`

## Source Layout

```
src/
  main.rs              # Entry point
  cli.rs               # CLI argument parsing
  startup.rs           # Server bootstrap
  error.rs             # Error types (thiserror)
  metrics.rs           # Prometheus-format metrics
  ip_tracker.rs        # IP tracking / rate limiting
  api/                 # HTTP management API (hyper)
    mod.rs             # Router, handlers
    model.rs           # API request/response models
    users.rs           # User management endpoints
    config_store.rs    # Config persistence
    runtime_*.rs       # Runtime stats, selftest, watch endpoints
  config/              # Configuration loading & hot-reload
    types.rs           # Config structs (serde)
    load.rs            # TOML parsing & validation
    hot_reload.rs      # File-watch config reload (notify)
    defaults.rs        # Default values
  crypto/              # AES-CTR/CBC, SHA-256/SHA-1, MD5, HMAC, CRC32
    aes.rs             # MTProto AES encryption
    hash.rs            # Hash utilities
    random.rs          # Secure random generation
  protocol/            # MTProto protocol layer
    constants.rs       # Protocol constants, DC addresses
    frame.rs           # Frame structure
    obfuscation.rs     # MTProto obfuscation (obfuscated2)
    tls.rs             # Fake-TLS ClientHello/ServerHello parsing
  proxy/               # Core proxy logic
    client.rs          # Client connection handler
    handshake.rs       # MTProto handshake state machine
    relay.rs           # Bidirectional data relay
    direct_relay.rs    # Direct relay mode
    middle_relay.rs    # Middle-proxy relay mode
    masking.rs         # Traffic masking (forward to real host)
    route_mode.rs      # Routing decisions
  transport/           # Network transport layer
    upstream.rs        # Upstream connection management
    pool.rs            # ME (Middle-End) connection pool
    socket.rs          # Socket configuration (SO_KEEPALIVE, TCP_NODELAY)
    socks.rs           # SOCKS5 upstream support
    proxy_protocol.rs  # HAProxy PROXY protocol
    middle_proxy/      # Middle-proxy protocol (send logic)
  stream/              # Stream abstractions
    crypto_stream.rs   # Encrypted stream wrapper
    frame_codec.rs     # Frame codec (tokio-util)
    frame_stream.rs    # Framed stream
    tls_stream.rs      # TLS stream handling
    buffer_pool.rs     # Buffer pool (reusable allocations)
    state.rs           # Stream state machine
  tls_front/           # TLS fronting / emulation
    fetcher.rs         # Real certificate fetching
    emulator.rs        # TLS record emulation
    cache.rs           # Certificate cache
  network/             # Network utilities
    dns_overrides.rs   # DNS override support
    probe.rs           # Network probing
    stun.rs            # STUN protocol (public IP discovery)
  stats/               # Statistics collection
    mod.rs             # Aggregated stats
    beobachten.rs      # Observation / monitoring
    telemetry.rs       # Telemetry
  maestro/             # Orchestration / lifecycle
    mod.rs             # Main orchestrator
    listeners.rs       # Listener management
    me_startup.rs      # Middle-End pool startup
    connectivity.rs    # Connectivity checks
    admission.rs       # Connection admission control
    shutdown.rs        # Graceful shutdown
    runtime_tasks.rs   # Background task management
    tls_bootstrap.rs   # TLS bootstrap
  util/                # Shared utilities
    ip.rs              # IP address helpers
    time.rs            # Time utilities
```

## Code Conventions

All rules from `AGENTS.md` apply. Key points:

- **Language:** All code, comments, commit messages — English only
- **Comments:** Above the code, never trailing. Only meaningful comments (`///` for public, `//` for internal)
- **File size:** 350-550 lines max per file; split into submodules if exceeded
- **Formatting:** Preserve existing style as-is. Do NOT run `cargo fmt` unless explicitly asked
- **Warnings/unused code:** Leave untouched unless explicitly asked to fix
- **No refactors** outside the requested scope
- **No new abstractions** (traits, generics, macros) unless justified and approved
- **Hot-path safety:** No extra allocations, cloning, formatting, locks, or logging in hot paths
- **Async safety:** No blocking in async, preserve cancellation safety and backpressure
- **Error handling:** Structured errors (thiserror), no panics in production paths
- **Security:** Do not weaken crypto, log secrets, or alter key derivation / constant-time code
- **Concurrency:** parking_lot for sync locks, dashmap for concurrent maps, crossbeam for queues
- **Serialization:** serde + toml for config, serde_json for API

## Testing

```bash
cargo test                              # All tests
cargo test --lib                        # Unit tests only
cargo bench --bench crypto_bench        # Crypto benchmarks (criterion)
```

Dev dependencies: tokio-test, criterion, proptest, futures.

## Git Workflow

- Branch `flow` for development, `main` for releases
- Signed and verified commits only
- Commit messages: English, concise, explain *what* and *why*
- Co-author line: `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`

## Key Architectural Notes

- **Middle-End Pool:** Connection pooling to Telegram DCs with reader/writer split, adaptive floor, generation lifecycle
- **TLS Fronting:** Fetches real certificates, emulates TLS records to be indistinguishable from real HTTPS
- **Traffic Masking:** Unrecognized connections transparently spliced to a real web server
- **Anti-Replay:** Sliding window replay attack protection
- **Hot Reload:** Config changes watched via filesystem notifications (notify crate)
- **API:** HTTP management API on a separate port with IP whitelist


<claude-mem-context>
# Recent Activity

<!-- This section is auto-generated by claude-mem. Edit content outside the tags. -->

*No recent activity*
</claude-mem-context>