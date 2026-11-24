# SerenLink edge

The device side of SerenLink: a durable, crash-safe log of boat data and the protocol that
uploads it to a gateway.

| Crate | What it is |
| --- | --- |
| `sl-proto` | Wire types and codecs. `no_std` + `alloc`. |
| `sl-core` | The durable log, the recorder and the upload session. `no_std` + `alloc`. |
| `sl-agent` | A Linux program: reads a SignalK server's WebSocket stream, records it into the log and uploads it over TLS. |

## Build and test

```bash
nix build .#sl-agent          # builds and tests sl-agent; the binary is ./result/bin/sl-agent
nix-shell --run 'cargo test'  # the whole workspace
nix-shell --run 'cargo check --no-default-features -p sl-proto -p sl-core'  # must stay no_std
```

## The agent

```
sl-agent --hostname <gateway name> --ca <root.pem> --trust-store <file> --device-id <32 hex chars> [options]
```

| Flag | Meaning |
| --- | --- |
| `--hostname` | The gateway's name: TLS checks it and the session signs it. Required. |
| `--addr` | Where to connect, `host:port`. Default: the hostname on 443. |
| `--ca` | The private CA's root, PEM. Required. |
| `--trust-store` | The baseline trust store (a signed store file). Required. |
| `--device-id` | This device's id, 16 bytes of hex. Required. |
| `--state-dir` | Where the log and device key live. Default `/var/lib/sl-agent`. |
| `--capacity` | Most bytes the log may hold. Default 4 GiB. |
| `--signalk-url` | The SignalK stream. Default `ws://localhost:3000/signalk/v1/stream`. |
| `--print-pubkey` | Make the device key if there is none, print its public key in hex, and exit. |

## License

Apache-2.0, see `LICENSE`.
