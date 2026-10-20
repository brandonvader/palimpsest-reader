# Palimpsest

> **Unofficial, independent fork. Not affiliated with, endorsed by, or supported by the CrossPoint Reader organization or Xteink.**

Palimpsest is an e-reader-first firmware for the **Xteink X4 Pro**, based on the open-source
[CrossPoint Reader](https://github.com/crosspoint-reader/crosspoint-reader) firmware (MIT). The reading
experience is stock CrossPoint. On top of it, Palimpsest adds a discreet **Utilities** entry on the home
screen for security-research tools.

Base: CrossPoint Reader 1.6.5. See [NOTICE](NOTICE) and [LICENSE](LICENSE). The unmodified upstream README is kept at
[docs/UPSTREAM_README.md](docs/UPSTREAM_README.md); its install instructions refer to upstream's builds, not this fork.

## Status

Early development (v0.1). Currently supported target: **Xteink X4 Pro** (`x4pro` env, ESP32-S3).

| Feature | State |
|---|---|
| Stock CrossPoint 1.6.5 reading experience | unchanged |
| Utilities menu | in progress |
| WiFi scan | planned (v1) |
| WiFi monitor, BLE scan, SD capture logging | deferred |

## Authorized use

The Utilities tools are for security research and testing **only on networks and devices you own or are
explicitly authorized to assess.** You are responsible for complying with the laws that apply to you.
v1 tools are passive/observational; no offensive transmission features are planned for v1.

## Build

Requires PlatformIO.

```bash
git clone --recurse-submodules https://github.com/brandonvader/palimpsest-reader.git
cd palimpsest-reader
pio run -e x4pro
```

Flash **only the app image** (`.pio/build/x4pro/firmware.bin`) to the *active* OTA slot of your device, and
**back up your full flash first**. Never flash `firmware.factory.bin` and never run `erase_flash`: the device
partition table differs from the one in this repo's `partitions.csv`. Details in `docs/palimpsest/`.

## License

MIT. Original work © 2025 CrossPoint Reader organization; Palimpsest additions © 2026 Brandon Vader.
