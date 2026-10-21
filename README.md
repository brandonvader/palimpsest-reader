# Palimpsest

> **Unofficial, independent fork. Not affiliated with, endorsed by, or supported by the CrossPoint Reader organization or Xteink.**

Palimpsest is an e-reader-first firmware for the **Xteink X4 Pro**, based on the open-source
[CrossPoint Reader](https://github.com/crosspoint-reader/crosspoint-reader) firmware (MIT). The reading
experience is stock CrossPoint. On top of it, Palimpsest adds a discreet **Utilities** entry on the home
screen for security-research tools.

Base: CrossPoint Reader 1.6.5. See [NOTICE](NOTICE) and [LICENSE](LICENSE). The unmodified upstream README is kept at
[docs/UPSTREAM_README.md](docs/UPSTREAM_README.md); its install instructions refer to upstream's builds, not this fork.

## Status

v0.1. Supported target: **Xteink X4 Pro** (`x4pro` env, ESP32-S3). v1 is complete and verified on hardware; BLE scan
and a WiFi channel survey (roadmap 5a/5b) have since been built as well.

| Feature | State |
|---|---|
| Stock CrossPoint 1.6.5 reading experience | unchanged |
| Utilities menu (home entry, first-use authorized-use notice) | done |
| WiFi Tools, BLE Tools categories | done |
| WiFi Scan (SSID, BSSID, channel, RSSI, security; Rescan) | done |
| Channel Survey (beacon frame count per 2.4 GHz channel; Rescan) | done |
| BLE Scan (name, address, address type, connectable, RSSI; Rescan) | done |
| Frame Capture (management frames to pcap, Wireshark-ready) | done |
| Capture logging to SD | done (Frame Capture; retention is manual, see below) |

Known limitations, both accepted for now (tracked in the project backlog):
- the first WiFi Scan after boot keeps about 18 KB of heap held by the WiFi driver until the next reboot; it does
  not grow with further scans.
- linking the BLE stack keeps about 28 KB of heap reserved at boot for every user, whether or not BLE Scan is ever
  opened; measured reader headroom stays comfortable (140+ KB free) even after using both radios.

Utilities lives on the home screen between File Transfer and Settings. The first time you open it you must confirm the
authorized-use notice; the confirmation is stored as `/.crosspoint/palimpsest/utilities_ack` on the SD card.

### Frame Capture data handling

Frame Capture (`Utilities → WiFi Tools → Frame Capture`) writes standard pcap files (with a radiotap link-layer
header, so channel and RSSI load straight into Wireshark) to `/Palimpsest/captures/` on the SD card. It captures only
802.11 **management** frames (beacon, probe request/response, association, authentication) — never data frames, so no
other device's actual traffic content is touched. A capture stops automatically at 20,000 frames, 8 MB, or 10 minutes,
whichever comes first, in addition to a manual Stop.

These files contain nearby devices' MAC addresses and any SSIDs they broadcast or probe for — handle and store them
under the same authorized-use policy as the rest of this tool. **Nothing is auto-deleted**: captures accumulate on
the SD card until you remove them yourself via File Transfer, Browse Files, or a card reader.

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
partition table differs from the one in this repo's `partitions.csv`. Details in
[docs/palimpsest/flashing.md](docs/palimpsest/flashing.md).

## License

MIT. Original work © 2025 CrossPoint Reader organization; Palimpsest additions © 2026 Brandon Vader.
