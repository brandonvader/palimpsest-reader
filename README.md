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
| Frame Capture (WiFi management frames to pcap, Wireshark-ready) | done |
| BLE Capture (advertisements to pcap, Wireshark-ready) | done |
| Airspace Monitor (deauth/Pwnagotchy/evil twin/Karma detection) | done — **not yet tested on a touch device, see note below** |
| Device Finder (Flipper Zero, Find My tracker, BLE spam detection) | done — **not yet tested on a touch device, see note below** |
| Capture logging to SD | done (all three capture-capable tools; retention is manual, see below) |

**Testing note:** Airspace Monitor and Device Finder were built, flashed, and verified to boot cleanly, but were never
exercised through the touchscreen (built in a session with no one available to test interactively). Evil twin and
Karma detection are also untested against live conflicting APs — there was no way to synthesize that traffic. Treat
both tools as "should work" rather than "confirmed working" until someone has opened each screen, started/stopped a
session, and seen real rows populate.

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

### BLE Capture data handling

BLE Capture (`Utilities → BLE Tools → BLE Capture`) writes to the same `/Palimpsest/captures/` directory as Frame
Capture (as `ble-capture-<timestamp>.pcap`), with the same safety caps and retention policy above.

One technical note worth knowing before reading a capture: NimBLE's host-level scan API has no raw promiscuous mode
the way the WiFi radio does. Each record is a standard HCI **"LE Advertising Report"** event (Bluetooth Core Spec Vol
4 Part E §7.7.65.2) rebuilt from NimBLE's already-decoded fields — the real address, RSSI, advertising data and event
type for every advertisement seen, just reassembled into the wire format rather than tapped off the bus. Wireshark
dissects it exactly as it would a real one; nothing shown is fabricated, only the bus framing around it is
reconstructed. (NimBLE also deduplicates advertisements by address in its own cache; this tool periodically clears
that cache during a capture so repeat advertisements keep showing up, rather than each device appearing only once.)

### Airspace Monitor

Airspace Monitor (`Utilities → WiFi Tools → Airspace Monitor`) is a continuous, Start/Stop blue-team screen rather
than a raw capture tool: it hops channels like the capture tools and surfaces four kinds of finding in one
severity-sorted list.

- **Deauth/disassoc fingerprinting.** Counts deauth and disassoc frames per transmitter address (the radio that
  actually sent the frame, not the address it claims to be deauthenticating). Five or more from one source in a
  session reads as a likely attacker rather than normal client roaming. Each source is looked up against a curated
  OUI vendor table (~360 entries: every Espressif prefix, Raspberry Pi's, Flipper Zero's, and common consumer/
  networking vendors — built from `tshark -G manuf`, Wireshark's own database, via `scripts/gen_oui_table.py`) for a
  rough "what is this" hint; unrecognized MACs show "Unknown vendor" rather than a guess.
- **Pwnagotchy.** Its status "beacon" always transmits from the fixed address `de:ad:be:ef:de:ad` with its name and
  stats as JSON text in the SSID — the same fingerprint [ESP32Marauder's pwnagotchi
  detector](https://github.com/justcallmekoko/ESP32Marauder/wiki/detect-pwnagotchi) uses. Shown with its raw SSID
  text; the JSON is never parsed on-device, since a malformed or adversarial string should never reach a parser.
- **Evil twin.** The same SSID broadcast with a different Privacy bit (open vs protected) from more than one
  address. Deliberately a coarse open-vs-protected check rather than full RSN cipher/AKM decoding — it catches the
  most common and most dangerous pattern (an open clone of a normally protected network) without claiming precision
  this tool doesn't have on, say, a WPA2-vs-WPA3 mismatch, and a legitimate multi-AP deployment broadcasting the same
  SSID with matching security everywhere (as most conference venues do) never trips it.
- **Karma.** One address sending probe responses claiming to be four or more distinct SSIDs — a real AP only answers
  for its own configured name(s).

Once any of the above escalates, its subsequent frames are saved to one pcap file per session
(`/Palimpsest/captures/airspace-<timestamp>.pcap`, same radiotap format and safety caps as Frame Capture) for offline
forensics; a session with nothing escalating writes no extra file at all.

### Device Finder

Device Finder (`Utilities → BLE Tools → Device Finder`) is a continuous BLE scan (like BLE Capture, periodically
clearing NimBLE's own dedup cache so repeat advertisements keep registering) that flags three kinds of device:

- **Flipper Zero.** Any of three independent signals: its registered MAC vendor prefix (Flipper Devices Inc), a
  device name starting with "Flipper" (the default, unless renamed), or its colorway GATT service UUID. Adapted from
  the same signals the [Wall-of-Flippers](https://github.com/K3YOMI/Wall-of-Flippers) project uses (MIT licensed,
  reimplemented independently here).
- **Find My Tracker.** Apple manufacturer data carrying the fixed Find My type byte (0x12), distinct from ordinary
  AirPods/Continuity traffic. Labelled "Find My Tracker" rather than "AirTag": any Find My network accessory, or even
  a lost iPhone, broadcasts this.
- **BLE spam.** Manufacturer-data and service-data byte patterns matching known forged-popup payloads (fake Apple/
  Samsung/Windows pairing popups, plus the standard HID and Fast Pair service UUIDs), also adapted from
  Wall-of-Flippers. A single match is not shown — ordinary earbuds legitimately send some of these during normal
  pairing-mode chatter — only an address crossing a cumulative threshold (25 matches, Wall-of-Flippers' own sourced
  default) is flagged, and this is not Flipper-specific: any BLE spam tool trips it.

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
