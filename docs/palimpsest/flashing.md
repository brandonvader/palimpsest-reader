# Flashing Palimpsest safely (Xteink X4 Pro)

These notes are from the first unit this firmware was developed on. Check every value against your own device
before writing anything.

## Rules

1. **Back up the whole flash first** and verify it (size and sha256) in at least two places.
2. **Never run `erase_flash`.** Never write the bootloader, partition table or `otadata`.
3. **Never flash `firmware.factory.bin`.** It is a merged image that carries this repo's `partitions.csv`, which
   does **not** match the table on the device.
4. Write **only the app image** (`.pio/build/x4pro/firmware.bin`), and only to the **active OTA slot**.

## Backup (read-only)

```bash
esptool --port /dev/ttyACM0 chip-id
esptool --port /dev/ttyACM0 --baud 921600 read-flash 0x0 0x1000000 x4pro-backup.bin
sha256sum x4pro-backup.bin    # file must be exactly 16,777,216 bytes
```

esptool 5 uses hyphenated subcommands (`read-flash`); esptool 4 used underscores.

## Find the active slot

Read the partition table and `otadata` from the backup (or the device):

```bash
esptool --port /dev/ttyACM0 read-flash 0x8000 0x1000 ptable.bin
esptool --port /dev/ttyACM0 read-flash 0xe000 0x2000 otadata.bin
```

The first 4 bytes at `0xe000` and at `0xf000` are the two sequence numbers. The higher sequence N selects slot
`(N - 1) mod 2` (0 = `ota_0`, 1 = `ota_1`). On the development unit the table was:

| Name | Offset | Size |
|---|---|---|
| nvs | 0x9000 | 0x5000 |
| otadata | 0xe000 | 0x2000 |
| app0 (ota_0) | 0x10000 | 0x7e0000 |
| app1 (ota_1) | 0x7f0000 | 0x7e0000 |
| spiffs | 0xfd0000 | 0x14000 |
| coredump | 0xfe4000 | 0x1c000 |

and the sequences were 1 and 2, so the unit booted **app1 (0x7f0000)**. Writing the other slot changes nothing
visible. `board_upload.offset_address = 0x10000` in `platformio.ini` is upstream's default and does not apply to such a
unit, so do not use `pio run -t upload` blindly.

## Flash

```bash
pio run -e x4pro
esptool --port /dev/ttyACM0 --baud 921600 write-flash 0x7f0000 .pio/build/x4pro/firmware.bin
```

Then read the flash back and confirm that the slot equals the build and that nothing outside it changed compared with
your backup.

## Recovery

- Re-write the official CrossPoint image for the `x4pro` board to the same offset (app-only), or
- restore the verified full backup: `esptool --port /dev/ttyACM0 write-flash 0x0 x4pro-backup.bin`.

Keep the battery charged and the adapter seated while writing.
