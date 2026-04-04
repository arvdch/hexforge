# HEXFORGE

**File Forensics & Embedded Payload Extractor**

> A Python-based binary forensics tool built for CTF challenges and real-world file analysis. Scans any file for hidden embedded payloads, detects steganography, and carves embedded files out with format-aware precision — with zero external dependencies.

<!-- [SCREENSHOT: terminal running hexforge.py challenge.png showing the banner and clean output with ZIP detected] -->

---

## Why HEXFORGE?

Most file forensics workflows stitch together `file`, `strings`, `binwalk`, and manual hex editors. HEXFORGE replaces all of them in a single Python script with no pip installs — it runs anywhere Python 3.8+ runs.

It was built to solve a specific frustration with binwalk: **false positives**. Short magic byte sequences like `\x78\xda` (zlib) or `\x1f\x9d` (compress) appear constantly inside compressed image data and produce noise. HEXFORGE solves this architecturally with a compressed-region mapper that suppresses hits inside known PNG IDAT chunks, GZIP members, and zlib streams — only reporting short-magic hits that appear *outside* those regions.

On the `challenge.png` file above, binwalk reports nothing. HEXFORGE finds the embedded ZIP and extracts `flag.txt` from it.

---

## Features

| Feature | Description |
|---|---|
| **175 file signatures** | Images, archives, firmware/IoT, mobile, forensics, containers, games, crypto, disk, databases |
| **35+ structural validators** | Every short-magic signature has a format-specific struct check to eliminate false positives |
| **Compressed-region mapper** | PNG IDAT, GZIP, and zlib spans are mapped before scanning — hits inside are suppressed |
| **GZIP boundary detection** | Walks the deflate stream via `zlib.decompressobj` to find the exact end byte |
| **Format-aware carving** | PNG finds IEND, JPEG finds FF D9, ZIP walks EOCD, TIFF walks IFD chain, PCAP walks packet records |
| **Recursive carving** | Carved files are re-scanned for nested embeds; SHA-256 deduplication prevents loops |
| **File validation** | Each carved file is structurally verified (PNG IEND check, ZIP open, PDF %%EOF, ELF class) |
| **LSB steganography detection** | Chi-squared test on pixel LSBs with MSB-first bit extraction preview |
| **XOR obfuscation detection** | Detects single-byte XOR on file magic and prints the decode command |
| **JSON output** | `--json report.json` writes a machine-readable report |
| **Batch directory scan** | `--scan ./dir` scans all files and prints a summary table |
| **Zero dependencies** | Pure Python 3.8+ stdlib only (Pillow optional for JPEG/PNG stego) |

---

## Quick Start

```bash
git clone https://github.com/arvdch/hexforge
cd hexforge

# Basic analysis
python3 hexforge.py challenge.png

# With strings and LSB stego detection
python3 hexforge.py stego.png --strings --lsb

# Extract embedded files
python3 hexforge.py challenge.png --extract

# Extract to a specific folder
python3 hexforge.py challenge.png --extract --out ./carved

# Write a JSON report
python3 hexforge.py binary.bin --json report.json

# Batch scan a directory
python3 hexforge.py --scan ./firmware_dump/

# List all 175 known signatures
python3 hexforge.py --list-sigs
```

No `pip install` required. Python 3.8+ stdlib only.

---

## Usage

```
usage: hexforge [-h] [--strings] [--lsb] [--extract] [--out OUT]
                [--max-depth N] [--json PATH] [--scan DIR]
                [--bytes N] [--min-str-len N] [--max-strings N]
                [--list-sigs] [file]

positional arguments:
  file                Target file to analyze

options:
  --strings           Print extracted printable strings
  --lsb               Run LSB steganography detection (images)
  --extract           Extract all detected embedded files
  --out OUT           Output dir for carved files (default: <file>_carved/)
  --max-depth N       Max recursive carve depth (default: 0, disabled)
  --json PATH         Write JSON report to this path
  --scan DIR          Batch-scan all files in a directory
  --bytes N           Bytes to show in hex dump (default: 256)
  --list-sigs         List all known signatures and exit
```

---

## Output Sections

HEXFORGE produces eight analysis sections for every file:

**01 File Metadata** — name, size, MD5, SHA-256, full path.

**02 Primary Magic Signature** — identifies the file format by magic bytes. If the primary signature fails, it scans all 255 possible single-byte XOR keys and reports if the magic appears to be obfuscated.

**03 Hex Dump** — first N bytes with color coding: green = magic signature bytes, cyan = printable ASCII, grey = null bytes.

**04 Entropy Analysis** — Shannon entropy overall and per-chunk. High entropy (>7.2) indicates encrypted or compressed data; low entropy suggests structured text.

**05 Full Signature Scan** — every byte offset is scanned for all 175 signatures. Hits are split into confirmed (passed validator + not in compressed region) and suppressed (would be false positives).

**06 Embedded File Summary** — lists all confirmed embedded signatures with byte offset, context bytes, and a quick structural validity check on the carved content.

**07 Interesting Strings** — printable strings extracted with offset. URLs, filesystem paths, and sensitive keywords (password, flag{, token) are automatically tagged.

**08 LSB Steganography Detection** — chi-squared test on pixel LSBs. If the distribution is suspiciously uniform, the first 64 bytes of the LSB bitstream are decoded and shown as a preview — useful for confirming if there's readable text hidden in the image.

<!-- [SCREENSHOT: hexforge output on challenge.png showing sections 05 and 06 with the ZIP detected] -->

---

## Signature Categories

```
image      PNG, JPEG, GIF, BMP, WEBP, TIFF, ICO, PSD, AVIF, HEIC, DDS, KTX, SVG…
archive    ZIP, RAR4/5, 7ZIP, GZIP, BZIP2, XZ, ZSTD, LZ4, ZLIB, CPIO, SquashFS…
firmware   U-Boot, DTB, JFFS2, UBIFS, UBI, ROMFS, ext2/3/4, F2FS, OpenWrt…
exec       ELF, PE, Mach-O (32/64/fat), WASM, Lua bytecode, DEX (v035-039)…
mobile     ARSC, AXML, IMG4 (Apple), DEX versioned…
forensics  EVTX, Registry hive, LNK, Prefetch, WER minidump, LiME, EWF/EnCase…
container  Avro, Parquet, ORC, Arrow, HDF5, FlatBuffers, BSON…
game       Unity AssetBundle, Godot PCK, Unreal PAK, glTF GLB, Blender, FBX…
crypto     PEM, DER/PKCS, OpenSSH key, GPG binary, PGP armor, JKS, JCEKS…
network    PCAP (LE/BE), PCAPNG, ERF…
db         SQLite, LevelDB, MySQL binlog, MS Access…
disk       QCOW2, VMDK, VHD/VHDX, VDI, ISO 9660, MBR/FAT, GPT…
media      MP3, FLAC, OGG, MKV, MIDI, AAC-ADTS, WMV/WMA, MP4…
```

---

## How False Positive Suppression Works

The core insight is that short magic sequences appear randomly inside compressed data. A 2-byte sequence like `\x78\xda` appears roughly once every 65536 bytes by chance — and PNG images contain megabytes of compressed deflate data in their IDAT chunks.

HEXFORGE solves this in two layers:

**Layer 1 — Structural validators.** Every short-magic signature has a format-specific check. For BMP, it validates the DIB header size field. For MP3, it checks the bitrate nibble. For GZIP, it checks CM=8 and FLG reserved bits. A hit only passes if the surrounding bytes make structural sense for that format.

**Layer 2 — Compressed-region mapper.** Before scanning, HEXFORGE walks the file structure to map out spans that are definitively inside compressed payloads: PNG IDAT chunks (walked via the PNG chunk structure), GZIP members (walked via the RFC 1952 header), and raw zlib streams (drained via `zlib.decompressobj`). Any hit whose offset falls inside one of these regions is suppressed if its magic is shorter than 6 bytes. A 6-byte sequence appearing by chance inside deflate output is astronomically unlikely.

The result: on `challenge.png`, 13 hits are suppressed and 2 real embedded signatures are confirmed — with zero noise.

---

## CTF Use Cases

HEXFORGE was built specifically for CTF file forensics challenges. Common patterns it handles:

- **PNG with appended ZIP** — the classic stego trick. ZIP's EOCD record is found regardless of what comes before it.
- **XOR-obfuscated magic bytes** — challenge files often have the first byte flipped. HEXFORGE scans all 255 XOR keys and prints a decode one-liner.
- **Polyglot files** — files valid as two formats simultaneously (JPEG+ZIP, PDF+ZIP). Both signatures are reported with exact offsets.
- **tEXtComment metadata** — PNG tEXt chunks containing `password=...` are extracted by the strings scanner and tagged `[SENSITIVE]`.
- **Nested archives** — use `--max-depth 2` to carve inside carved files recursively.
- **PCAP with embedded images** — batch-carve all JPEG frames out of a network capture.

---

## Comparison with binwalk

| | binwalk | hexforge |
|---|---|---|
| False positive suppression | Basic | Compressed-region mapper + 35 validators |
| GZIP boundary detection | Heuristic | Exact via deflate stream walking |
| TIFF carving | End of file | IFD chain traversal |
| PCAP carving | End of file | Packet record walking |
| LSB stego detection | No | Chi-squared + bit preview |
| XOR obfuscation hints | No | Yes (all 255 keys) |
| JSON output | Yes | Yes |
| Dependencies | C extensions, libmagic | Zero (stdlib only) |
| Language | Python + C | Pure Python |

---

## Project Structure

```
hexforge/
├── hexforge.py          # Single-file tool — everything is here
└── README.md
```

Everything lives in one file. Copy it anywhere, run it.

---

## Requirements

- Python 3.8 or newer
- No external packages required
- `Pillow` (optional) — enables JPEG/PNG LSB analysis via PIL pixel decoding

```bash
pip install Pillow   # optional
```

---

## Author

**arvdch** — [github.com/arvdch](https://github.com/arvdch)

Built as a personal CTF tool, open-sourced so others can use and extend it.

---

## License

MIT License. See `LICENSE` for details.
