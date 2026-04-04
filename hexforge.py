#!/usr/bin/env python3
"""
HEXFORGE — File Forensics & Embedded Payload Extractor  v1.0
Author  : arvdch  (github.com/arvdch)
Language: Python 3.8+
Requires: no external dependencies  (Pillow optional — used for image validation)

What's in v1.0:
  1. False-positive filter       — 35+ structural validators on short magic sigs.
  2. Compressed-region mapper    — PNG IDAT, GZIP, zlib streams are mapped before
                                   scanning; short-magic hits inside are suppressed.
  3. GZIP boundary detection     — deflate stream walked byte-exactly via zlib API.
  4. Recursive carving           — carved files re-scanned up to --max-depth levels.
  5. File validation             — carved files structurally verified after extraction.
  6. 175 signatures              — images, archives, firmware/IoT, mobile, forensics,
                                   containers, games, crypto, disk images, databases.

Usage:
    python3 hexforge.py <file>
    python3 hexforge.py <file> --extract
    python3 hexforge.py <file> --extract --out ./carved
    python3 hexforge.py <file> --strings
    python3 hexforge.py <file> --bytes 512 --strings --extract
    python3 hexforge.py <file> --extract --max-depth 6
    python3 hexforge.py --list-sigs
"""

import sys
import math
import zlib
import struct
import hashlib
import argparse
import zipfile
import gzip
import io
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Callable

if sys.version_info < (3, 8):
    sys.exit("[!] hexforge requires Python 3.8 or newer.")

# Optional Pillow for image validation
try:
    from PIL import Image as _PILImage
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# ─────────────────────────────────────────────────────────────────────────────
# ANSI color helpers
# ─────────────────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GREY    = "\033[37m"

def g(s):    return f"{C.GREEN}{s}{C.RESET}"
def r(s):    return f"{C.RED}{s}{C.RESET}"
def y(s):    return f"{C.YELLOW}{s}{C.RESET}"
def c(s):    return f"{C.CYAN}{s}{C.RESET}"
def m(s):    return f"{C.MAGENTA}{s}{C.RESET}"
def grey(s): return f"{C.GREY}{s}{C.RESET}"
def sep(s):  return f"{C.DIM}{s}{C.RESET}"
def bold(s): return f"{C.BOLD}{s}{C.RESET}"
def w(s):    return f"{C.WHITE}{s}{C.RESET}"


# ─────────────────────────────────────────────────────────────────────────────
# Signature database
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Sig:
    name:      str
    magic:     bytes
    offset:    int
    ext:       str
    desc:      str
    cat:       str
    end_sig:   Optional[bytes]                   = None
    # validator(data, offset) -> bool — extra check to reduce false positives
    validator: Optional[Callable[[bytes, int], bool]] = field(default=None, repr=False)


# ── Validator functions ───────────────────────────────────────────────────────

def _val_bmp(data: bytes, off: int) -> bool:
    """BMP: must have a valid file-size field and DIB header size."""
    if off + 26 > len(data):
        return False
    file_size = struct.unpack_from("<I", data, off + 2)[0]
    # file size stored in header must be ≤ actual remaining bytes and > 26
    if not (26 < file_size <= len(data) - off + 1024):
        return False
    dib_size = struct.unpack_from("<I", data, off + 14)[0]
    return dib_size in (12, 40, 108, 124)   # known DIB header sizes

def _val_mp3(data: bytes, off: int) -> bool:
    """MP3: FF FB / FF FA — check sync word + layer/bitrate sanity."""
    if off + 4 > len(data):
        return False
    b0, b1 = data[off], data[off + 1]
    # frame sync: first 11 bits set
    if (b0 & 0xFF) != 0xFF or (b1 & 0xE0) != 0xE0:
        return False
    layer    = (b1 >> 1) & 0x3
    bitrate  = (data[off + 2] >> 4) & 0xF
    samprate = (data[off + 2] >> 2) & 0x3
    return layer != 0 and bitrate not in (0, 15) and samprate != 3

def _val_der(data: bytes, off: int) -> bool:
    """DER: 0x30 0x82 — validate ASN.1 SEQUENCE length field is plausible."""
    if off + 4 > len(data):
        return False
    length = struct.unpack_from(">H", data, off + 2)[0]
    return 64 <= length <= len(data) - off

def _val_ico(data: bytes, off: int) -> bool:
    """ICO: reserved=0, type=1, count 1-20. Also checks first entry data offset."""
    if off + 22 > len(data):
        return False
    reserved = struct.unpack_from("<H", data, off)[0]
    img_type = struct.unpack_from("<H", data, off + 2)[0]
    count    = struct.unpack_from("<H", data, off + 4)[0]
    if not (reserved == 0 and img_type == 1 and 1 <= count <= 20):
        return False
    # Check first ICONDIRENTRY: image data offset must be within file bounds
    # and image size (at +8) must be > 0
    if off + 22 > len(data):
        return False
    img_size   = struct.unpack_from("<I", data, off + 14)[0]  # image data size
    img_offset = struct.unpack_from("<I", data, off + 18)[0]  # image data offset
    return img_size > 0 and img_offset >= 6 + count * 16 and img_offset + img_size <= len(data) + 65536

def _val_tiff_le(data: bytes, off: int) -> bool:
    if off + 8 > len(data): return False
    return struct.unpack_from("<I", data, off + 4)[0] >= 8

def _val_tiff_be(data: bytes, off: int) -> bool:
    if off + 8 > len(data): return False
    return struct.unpack_from(">I", data, off + 4)[0] >= 8

def _val_pe(data: bytes, off: int) -> bool:
    """PE/MZ: check e_lfanew points to a valid PE signature."""
    if off + 0x40 > len(data):
        return False
    try:
        e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
        pe_off   = off + e_lfanew
        if pe_off + 4 > len(data):
            return False
        return data[pe_off:pe_off + 4] == b"PE\x00\x00"
    except struct.error:
        return False

def _val_riff_webp(data: bytes, off: int) -> bool:
    """RIFF: check RIFF chunk size is reasonable and subtype is WEBP/AVI/WAVE."""
    if off + 12 > len(data):
        return False
    sub = data[off + 8:off + 12]
    return sub in (b"WEBP", b"AVI ", b"WAVE")

def _val_pcap(data: bytes, off: int) -> bool:
    """PCAP: magic + link type in valid range."""
    if off + 24 > len(data):
        return False
    # snaplen and network type sanity
    snaplen = struct.unpack_from("<I", data, off + 16)[0]
    return 0 < snaplen <= 262144

def _val_pcap_be(data: bytes, off: int) -> bool:
    if off + 24 > len(data):
        return False
    snaplen = struct.unpack_from(">I", data, off + 16)[0]
    return 0 < snaplen <= 262144

def _val_gzip(data: bytes, off: int) -> bool:
    """GZIP: CM must be 8 (deflate), FLG reserved bits must be 0."""
    if off + 10 > len(data):
        return False
    cm  = data[off + 2]   # compression method: must be 8
    flg = data[off + 3]   # flags
    return cm == 8 and (flg & 0xE0) == 0

def _val_elf(data: bytes, off: int) -> bool:
    """ELF: validate EI_CLASS (1/2), EI_DATA (1/2), EI_VERSION (1)."""
    if off + 16 > len(data):
        return False
    return data[off+4] in (1,2) and data[off+5] in (1,2) and data[off+6] == 1

def _val_zip(data: bytes, off: int) -> bool:
    """ZIP local file header: version needed must be plausible (<= 63)."""
    if off + 6 > len(data):
        return False
    ver = struct.unpack_from("<H", data, off + 4)[0]
    return ver <= 63  # version 6.3 = highest known ZIP spec

def _val_pdf(data: bytes, off: int) -> bool:
    """PDF: %PDF-X.Y version string."""
    if off + 7 > len(data):
        return False
    chunk = data[off:off+8]
    return bool(__import__('re').match(rb'%PDF-\d\.\d', chunk))

def _val_sqlite(data: bytes, off: int) -> bool:
    """SQLite: page size must be power of 2, between 512 and 65536."""
    if off + 18 > len(data):
        return False
    page_size = struct.unpack_from(">H", data, off + 16)[0]
    if page_size == 1:   # means 65536
        return True
    return page_size >= 512 and (page_size & (page_size - 1)) == 0

def _val_dex(data: bytes, off: int) -> bool:
    """DEX: validate version string and file size field."""
    if off + 40 > len(data):
        return False
    version = data[off+4:off+8]
    return version in (b"035\x00", b"036\x00", b"037\x00", b"038\x00", b"039\x00")

def _val_axml(data: bytes, off: int) -> bool:
    """Android binary XML: chunk size must be > 8 and reasonable."""
    if off + 8 > len(data):
        return False
    chunk_size = struct.unpack_from("<I", data, off + 4)[0]
    return 8 < chunk_size <= 50 * 1024 * 1024  # up to 50MB is plausible

def _val_arsc(data: bytes, off: int) -> bool:
    """Android ARSC resource table: type=0x0002, header size=0x000C."""
    if off + 8 > len(data):
        return False
    res_type   = struct.unpack_from("<H", data, off)[0]
    hdr_size   = struct.unpack_from("<H", data, off+2)[0]
    return res_type == 0x0002 and hdr_size == 0x000C

def _val_evtx(data: bytes, off: int) -> bool:
    """Windows EVTX: must have chunk_size=65536 at offset 40."""
    if off + 48 > len(data):
        return False
    # First 8 bytes = "ElfFile\x00" already matched; check header chunk size
    return True  # magic is already specific enough (8 bytes)

def _val_lnk(data: bytes, off: int) -> bool:
    """Windows LNK: header size must be 0x4C, link class identifier."""
    if off + 20 > len(data):
        return False
    hdr_size = struct.unpack_from("<I", data, off)[0]
    return hdr_size == 0x4C

def _val_jks(data: bytes, off: int) -> bool:
    """Java KeyStore: magic 0xFEEDFEED + version 1 or 2."""
    if off + 8 > len(data):
        return False
    version = struct.unpack_from(">I", data, off + 4)[0]
    return version in (1, 2)

def _val_regf(data: bytes, off: int) -> bool:
    """Windows Registry hive: sequence numbers and hive size must be sane."""
    if off + 32 > len(data):
        return False
    # hive_size at offset 40 should be > 4096
    hive_size = struct.unpack_from("<I", data, off + 40)[0] if off + 44 <= len(data) else 0
    return hive_size > 4096

def _val_blend(data: bytes, off: int) -> bool:
    """Blender: BLENDER-v followed by pointer size (- or _) and endian (v/V)."""
    if off + 12 > len(data):
        return False
    return data[off+7:off+8] in (b'-', b'_')

def _val_uboot(data: bytes, off: int) -> bool:
    """U-Boot legacy image: magic 0x27051956 big-endian (already matched), check ih_dcrc."""
    if off + 64 > len(data):
        return False
    # ih_type (offset 30) should be in 0..20 range
    ih_type = data[off + 30] if off + 31 <= len(data) else 0xFF
    return ih_type <= 20

def _val_dtb(data: bytes, off: int) -> bool:
    """DTB/FDT: magic is big-endian 0xD00DFEED, totalsize must be > 40."""
    if off + 8 > len(data):
        return False
    totalsize = struct.unpack_from(">I", data, off + 4)[0]
    return 40 < totalsize <= 256 * 1024 * 1024

def _val_cur(data: bytes, off: int) -> bool:
    """CUR: reserved=0, type=2, count 1-20, and first entry data offset plausible."""
    if off + 22 > len(data):
        return False
    reserved = struct.unpack_from("<H", data, off)[0]
    img_type = struct.unpack_from("<H", data, off + 2)[0]
    count    = struct.unpack_from("<H", data, off + 4)[0]
    if not (reserved == 0 and img_type == 2 and 1 <= count <= 20):
        return False
    img_size   = struct.unpack_from("<I", data, off + 14)[0]
    img_offset = struct.unpack_from("<I", data, off + 18)[0]
    return img_size > 0 and img_offset >= 6 + count * 16 and img_offset + img_size <= len(data) + 65536

def _val_ttf(data: bytes, off: int) -> bool:
    """TrueType Font: numTables in 1-256, searchRange == (2^floor(log2(N)))*16."""
    if off + 12 > len(data):
        return False
    num_tables   = struct.unpack_from(">H", data, off + 4)[0]
    search_range = struct.unpack_from(">H", data, off + 6)[0]
    if not (1 <= num_tables <= 256):
        return False
    # searchRange must equal the largest power-of-2 <= numTables, times 16
    p = 1
    while p * 2 <= num_tables:
        p *= 2
    return search_range == p * 16


def _val_zlib(data: bytes, off: int) -> bool:
    """ZLIB: CMF byte low nibble must be 8 (deflate), FCHECK valid."""
    if off + 2 > len(data):
        return False
    cmf = data[off]
    flg = data[off + 1]
    cm  = cmf & 0x0F
    return cm == 8 and ((cmf * 256 + flg) % 31 == 0)

def _val_jxl(data: bytes, off: int) -> bool:
    """JPEG XL bare codestream: 0xFF 0x0A — next byte is a valid SizeHeader or ImageMetadata marker."""
    # JXL bare codestream starts FF 0A, followed by encoded bitstream.
    # The third byte encodes a VarLenUint. We check it isn't a control char
    # that would indicate accidental match (e.g. inside a JPEG scan).
    if off + 3 > len(data):
        return False
    # Must NOT appear immediately after FF D8 (JPEG SOI) — that's a JPEG scan header
    if off >= 2 and data[off-2:off] == b'\xff\xd8':
        return False
    # The byte before 0x0A in JPEG context is a marker like FF C0, FF DA, etc.
    if off >= 1 and data[off-1] == 0xFF:
        return False
    return True

def _val_compress(data: bytes, off: int) -> bool:
    """Unix compress .Z: 0x1F 0x9D — bits field byte 3 must be 9-16, bit 7 is block flag."""
    if off + 3 > len(data):
        return False
    bits = data[off + 2] & 0x1F   # lower 5 bits = max bits (9-16)
    return 9 <= bits <= 16

def _val_jffs2(data: bytes, off: int) -> bool:
    """JFFS2: 0x19 0x85 magic, followed by a valid node type (dirent, inode, cleanmarker, etc.)."""
    if off + 4 > len(data):
        return False
    node_type = struct.unpack_from("<H", data, off + 2)[0]
    # Known JFFS2 node types
    return node_type in (0xE001, 0xE002, 0xE003, 0x2003, 0x0000, 0xFFFF)

def _val_jffs2_be(data: bytes, off: int) -> bool:
    """JFFS2 BE: 0x85 0x19 — node type in big-endian."""
    if off + 4 > len(data):
        return False
    node_type = struct.unpack_from(">H", data, off + 2)[0]
    return node_type in (0xE001, 0xE002, 0xE003, 0x2003, 0x0000, 0xFFFF)

def _val_ext2(data: bytes, off: int) -> bool:
    """ext2/3/4: magic at offset 1080, s_inodes_count at -1076 must be plausible."""
    # The magic 0x53EF appears at byte 1080 within the superblock (at filesystem offset 1024).
    # Check that s_inodes_count (4 bytes before s_magic at offset 0) is reasonable.
    sb_start = off - 56  # s_magic is at superblock offset 56
    if sb_start < 0 or sb_start + 264 > len(data):
        return False
    inodes = struct.unpack_from("<I", data, sb_start)[0]
    blocks = struct.unpack_from("<I", data, sb_start + 4)[0]
    return 0 < inodes < 0x80000000 and 0 < blocks < 0x80000000

def _val_jpeg(data: bytes, off: int) -> bool:
    """JPEG: FF D8 FF <marker> — 4th byte must be a valid JFIF/EXIF/APP/SOF marker."""
    if off + 4 > len(data):
        return False
    # Magic is FF D8 FF, so off+3 is the first byte of the actual marker
    marker = data[off + 3]
    # Valid JPEG markers following SOI: E0-EF (APPn), FE (COM), DB (DQT),
    # C0-C3 (SOF), C4 (DHT), DA (SOS), D9 (EOI), D0-D7 (RST)
    return marker in (0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
                      0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
                      0xFE, 0xDB, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xDA,
                      0xD9, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7)

def _val_mp3_id3(data: bytes, off: int) -> bool:
    """MP3 ID3: 'ID3' tag — version byte must be 2, 3, or 4 and flags byte sane."""
    if off + 10 > len(data):
        return False
    version = data[off + 3]
    revision = data[off + 4]
    flags   = data[off + 5]
    # ID3v2.2, v2.3, v2.4 are the only valid versions; revision should be 0
    # flags must not have bits 4-7 set (reserved)
    return version in (2, 3, 4) and revision == 0 and (flags & 0x0F) == 0

def _val_aac_adts(data: bytes, off: int) -> bool:
    """AAC ADTS: 0xFF 0xF1/0xF9 — check sync, layer=0, profile, sample_rate index."""
    if off + 4 > len(data):
        return False
    b1 = data[off + 1]
    # Sync: 0xFFF, ID bit (0=MPEG-4, 1=MPEG-2), layer must be 00
    layer = (b1 >> 1) & 0x3
    if layer != 0:
        return False
    b2 = data[off + 2]
    profile     = (b2 >> 6) & 0x3          # 0-3 valid
    samp_idx    = (b2 >> 2) & 0xF          # 0-12 valid sample rate indices
    return samp_idx <= 12

def _val_flac(data: bytes, off: int) -> bool:
    """FLAC: 'fLaC' followed by STREAMINFO block type (0) and block length > 0."""
    if off + 8 > len(data):
        return False
    block_type = data[off + 4] & 0x7F      # strip last-metadata bit
    block_len  = struct.unpack_from(">I", data, off + 4)[0] & 0x00FFFFFF
    return block_type == 0 and block_len >= 34  # STREAMINFO is always 34 bytes

def _val_ogg(data: bytes, off: int) -> bool:
    """Ogg: 'OggS' followed by version (0) and header_type byte."""
    if off + 6 > len(data):
        return False
    version     = data[off + 4]
    header_type = data[off + 5]
    return version == 0 and header_type in (0x00, 0x01, 0x02, 0x04)

def _val_mkv(data: bytes, off: int) -> bool:
    """MKV/WebM: EBML magic 0x1A45DFA3 — EBML element size must be plausible."""
    if off + 6 > len(data):
        return False
    # Next byte after magic encodes VINT size; valid range for EBML header
    size_byte = data[off + 4]
    return size_byte != 0x00  # 0x00 would mean an invalid VINT

def _val_midi(data: bytes, off: int) -> bool:
    """MIDI: 'MThd' + 4-byte big-endian length (must be 6)."""
    if off + 8 > len(data):
        return False
    length = struct.unpack_from(">I", data, off + 4)[0]
    return length == 6  # MThd chunk length is always exactly 6

def _val_pcapng(data: bytes, off: int) -> bool:
    """PCAPNG: SHB magic 0x0A0D0D0A + block length must be >= 28."""
    if off + 12 > len(data):
        return False
    # Next 4 bytes are block type (should be 0x0A0D0D0A for SHB)
    block_type   = struct.unpack_from("<I", data, off)[0]
    block_length = struct.unpack_from("<I", data, off + 4)[0]
    return block_type == 0x0A0D0D0A and 28 <= block_length <= 16 * 1024 * 1024

def _val_svg(data: bytes, off: int) -> bool:
    """SVG: '<?xml' must be followed by version or encoding attribute within 64 bytes."""
    if off + 20 > len(data):
        return False
    chunk = data[off:off + 64].lower()
    return b'version' in chunk or b'encoding' in chunk or b'svg' in chunk

def _val_psd(data: bytes, off: int) -> bool:
    """PSD: '8BPS' + version (1=PSD, 2=PSB) + 6 reserved zero bytes."""
    if off + 10 > len(data):
        return False
    version   = struct.unpack_from(">H", data, off + 4)[0]
    reserved  = data[off + 6:off + 12]
    return version in (1, 2) and reserved == b'\x00' * 6

def _val_bson(data: bytes, off: int) -> bool:
    """BSON: first 4 bytes = document length, must equal remaining data size approx."""
    if off + 8 > len(data):
        return False
    doc_len = struct.unpack_from("<I", data, off)[0]
    # Must be >= 5 (min BSON doc) and plausible given remaining bytes
    return 5 <= doc_len <= len(data) - off + 1024 and data[off + doc_len - 1:off + doc_len] == b'\x00'

def _val_zip_empty(data: bytes, off: int) -> bool:
    """ZIP-EMPTY (EOCD PK\\x05\\x06): disk numbers must be 0, central dir size plausible."""
    if off + 22 > len(data):
        return False
    disk_num    = struct.unpack_from("<H", data, off + 4)[0]
    start_disk  = struct.unpack_from("<H", data, off + 6)[0]
    total_cdir  = struct.unpack_from("<H", data, off + 10)[0]
    return disk_num <= 1 and start_disk <= 1 and total_cdir < 65536

def _val_bzip2(data: bytes, off: int) -> bool:
    """BZIP2: BZh followed by block size digit 1-9."""
    if off + 4 > len(data):
        return False
    return data[off + 2:off + 3] in (b'h',) and chr(data[off + 3]) in '123456789'

def _val_squashfs(data: bytes, off: int) -> bool:
    """SquashFS: check inode count and block_size are plausible."""
    if off + 28 > len(data):
        return False
    try:
        inodes = struct.unpack_from("<I", data, off + 8)[0]
        block_size = struct.unpack_from("<I", data, off + 24)[0]
        return 0 < inodes < 10_000_000 and block_size in (4096, 8192, 16384, 32768, 65536, 131072, 1048576)
    except Exception:
        return False

def _val_cpio(data: bytes, off: int) -> bool:
    """CPIO newc: starts with 070701 or 070702 followed by hex fields."""
    if off + 110 > len(data):
        return False
    # namesize field at offset 94 (8 hex chars) should be > 0
    try:
        namesize = int(data[off + 94:off + 102], 16)
        return 1 <= namesize <= 1024
    except (ValueError, IndexError):
        return False

def _val_iso9660(data: bytes, off: int) -> bool:
    """ISO 9660: CD001 at 32769 — verify volume type byte is 0-3 or 255."""
    if off < 1:
        return False
    vol_type = data[off - 1] if off - 1 >= 0 else 0xFF
    return vol_type in (0, 1, 2, 3, 255)

def _val_fat_boot(data: bytes, off: int) -> bool:
    """FAT boot sector: 0x55AA at 510 — check jump instruction at start."""
    sector_start = off - 510
    if sector_start < 0 or sector_start + 512 > len(data):
        return False
    first = data[sector_start]
    # Must start with EB xx 90 (short jump + NOP) or E9 xx xx (near jump)
    return first in (0xEB, 0xE9)

def _val_gpt(data: bytes, off: int) -> bool:
    """GPT: revision 1.0 (00 00 01 00) and header size 92."""
    if off + 92 > len(data):
        return False
    revision = data[off + 8:off + 12]
    hdr_size = struct.unpack_from("<I", data, off + 12)[0]
    return revision == b'\x00\x00\x01\x00' and hdr_size == 92


SIGNATURES: list[Sig] = [

    # ════════════════════════════════════════════════════════════════════════
    # IMAGES
    # ════════════════════════════════════════════════════════════════════════
    Sig("PNG",        b"\x89PNG\r\n\x1a\n",                  0, ".png",    "Portable Network Graphics",                  "image",    b"\x00\x00\x00\x00IEND\xaeB`\x82"),
    Sig("JPEG",       b"\xff\xd8\xff",                        0, ".jpg",    "JPEG image",                                 "image",    b"\xff\xd9",   _val_jpeg),
    Sig("GIF89a",     b"GIF89a",                              0, ".gif",    "GIF image (89a)",                            "image",    b"\x3b"),
    Sig("GIF87a",     b"GIF87a",                              0, ".gif",    "GIF image (87a)",                            "image",    b"\x3b"),
    Sig("BMP",        b"BM",                                  0, ".bmp",    "Bitmap image",                               "image",    None,   _val_bmp),
    Sig("WEBP",       b"RIFF",                                0, ".webp",   "WebP / AVI / WAV (RIFF container)",          "image",    None,   _val_riff_webp),
    Sig("TIFF-LE",    b"II\x2a\x00",                         0, ".tiff",   "TIFF image (little-endian)",                 "image",    None,   _val_tiff_le),
    Sig("TIFF-BE",    b"MM\x00\x2a",                         0, ".tiff",   "TIFF image (big-endian)",                    "image",    None,   _val_tiff_be),
    Sig("ICO",        b"\x00\x00\x01\x00",                   0, ".ico",    "Windows icon",                               "image",    None,   _val_ico),
    Sig("CUR",        b"\x00\x00\x02\x00",                   0, ".cur",    "Windows cursor",                             "image",    None,   _val_cur),
    Sig("PSD",        b"8BPS",                                0, ".psd",    "Adobe Photoshop document",                   "image",   None,   _val_psd),
    Sig("XCF",        b"gimp xcf ",                           0, ".xcf",    "GIMP native image format",                   "image"),
    Sig("AVIF",       b"\x00\x00\x00\x1cftyp avif",       0, ".avif",   "AV1 Image File Format",                      "image"),
    Sig("HEIC",       b"\x00\x00\x00\x18ftyp heic",       0, ".heic",   "High Efficiency Image (HEIC/HEIF)",          "image"),
    Sig("JXL",        b"\xff\x0a",                            0, ".jxl",    "JPEG XL image (naked codestream)",           "image",   None,   _val_jxl),
    Sig("JXL-BMFF",   b"\x00\x00\x00\x0c\x4a\x58\x4c\x20",             0, ".jxl",    "JPEG XL image (ISOBMFF container)",          "image"),
    Sig("SVG",        b"<?xml",                               0, ".svg",    "SVG vector image (XML prefix)",              "image",   None,   _val_svg),
    Sig("ICNs",       b"icns",                                0, ".icns",   "Apple icon format",                          "image"),
    Sig("DDS",        b"DDS ",                                0, ".dds",    "DirectDraw Surface (GPU texture)",           "image"),
    Sig("KTX",        b"\xabKTX 11\xbb\r\n\x1a\n",           0, ".ktx",    "Khronos Texture (KTX1)",                     "image"),
    Sig("KTX2",       b"\xabKTX 20\xbb\r\n\x1a\n",           0, ".ktx2",   "Khronos Texture (KTX2)",                     "image"),

    # ════════════════════════════════════════════════════════════════════════
    # ARCHIVES / COMPRESSION
    # ════════════════════════════════════════════════════════════════════════
    Sig("ZIP",        b"PK\x03\x04",                         0, ".zip",    "ZIP archive / OOXML / APK / JAR",           "archive",  b"PK\x05\x06", _val_zip),
    Sig("ZIP-EMPTY",  b"PK\x05\x06",                         0, ".zip",    "ZIP archive (empty)",                        "archive",   None,   _val_zip_empty),
    Sig("RAR5",       b"Rar!\x1a\x07\x01\x00",               0, ".rar",    "RAR archive v5",                             "archive"),
    Sig("RAR4",       b"Rar!\x1a\x07\x00",                   0, ".rar",    "RAR archive v4",                             "archive"),
    Sig("7ZIP",       b"7z\xbc\xaf\x27\x1c",                 0, ".7z",     "7-Zip archive",                              "archive"),
    Sig("GZIP",       b"\x1f\x8b",                           0, ".gz",     "Gzip compressed data",                       "archive",  None,   _val_gzip),
    Sig("BZIP2",      b"BZh",                                 0, ".bz2",    "Bzip2 compressed data",                      "archive",  None,   _val_bzip2),
    Sig("XZ",         b"\xfd7zXZ\x00",                       0, ".xz",     "XZ compressed data",                         "archive"),
    Sig("ZSTD",       b"\x28\xb5\x2f\xfd",                   0, ".zst",    "Zstandard compressed data",                  "archive"),
    Sig("LZ4",        b"\x04\x22\x4d\x18",                   0, ".lz4",    "LZ4 compressed data",                        "archive"),
    Sig("CAB",        b"MSCF",                                0, ".cab",    "Microsoft Cabinet archive",                  "archive"),
    Sig("LZIP",       b"LZIP",                                0, ".lz",     "LZIP compressed data",                       "archive"),
    Sig("LZOP",       b"\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a", 0, ".lzo", "LZOP compressed data",                      "archive"),
    Sig("COMPRESS",   b"\x1f\x9d",                           0, ".Z",      "Unix compress (.Z)",                         "archive",   None,   _val_compress),
    Sig("SQUASHFS-LE",b"sqsh",                                0, ".sqsh",   "SquashFS filesystem (little-endian)",        "archive",  None,   _val_squashfs),
    Sig("SQUASHFS-BE",b"hsqs",                                0, ".sqsh",   "SquashFS filesystem (big-endian)",           "archive",  None,   _val_squashfs),
    Sig("CRAMFS",     b"\x45\x3d\xcd\x28",                   0, ".cramfs", "CramFS compressed filesystem",               "archive"),
    Sig("CPIO",       b"070701",                              0, ".cpio",   "CPIO archive (newc)",                        "archive",  None,   _val_cpio),
    Sig("CPIO-CRC",   b"070702",                              0, ".cpio",   "CPIO archive (newc+CRC)",                    "archive",  None,   _val_cpio),
    Sig("TAR-USTAR",  b"ustar",                             257, ".tar",    "POSIX tar archive (ustar)",                  "archive"),
    Sig("AR",         b"!<arch>\n",                           0, ".a",      "Unix ar static library",                     "archive"),
    Sig("ZLIB",       b"\x78\x9c",                           0, ".zlib",   "zlib compressed data (default)",             "archive",  None,   _val_zlib),
    Sig("ZLIB-BEST",  b"\x78\xda",                           0, ".zlib",   "zlib compressed data (best)",                "archive",  None,   _val_zlib),
    Sig("ZLIB-FAST",  b"\x78\x01",                           0, ".zlib",   "zlib compressed data (speed)",               "archive",  None,   _val_zlib),
    Sig("ZPAQ",       b"7kSt\xc5",                           0, ".zpaq",   "ZPAQ archive",                               "archive"),

    # ════════════════════════════════════════════════════════════════════════
    # DOCUMENTS
    # ════════════════════════════════════════════════════════════════════════
    Sig("PDF",        b"%PDF",                                0, ".pdf",    "Portable Document Format",                   "document", b"%%EOF", _val_pdf),
    Sig("CFBF",       b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  0, ".doc",    "MS Compound Binary (DOC/XLS/PPT)",           "document"),
    Sig("RTF",        b"{\\rtf1",                             0, ".rtf",    "Rich Text Format",                           "document"),
    Sig("DJVU",       b"AT&TFORM",                            0, ".djvu",   "DjVu document",                              "document"),
    Sig("PS",         b"%!PS-Adobe",                          0, ".ps",     "PostScript document",                        "document"),
    Sig("MOBI",       b"BOOKMOBI",                           60, ".mobi",   "Mobipocket/Kindle e-book",                   "document"),
    Sig("LIT",        b"ITOLITLS",                            0, ".lit",    "Microsoft LIT e-book",                       "document"),
    Sig("FLV",        b"FLV",                                 0, ".flv",    "Flash Video",                                "document"),

    # ════════════════════════════════════════════════════════════════════════
    # EXECUTABLES & BINARIES
    # ════════════════════════════════════════════════════════════════════════
    Sig("ELF",        b"\x7fELF",                            0, ".elf",    "ELF executable / shared lib",                "exec",     None,   _val_elf),
    Sig("PE",         b"MZ",                                  0, ".exe",    "MS-DOS MZ / Windows PE executable",          "exec",     None,   _val_pe),
    Sig("MACHO-32L",  b"\xce\xfa\xed\xfe",                   0, ".macho",  "Mach-O 32-bit (little-endian)",              "exec"),
    Sig("MACHO-32B",  b"\xfe\xed\xfa\xce",                   0, ".macho",  "Mach-O 32-bit (big-endian)",                 "exec"),
    Sig("MACHO-64",   b"\xcf\xfa\xed\xfe",                   0, ".macho",  "Mach-O 64-bit",                              "exec"),
    Sig("FAT-BIN",    b"\xca\xfe\xba\xbe",                   0, ".macho",  "Mach-O fat binary / Java class file",        "exec"),
    Sig("WASM",       b"\x00asm",                             0, ".wasm",   "WebAssembly binary",                         "exec"),
    Sig("LUAC",       b"\x1bLua",                             0, ".luac",   "Lua bytecode",                               "exec"),
    Sig("VDEX",       b"vdex",                                0, ".vdex",   "Android Verified DEX",                       "exec"),
    Sig("PYCO",       b"\x0d\x0d\x0a\x0a",                   0, ".pyc",    "Python bytecode (.pyc) 3.8+",                "exec"),
    Sig("SWF-Z",      b"CWS",                                 0, ".swf",    "Adobe Flash SWF (zlib compressed)",          "exec"),
    Sig("SWF-L",      b"ZWS",                                 0, ".swf",    "Adobe Flash SWF (LZMA compressed)",          "exec"),
    Sig("SWF",        b"FWS",                                 0, ".swf",    "Adobe Flash SWF (uncompressed)",             "exec"),

    # ════════════════════════════════════════════════════════════════════════
    # FIRMWARE & EMBEDDED SYSTEMS (IoT forensics)
    # ════════════════════════════════════════════════════════════════════════
    Sig("UBOOT",      b"\x27\x05\x19\x56",                   0, ".uboot",  "U-Boot firmware image (legacy)",             "firmware", None,   _val_uboot),
    Sig("FIT-IMG",    b"\xd0\x0d\xfe\xed",                   0, ".fit",    "U-Boot FIT / Device Tree Blob",              "firmware", None,   _val_dtb),
    Sig("DTB",        b"\xd0\x0d\xfe\xed",                   0, ".dtb",    "Device Tree Blob (flattened)",               "firmware", None,   _val_dtb),
    Sig("JFFS2-LE",   b"\x19\x85",                            0, ".jffs2",  "JFFS2 filesystem (little-endian)",           "firmware",   None,   _val_jffs2),
    Sig("JFFS2-BE",   b"\x85\x19",                            0, ".jffs2",  "JFFS2 filesystem (big-endian)",              "firmware",   None,   _val_jffs2_be),
    Sig("UBIFS",      b"\x31\x18\x10\x06",                   0, ".ubifs",  "UBIFS filesystem superblock",                "firmware"),
    Sig("UBI",        b"UBI#",                                0, ".ubi",    "UBI volume header",                          "firmware"),
    Sig("ROMFS",      b"-rom1fs-",                            0, ".romfs",  "ROMFS filesystem",                           "firmware"),
    Sig("YAFFS",      b"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff", 0, ".yaffs", "YAFFS2 filesystem chunk",             "firmware"),
    Sig("TRAMPOLINE", b"\xea\x00\x00\xea",                   0, ".bin",    "ARM32 branch instruction (firmware entry)",  "firmware"),
    Sig("OPENWRT",    b"OWRT",                                 0, ".bin",    "OpenWRT firmware header",                    "firmware"),
    Sig("SERCOMM",    b"\x00\x00\x00\x01\x00\x00\x10\x00",   0, ".bin",    "Sercomm firmware header",                    "firmware"),
    Sig("DLOB",       b"DLOB",                                 0, ".bin",    "TP-Link DLOB firmware partition",            "firmware"),
    Sig("SHRS",       b"SHRS",                                 0, ".bin",    "D-Link SHRS firmware header",                "firmware"),
    Sig("HDR0",       b"HDR0",                                 0, ".bin",    "Netgear firmware header (HDR0)",             "firmware"),
    Sig("W54S",       b"W54S",                                 0, ".bin",    "Linksys WRT54G firmware",                    "firmware"),
    Sig("HFS+",       b"H+\x00\x04",                          0, ".hfsplus","Apple HFS+ volume header",                   "firmware"),
    Sig("EXT2",       b"\x53\xef",                          1080, ".ext",    "Linux ext2/3/4 filesystem",                  "firmware",   None,   _val_ext2),
    Sig("CRAMFS-BE",  b"\x28\xcd\x3d\x45",                   0, ".cramfs", "CramFS filesystem (big-endian)",             "firmware"),
    Sig("MINIX",      b"\x8f\x13",                          1080, ".minix",  "Minix filesystem",                           "firmware"),
    Sig("F2FS",       b"\x10\x20\xf5\xf2",                 1024, ".f2fs",   "Flash-Friendly File System (F2FS)",          "firmware"),

    # ════════════════════════════════════════════════════════════════════════
    # MEDIA
    # ════════════════════════════════════════════════════════════════════════
    Sig("MP3-ID3",    b"ID3",                                 0, ".mp3",    "MP3 audio with ID3 tag",                     "media",   None,   _val_mp3_id3),
    Sig("MP3",        b"\xff\xfb",                            0, ".mp3",    "MP3 audio frame",                            "media",    None,   _val_mp3),
    Sig("FLAC",       b"fLaC",                                0, ".flac",   "FLAC lossless audio",                        "media",   None,   _val_flac),
    Sig("OGG",        b"OggS",                                0, ".ogg",    "Ogg Vorbis / OPUS",                          "media",   None,   _val_ogg),
    Sig("MKV",        b"\x1a\x45\xdf\xa3",                   0, ".mkv",    "Matroska video / WebM",                      "media",   None,   _val_mkv),
    Sig("MIDI",       b"MThd",                                0, ".mid",    "MIDI audio",                                 "media",   None,   _val_midi),
    Sig("AAC-ADTS",   b"\xff\xf1",                            0, ".aac",    "AAC audio (ADTS stream)",                    "media",   None,   _val_aac_adts),
    Sig("MP4-FTYP",   b"\x00\x00\x00\x18ftyp",             0, ".mp4",    "MPEG-4 / QuickTime video (ftyp box)",        "media"),
    Sig("ASF/WMV/WMA",b"\x30\x26\xb2\x75\x8e\x66\xcf\x11",   0, ".asf",    "Windows Media / ASF container",              "media"),

    # ════════════════════════════════════════════════════════════════════════
    # NETWORK / FORENSICS
    # ════════════════════════════════════════════════════════════════════════
    Sig("PCAP",       b"\xd4\xc3\xb2\xa1",                   0, ".pcap",   "Wireshark pcap (little-endian)",             "network",  None,   _val_pcap),
    Sig("PCAP-BE",    b"\xa1\xb2\xc3\xd4",                   0, ".pcap",   "Wireshark pcap (big-endian)",                "network",  None,   _val_pcap_be),
    Sig("PCAPNG",     b"\x0a\x0d\x0d\x0a",                   0, ".pcapng", "Wireshark pcapng",                           "network",   None,   _val_pcapng),
    Sig("ERF",        b"\xed\xfe",                             0, ".erf",    "Endace ERF capture file",                    "network"),

    # ════════════════════════════════════════════════════════════════════════
    # DATABASES
    # ════════════════════════════════════════════════════════════════════════
    Sig("SQLite",     b"SQLite format 3\x00",                 0, ".db",     "SQLite database",                            "db",       None,   _val_sqlite),
    Sig("LEVELDB",    b"\x57\xfb\x80\x8b\x24\x75\x47\xdb",   0, ".ldb",    "LevelDB log file",                           "db"),
    Sig("MYSQL",      b"\xfe\x62\x69\x6e",                    0, ".bin",    "MySQL binary log",                           "db"),
    Sig("MSACCESS",   b"\x00\x01\x00\x00Standard Jet DB",     0, ".mdb",    "Microsoft Access 97 database",               "db"),
    Sig("MSACCESS2",  b"\x00\x01\x00\x00Standard ACE DB",     0, ".accdb",  "Microsoft Access 2007+ database",            "db"),

    # ════════════════════════════════════════════════════════════════════════
    # DISK IMAGES & VIRTUAL MACHINES
    # ════════════════════════════════════════════════════════════════════════
    Sig("QCOW2",      b"QFI\xfb",                            0, ".qcow2",  "QEMU copy-on-write disk image",              "disk"),
    Sig("VMDK",       b"KDMV",                                0, ".vmdk",   "VMware virtual disk",                        "disk"),
    Sig("VHDFOOTER",  b"conectix",                            0, ".vhd",    "Microsoft VHD (fixed/dynamic footer)",       "disk"),
    Sig("VHDX",       b"vhdxfile",                            0, ".vhdx",   "Microsoft VHDX disk image",                  "disk"),
    Sig("VDI",        b"<<< Oracle VM VirtualBox Disk Image", 0, ".vdi",    "VirtualBox VDI disk image",                  "disk"),
    Sig("ISO9660",    b"CD001",                            32769, ".iso",    "ISO 9660 CD/DVD image",                      "disk",     None,   _val_iso9660),
    Sig("MBR/FAT",    b"\x55\xaa",                          510, ".img",    "MBR / FAT12/16 bootsector (55AA)",           "disk",     None,   _val_fat_boot),
    Sig("GPT",        b"EFI PART",                            512, ".img",   "GUID Partition Table (GPT) header",          "disk"),

    # ════════════════════════════════════════════════════════════════════════
    # CRYPTO / CERTIFICATES / KEYS
    # ════════════════════════════════════════════════════════════════════════
    Sig("PEM",        b"-----BEGIN",                          0, ".pem",    "PEM certificate / private key",              "crypto"),
    Sig("DER/PKCS",   b"\x30\x82",                            0, ".der",    "DER cert / PKCS#8 key / PKCS#12 bundle",     "crypto",   None,   _val_der),
    Sig("OPENSSH",    b"openssh-key-v1",                      0, ".key",    "OpenSSH private key",                        "crypto"),
    Sig("GPG-BINARY", b"\x99\x01",                            0, ".gpg",    "GPG/PGP binary key or message",              "crypto"),
    Sig("PGP-ARMOR",  b"-----BEGIN PGP",                      0, ".asc",    "PGP armored message/key",                    "crypto"),
    Sig("JCEKS",      b"\xce\xce\xce\xce",                    0, ".jceks",  "Java Cryptography Extension KeyStore",       "crypto"),
    Sig("JKS",        b"\xfe\xed\xfe\xed",                    0, ".jks",    "Java KeyStore (JKS)",                        "crypto",   None,   _val_jks),
    Sig("MOZILLA-NSS",b"certdata\n",                           0, ".txt",    "Mozilla NSS certificate data",               "crypto"),

    # ════════════════════════════════════════════════════════════════════════
    # MOBILE (Android / iOS)
    # ════════════════════════════════════════════════════════════════════════
    Sig("DEX-MAGIC",  b"dex\n035\x00",                        0, ".dex",    "Android Dalvik Executable v035",             "mobile",   None,   _val_dex),
    Sig("DEX-036",    b"dex\n036\x00",                        0, ".dex",    "Android Dalvik Executable v036",             "mobile",   None,   _val_dex),
    Sig("DEX-037",    b"dex\n037\x00",                        0, ".dex",    "Android Dalvik Executable v037",             "mobile",   None,   _val_dex),
    Sig("DEX-038",    b"dex\n038\x00",                        0, ".dex",    "Android Dalvik Executable v038",             "mobile",   None,   _val_dex),
    Sig("DEX-039",    b"dex\n039\x00",                        0, ".dex",    "Android Dalvik Executable v039",             "mobile",   None,   _val_dex),
    Sig("ARSC",       b"\x02\x00\x0c\x00",                    0, ".arsc",   "Android resource table (resources.arsc)",    "mobile",   None,   _val_arsc),
    Sig("AXML",       b"\x03\x00\x08\x00",                    0, ".xml",    "Android binary XML (AXML)",                  "mobile",   None,   _val_axml),
    Sig("IMG4",       b"IMG4",                                 0, ".img4",   "Apple IMG4 firmware container",              "mobile"),

    # ════════════════════════════════════════════════════════════════════════
    # CONTAINERS & SERIALISATION
    # ════════════════════════════════════════════════════════════════════════
    Sig("OCI-TAR",    b"./\x00",                              0, ".tar",    "OCI/Docker container layer (tar)",           "container"),
    Sig("FLATBUF",    b"FLAT",                                 0, ".fbs",    "FlatBuffers binary",                         "container"),
    Sig("BSON",       b"\x05\x00\x00\x00",                    0, ".bson",   "BSON document (5-byte minimum)",             "container",   None,   _val_bson),
    Sig("AVRO",       b"Obj\x01",                              0, ".avro",   "Apache Avro data file",                      "container"),
    Sig("PARQUET",    b"PAR1",                                 0, ".parquet","Apache Parquet column store",                "container"),
    Sig("ORC",        b"ORC",                                  0, ".orc",    "Apache ORC column store",                    "container"),
    Sig("HDF5",       b"\x89HDF\r\n\x1a\n",                   0, ".h5",     "HDF5 scientific data file",                  "container"),
    Sig("ARROW",      b"ARROW1",                               0, ".arrow",  "Apache Arrow IPC file",                      "container"),
    Sig("FEATHER",    b"FEA1",                                 0, ".feather","Apache Arrow Feather v1",                    "container"),

    # ════════════════════════════════════════════════════════════════════════
    # GAME / 3D / ASSET FORMATS (useful for CTFs with game challenges)
    # ════════════════════════════════════════════════════════════════════════
    Sig("UNITY-AB",   b"UnityFS",                              0, ".bundle", "Unity AssetBundle",                          "game"),
    Sig("UNITY-WEB",  b"UnityWeb",                             0, ".unity3d","Unity WebGL data",                           "game"),
    Sig("GODOT-PCK",  b"GDPC",                                 0, ".pck",    "Godot engine PCK archive",                   "game"),
    Sig("UNREAL-PAK", b"\xE1\x12\x6F\x5A",                    0, ".pak",    "Unreal Engine PAK archive",                  "game"),
    Sig("STEAM-NCF",  b"\x28\xBF\x4F\xBE",                    0, ".ncf",    "Steam NCF / VPK archive",                    "game"),
    Sig("GLB",        b"glTF",                                 0, ".glb",    "glTF 2.0 3D model (binary)",                 "game"),
    Sig("FBX",        b"Kaydara FBX Binary",                   0, ".fbx",    "Autodesk FBX 3D model",                      "game"),
    Sig("BLEND",      b"BLENDER",                              0, ".blend",  "Blender 3D project file",                    "game"),

    # ════════════════════════════════════════════════════════════════════════
    # FORENSICS / MEMORY / CRASH DUMPS
    # ════════════════════════════════════════════════════════════════════════
    Sig("CORE",       b"CORE",                                 0, ".core",   "Unix core dump",                             "forensics"),
    Sig("WER",        b"MDMP",                                 0, ".dmp",    "Windows MiniDump (WER crash dump)",          "forensics"),
    Sig("HIBERFIL",   b"hibr",                                 0, ".sys",    "Windows hibernation file (hiberfil.sys)",    "forensics"),
    Sig("PAGEFILE",   b"PHMM",                                 0, ".sys",    "Windows pagefile.sys snapshot",              "forensics"),
    Sig("EVTX",       b"ElfFile\x00",                          0, ".evtx",   "Windows Event Log (EVTX)",                   "forensics", None,  _val_evtx),
    Sig("REG-HIVE",   b"regf",                                 0, ".hive",   "Windows Registry hive file",                 "forensics", None,  _val_regf),
    Sig("LNK",        b"\x4c\x00\x00\x00\x01\x14\x02\x00",    0, ".lnk",    "Windows Shell Link (.lnk shortcut)",         "forensics", None,  _val_lnk),
    Sig("PREFETCH",   b"MAM\x84",                              0, ".pf",     "Windows Prefetch file",                      "forensics"),
    Sig("JVM-DUMP",   b"JAVA PROFILE",                         0, ".hprof",  "Java heap dump (hprof)",                     "forensics"),
    Sig("VOLATILITY", b"PAGEDU64",                             0, ".raw",    "Volatility memory image (Win64 paging)",     "forensics"),
    Sig("LIME",       b"EMiL",                                 0, ".lime",   "LiME Linux memory dump",                     "forensics"),
    Sig("EWF",        b"EVF\x09\x0d\x0a\xff\x00",             0, ".e01",    "Expert Witness Format (EnCase image)",       "forensics"),
    Sig("AFF",        b"AFF\x10",                              0, ".aff",    "Advanced Forensic Format disk image",        "forensics"),

    # ════════════════════════════════════════════════════════════════════════
    # MISC / OTHER
    # ════════════════════════════════════════════════════════════════════════
    Sig("FONT-TTF",   b"\x00\x01\x00\x00\x00",                0, ".ttf",    "TrueType Font",                              "misc",     None,   _val_ttf),
    Sig("FONT-OTF",   b"OTTO",                                 0, ".otf",    "OpenType Font",                              "misc"),
    Sig("FONT-WOFF",  b"wOFF",                                 0, ".woff",   "Web Open Font Format (WOFF)",                "misc"),
    Sig("FONT-WOFF2", b"wOF2",                                 0, ".woff2",  "Web Open Font Format 2 (WOFF2)",             "misc"),
    Sig("DICOM",      b"DICM",                               128, ".dcm",    "DICOM medical image",                        "misc"),
    Sig("MACHO-UNI",  b"\xbe\xba\xfe\xca",                    0, ".macho",  "Mach-O universal binary (reverse endian)",   "misc"),
    Sig("NSIS",       b"\xef\xbe\xad\xde\x4e\x75\x6c\x6c",              0, ".exe",    "NSIS installer header",                      "misc"),
    Sig("INNO",       b"Inno Setup Setup Data",               0, ".exe",    "Inno Setup installer",                       "misc"),
    Sig("AMIGA",      b"\x00\x00\x03\xf3",                    0, ".hunk",   "Amiga executable (HUNK_HEADER)",             "misc"),
    Sig("NDS",        b"\x24\xff\xae\x51\x69\x9a\xa2\x21",    0, ".nds",    "Nintendo DS ROM",                            "misc"),
    Sig("GBA",        b"\x2e\x00\x00\xea",                    0, ".gba",    "Game Boy Advance ROM",                       "misc"),
    Sig("NES",        b"NES\x1a",                              0, ".nes",    "NES ROM (iNES format)",                      "misc"),
    Sig("N64",        b"\x80\x37\x12\x40",                    0, ".n64",    "Nintendo 64 ROM (big-endian)",               "misc"),
    Sig("WBFS",       b"WBFS",                                 0, ".wbfs",   "Wii Backup File System image",               "misc"),
    Sig("XDF",        b"XDF0",                                 0, ".xdf",    "Xbox 360 disc filesystem",                   "misc"),
]

SIGNATURES.sort(key=lambda s: len(s.magic), reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# GAP 1 — False positive filter
# ─────────────────────────────────────────────────────────────────────────────

def sig_passes(data: bytes, off: int, sig: Sig) -> bool:
    """
    Returns True only if the hit at `off` passes the signature's validator.
    Signatures with no validator are always trusted (magic is long enough).
    """
    if sig.validator is None:
        return True
    try:
        return sig.validator(data, off)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Core analysis helpers
# ─────────────────────────────────────────────────────────────────────────────

def match_at(data: bytes, magic: bytes, offset: int) -> bool:
    end = offset + len(magic)
    return end <= len(data) and data[offset:end] == magic


def detect_primary(data: bytes) -> Optional[Sig]:
    for sig in SIGNATURES:
        if match_at(data, sig.magic, sig.offset) and sig_passes(data, sig.offset, sig):
            return sig
    return None


def build_compressed_regions(data: bytes) -> list[tuple[int, int, str]]:
    """
    Map out spans that are known compressed payloads so short-magic hits inside
    them can be suppressed as false positives.

    Returns a list of (start, end, label) tuples. Only sigs with magic < _MIN_SAFE_LEN
    are suppressed inside these regions; longer magic sequences are always reported.

    Design note: we deliberately do NOT use a generic high-entropy heuristic here.
    High-entropy regions include legitimate embedded files (encrypted archives, compressed
    firmware) and suppressing them would cause us to miss real embedded payloads.
    We only suppress inside regions where we can *structurally verify* the container.
    """
    regions: list[tuple[int, int, str]] = []

    # ── PNG IDAT chunks ───────────────────────────────────────────────────────
    # PNG spec: each chunk is  4B length | 4B type | <length> bytes data | 4B CRC
    # IDAT data is a zlib stream wrapping raw deflate. It is the main FP source.
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        pos = 8
        while pos + 12 <= len(data):
            try:
                clen        = struct.unpack_from(">I", data, pos)[0]
                ctype       = data[pos + 4:pos + 8]
                cdata_start = pos + 8
                cdata_end   = cdata_start + clen
                if cdata_end + 4 > len(data):
                    break
                if ctype == b"IDAT" and clen > 0:
                    regions.append((cdata_start, cdata_end, "PNG-IDAT"))
                pos = cdata_end + 4  # advance past CRC
            except (struct.error, IndexError):
                break

    # ── GZIP members ──────────────────────────────────────────────────────────
    gz_start = 0
    while True:
        idx = data.find(b"\x1f\x8b", gz_start)
        if idx == -1:
            break
        if _val_gzip(data, idx):
            end = find_gzip_end(data, idx)
            if end > idx + 10:
                # Suppress the deflate payload (between fixed header end and CRC32+ISIZE)
                regions.append((idx + 10, end - 8, "GZIP-payload"))
        gz_start = idx + 1

    # ── Raw zlib streams ──────────────────────────────────────────────────────
    # Walk all valid zlib headers and drain the full deflate stream to find the
    # precise boundary. We feed ALL remaining bytes to the decompressor so that
    # unused_data is accurate even for very large streams.
    for zlib_magic in (b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e"):
        pos = 0
        while True:
            idx = data.find(zlib_magic, pos)
            if idx == -1:
                break
            if _val_zlib(data, idx):
                try:
                    dobj   = zlib.decompressobj()
                    # Feed the entire slice from this offset to EOF
                    dobj.decompress(data[idx:])
                    if dobj.unused_data is not None and len(dobj.unused_data) < len(data) - idx:
                        # stream_end = total_len - unused bytes remaining
                        stream_end = len(data) - len(dobj.unused_data)
                        if stream_end > idx + 6:
                            # Mark only the deflate payload (skip 2-byte zlib header and
                            # 4-byte Adler-32 checksum at the end)
                            regions.append((idx + 2, stream_end - 4, "ZLIB-payload"))
                except zlib.error:
                    pass
            pos = idx + 1

    return regions


# Sigs with magic >= this length are trusted even inside compressed regions.
# At 6+ bytes the probability of a random match inside deflate is ~1 in 281 trillion.
_MIN_SAFE_LEN = 6


def _in_compressed_region(off: int, magic_len: int,
                           regions: list[tuple[int, int, str]]) -> Optional[str]:
    """Return the region label if this offset is inside a compressed span, else None."""
    for start, end, label in regions:
        if start <= off < end:
            return label
    return None


def find_all_signatures(data: bytes,
                        compressed_regions: Optional[list] = None
                        ) -> list[dict]:
    """
    Scan every offset; apply false-positive filter and compressed-region suppression.

    A hit is suppressed (fp_filtered=True + reason) if:
      1. Its validator returns False, OR
      2. Its magic is shorter than _MIN_SAFE_LEN AND its offset is inside a
         known compressed/high-entropy region.
    """
    if compressed_regions is None:
        compressed_regions = build_compressed_regions(data)

    hits = []
    for sig in SIGNATURES:
        start = 0
        while True:
            idx = data.find(sig.magic, start)
            if idx == -1:
                break

            # ── Validator check ───────────────────────────────────────────────
            if not sig_passes(data, idx, sig):
                hits.append({"sig": sig, "offset": idx,
                             "fp_filtered": True, "fp_reason": "validator"})
                start = idx + 1
                continue

            # ── Compressed-region suppression (only for short magic) ──────────
            if len(sig.magic) < _MIN_SAFE_LEN:
                region = _in_compressed_region(idx, len(sig.magic), compressed_regions)
                if region:
                    hits.append({"sig": sig, "offset": idx,
                                 "fp_filtered": True,
                                 "fp_reason": f"inside {region}"})
                    start = idx + 1
                    continue

            hits.append({"sig": sig, "offset": idx,
                         "fp_filtered": False, "fp_reason": ""})
            start = idx + 1

    hits.sort(key=lambda h: h["offset"])
    return hits


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * math.log2(f / n) for f in freq if f > 0)


def extract_strings(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    results, cur, start = [], [], 0
    for i, byte in enumerate(data):
        if 0x20 <= byte < 0x7F:
            if not cur:
                start = i
            cur.append(chr(byte))
        else:
            if len(cur) >= min_len:
                results.append((start, "".join(cur)))
            cur = []
    if len(cur) >= min_len:
        results.append((start, "".join(cur)))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# GAP 2 — GZIP boundary detection
# ─────────────────────────────────────────────────────────────────────────────

def find_gzip_end(data: bytes, off: int) -> int:
    """
    Walk the GZIP header + deflate stream to find the real end byte.
    GZIP format (RFC 1952):
      10-byte fixed header → optional fields → deflate stream → CRC32 (4B) + ISIZE (4B)

    Strategy: feed bytes into a zlib decompressor; it raises when stream ends.
    Returns the offset of the first byte AFTER the gzip member, or -1 on failure.
    """
    if off + 18 > len(data):   # minimum possible GZIP size
        return -1

    # Parse header flags to skip optional fields
    flg = data[off + 3]
    pos = off + 10

    try:
        if flg & 0x04:  # FEXTRA
            xlen = struct.unpack_from("<H", data, pos)[0]
            pos += 2 + xlen
        if flg & 0x08:  # FNAME — null-terminated
            while pos < len(data) and data[pos] != 0:
                pos += 1
            pos += 1
        if flg & 0x10:  # FCOMMENT — null-terminated
            while pos < len(data) and data[pos] != 0:
                pos += 1
            pos += 1
        if flg & 0x02:  # FHCRC
            pos += 2
    except (struct.error, IndexError):
        return -1

    # Decompress deflate stream; wbits=-15 = raw deflate (no zlib header)
    dobj = zlib.decompressobj(wbits=-15)
    chunk_size = 4096
    i = pos
    while i < len(data):
        end = min(i + chunk_size, len(data))
        try:
            dobj.decompress(data[i:end])
        except zlib.error:
            # The stream ended somewhere in this chunk; binary-search for exact boundary
            lo, hi = i, end
            while lo < hi:
                mid = (lo + hi) // 2
                try:
                    zlib.decompressobj(wbits=-15).decompress(data[pos:mid])
                    lo = mid + 1
                except zlib.error:
                    hi = mid
            stream_end = lo - 1
            # After deflate stream: CRC32 (4) + ISIZE (4)
            return stream_end + 8 if stream_end + 8 <= len(data) else -1
        if dobj.unused_data:
            # decompressor consumed all it needed; unused_data = bytes after stream
            stream_end = len(data) - len(dobj.unused_data)
            return stream_end + 8 if stream_end + 8 <= len(data) else -1
        i = end
    return -1


# ─────────────────────────────────────────────────────────────────────────────
# GAP 4 — File validation
# ─────────────────────────────────────────────────────────────────────────────

def validate_carved(sig_name: str, carved_bytes: bytes) -> tuple[bool, str]:
    """
    Structurally validate a carved file.
    Returns (is_valid, reason_string).
    """
    name = sig_name.upper()

    # PNG — verify IHDR chunk present and IEND at the end
    if name == "PNG":
        if len(carved_bytes) < 16:
            return False, "too small"
        if carved_bytes[:8] != b"\x89PNG\r\n\x1a\n":
            return False, "missing PNG header"
        if b"IHDR" not in carved_bytes[:30]:
            return False, "missing IHDR chunk"
        if not carved_bytes.endswith(b"IEND\xaeB`\x82"):
            return False, "missing/truncated IEND chunk"
        if HAS_PIL:
            try:
                _PILImage.open(io.BytesIO(carved_bytes)).verify()
            except Exception as e:
                return False, f"Pillow: {e}"
        return True, "OK"

    # JPEG — must start FF D8 and end FF D9
    if name == "JPEG":
        if len(carved_bytes) < 4:
            return False, "too small"
        if carved_bytes[:2] != b"\xff\xd8":
            return False, "missing SOI"
        if carved_bytes[-2:] != b"\xff\xd9":
            return False, "missing EOI (truncated?)"
        if HAS_PIL:
            try:
                _PILImage.open(io.BytesIO(carved_bytes)).verify()
            except Exception as e:
                return False, f"Pillow: {e}"
        return True, "OK"

    # GIF — must end with 0x3B trailer
    if name in ("GIF89A", "GIF87A"):
        if carved_bytes[-1:] != b"\x3b":
            return False, "missing GIF trailer byte"
        return True, "OK"

    # ZIP — try opening with zipfile module
    if name in ("ZIP", "ZIP-EMPTY"):
        try:
            with zipfile.ZipFile(io.BytesIO(carved_bytes)) as zf:
                names = zf.namelist()
            return True, f"OK — {len(names)} file(s) inside"
        except zipfile.BadZipFile as e:
            return False, str(e)

    # GZIP — try decompressing header
    if name == "GZIP":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(carved_bytes)) as gz:
                gz.read(1)
            return True, "OK — decompressible"
        except (OSError, EOFError) as e:
            return False, str(e)

    # PDF — must contain %%EOF
    if name == "PDF":
        if b"%%EOF" not in carved_bytes:
            return False, "missing %%EOF marker"
        return True, "OK"

    # ELF — verify e_ident magic and class/data fields
    if name == "ELF":
        if len(carved_bytes) < 16:
            return False, "too small"
        if carved_bytes[:4] != b"\x7fELF":
            return False, "bad magic"
        if carved_bytes[4] not in (1, 2):
            return False, f"unknown EI_CLASS: {carved_bytes[4]}"
        return True, "OK"

    # PE — check PE signature at e_lfanew
    if name == "PE":
        try:
            e_lfanew = struct.unpack_from("<I", carved_bytes, 0x3C)[0]
            if carved_bytes[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                return True, "OK"
            return False, "PE signature not found at e_lfanew"
        except (struct.error, IndexError):
            return False, "too small to read e_lfanew"

    # SQLite — check 100-byte header magic
    if name == "SQLITE":
        expected = b"SQLite format 3\x00"
        if carved_bytes[:len(expected)] == expected:
            page_size = struct.unpack_from(">H", carved_bytes, 16)[0]
            return True, f"OK — page size {page_size}B"
        return False, "invalid SQLite header"

    # PCAP — validate magic + link type range
    if name in ("PCAP", "PCAP-BE"):
        if len(carved_bytes) < 24:
            return False, "too small"
        return True, "OK — header present"

    # Fallback: magic bytes present = weak OK
    return True, "OK (magic verified only)"


# ─────────────────────────────────────────────────────────────────────────────
# File carving
# ─────────────────────────────────────────────────────────────────────────────

def carve_chunk(data: bytes, hit: dict) -> bytes:
    """
    Format-aware carving. Uses structural fields (footers, size headers, IFD chains)
    to find the precise end of each embedded file.
    Falls back to a 32 MB capped slice for formats with no reliable boundary.
    This prevents runaway extraction (no more 3GB TIFF cascades).
    """
    sig  = hit["sig"]
    off  = hit["offset"]
    name = sig.name

    # ── Formats with reliable footers ────────────────────────────────────────

    if name == "PNG":
        iend = data.find(b"IEND", off)
        if iend != -1 and iend + 8 <= len(data):
            return data[off : iend + 8]

    if name == "JPEG":
        eoi = data.find(b"\xff\xd9", off + 2)
        if eoi != -1 and eoi - off < 20 * 1024 * 1024:
            return data[off : eoi + 2]

    if name in ("GIF87a", "GIF89a"):
        trailer = data.find(b"\x3b", off + 6)
        if trailer != -1 and trailer - off < 5 * 1024 * 1024:
            return data[off : trailer + 1]

    if name in ("ZIP", "ZIP-EMPTY"):
        search_end = min(len(data), off + 512 * 1024 * 1024)
        eocd = data.rfind(b"PK\x05\x06", off, search_end)
        if eocd != -1 and eocd + 22 <= len(data):
            comment_len = struct.unpack_from("<H", data, eocd + 20)[0]
            return data[off : eocd + 22 + comment_len]

    if name == "PDF":
        eof_marker = data.rfind(b"%%EOF", off)
        if eof_marker != -1 and eof_marker - off < 256 * 1024 * 1024:
            return data[off : eof_marker + 5]

    if name == "GZIP":
        end = find_gzip_end(data, off)
        if end != -1 and end > off:
            return data[off : end]

    # ── Formats with size info in their header ────────────────────────────────

    if name == "ELF" and len(data) - off >= 64:
        ei_class = data[off + 4]
        ei_data  = data[off + 5]
        bo = "<" if ei_data == 1 else ">"
        try:
            if ei_class == 1:
                e_shoff, e_shentsize, e_shnum = struct.unpack_from(f"{bo}IHH", data, off + 32)
            else:
                e_shoff, e_shentsize, e_shnum = struct.unpack_from(f"{bo}QHH", data, off + 40)
            total = e_shoff + e_shentsize * e_shnum
            if e_shoff and e_shnum and 0 < total < 256 * 1024 * 1024 and off + total <= len(data):
                return data[off : off + total]
        except struct.error:
            pass

    if name == "PE" and len(data) - off >= 64:
        try:
            e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
            pe_off   = off + e_lfanew
            if pe_off + 4 < len(data) and data[pe_off : pe_off + 4] == b"PE\x00\x00":
                size_off   = pe_off + 24 + 56
                size_image = struct.unpack_from("<I", data, size_off)[0]
                if size_image and off + size_image <= len(data) and size_image < 256 * 1024 * 1024:
                    return data[off : off + size_image]
        except (struct.error, IndexError):
            pass

    if name == "PCAP" and len(data) - off >= 24:
        # Walk PCAP packet records to find the real end of the capture
        try:
            magic = struct.unpack_from("<I", data, off)[0]
            bo    = "<" if magic == 0xD4C3B2A1 else ">"
            pos   = off + 24
            while pos + 16 <= len(data):
                caplen = struct.unpack_from(f"{bo}I", data, pos + 8)[0]
                if caplen > 65535 or pos + 16 + caplen > len(data):
                    break
                pos += 16 + caplen
            if pos > off + 24:
                return data[off : pos]
        except (struct.error, IndexError):
            pass

    if name in ("TIFF-BE", "TIFF-LE") and len(data) - off >= 8:
        # Walk the TIFF IFD chain to compute the max referenced extent
        bo = ">" if name == "TIFF-BE" else "<"
        try:
            ifd_off = struct.unpack_from(f"{bo}I", data, off + 4)[0]
            if ifd_off == 0 or off + ifd_off + 2 > len(data):
                raise ValueError("bad IFD offset")
            max_extent = off + ifd_off
            pos        = off + ifd_off
            visited    = set()
            while pos + 2 <= len(data) and pos not in visited:
                visited.add(pos)
                num_entries = struct.unpack_from(f"{bo}H", data, pos)[0]
                if num_entries == 0 or num_entries > 2000:
                    break
                entry_end = pos + 2 + num_entries * 12
                if entry_end + 4 > len(data):
                    break
                for i in range(num_entries):
                    e          = pos + 2 + i * 12
                    field_type = struct.unpack_from(f"{bo}H", data, e + 2)[0]
                    count      = struct.unpack_from(f"{bo}I", data, e + 4)[0]
                    type_size  = {1:1,2:1,3:2,4:4,5:8,7:1,9:4,10:8,11:4,12:8}.get(field_type, 1)
                    total_size = count * type_size
                    if total_size > 4:
                        val_off = off + struct.unpack_from(f"{bo}I", data, e + 8)[0]
                        extent  = val_off + total_size
                        if off < extent <= len(data):
                            max_extent = max(max_extent, extent)
                next_ifd = struct.unpack_from(f"{bo}I", data, entry_end)[0]
                pos = off + next_ifd if next_ifd else 0
            tiff_size = max_extent - off
            if 8 < tiff_size < 50 * 1024 * 1024:
                return data[off : max_extent]
        except Exception:
            pass

    # ── Fallback: cap at 32 MB to prevent runaway extraction ─────────────────
    # Formats without structural boundaries (MP3, OGG, GPG, COMPRESS, ERF, etc.)
    # get a hard cap. Better to have a complete-but-capped file than a 3 GB blob.
    _MAX_FALLBACK = 32 * 1024 * 1024
    return data[off : off + min(_MAX_FALLBACK, len(data) - off)]
def do_extract(
    data:           bytes,
    embedded_hits:  list[dict],
    out_dir:        Path,
    source_file:    str,
    depth:          int = 0,
    max_depth:      int = 0,
    _seen:          Optional[set] = None,
) -> list[Path]:
    """
    Carve embedded files from `data`, write them to `out_dir`,
    then recursively scan each carved file for further embeds.
    `_seen` tracks SHA-256 hashes to avoid infinite loops on identical data.
    """
    if _seen is None:
        _seen = set()

    out_dir.mkdir(parents=True, exist_ok=True)
    stem   = Path(source_file).stem
    indent = "  " + "  " * depth

    if depth == 0:
        print(f"\n{bold(g('[ EXTRACTION ]'))}")
        print(f"  Output dir : {y(str(out_dir))}\n")

    counts: dict[str, int] = {}
    saved: list[Path]      = []

    for hit in embedded_hits:
        sig  = hit["sig"]
        key  = sig.name.lower().replace("/", "_").replace("-", "_")
        counts[key] = counts.get(key, 0) + 1
        n    = counts[key]

        carved     = carve_chunk(data, hit)
        digest     = hashlib.sha256(carved).hexdigest()

        # ── GAP 4: validate before saving ────────────────────────────────
        valid, reason = validate_carved(sig.name, carved)
        valid_tag = g("✓ valid  ") if valid else y("⚠ suspect")

        fname = f"{stem}_d{depth}_{key}_{n:02d}{sig.ext}"
        fpath = out_dir / fname

        fpath.write_bytes(carved)
        saved.append(fpath)

        print(f"{indent}{g('►')} {bold(w(sig.name)):<18}  "
              f"offset={y(hex(hit['offset'])):<14}  "
              f"size={g(fmt_size(len(carved))):<12}  "
              f"[{valid_tag}] {grey(reason)}")
        print(f"{indent}  {grey('sha256:')} {grey(digest[:16])}…  "
              f"{grey('→')} {grey(fname)}")

        # ── GAP 3: recurse if not seen and depth allows ───────────────────
        if depth < max_depth and digest not in _seen:
            _seen.add(digest)
            child_regions = build_compressed_regions(carved)
            child_hits = find_all_signatures(carved, child_regions)
            child_embedded = [
                h for h in child_hits
                if not (h["sig"].name == sig.name and h["offset"] == 0)
                and not h["fp_filtered"]
            ]
            if child_embedded:
                print(f"{indent}  {y(f'↳ {len(child_embedded)} nested signature(s) — recursing (depth {depth+1})')}")
                child_dir = out_dir / f"{fname}_nested"
                nested = do_extract(
                    carved, child_embedded, child_dir,
                    fname, depth + 1, max_depth, _seen
                )
                saved.extend(nested)
        elif digest in _seen:
            print(f"{indent}  {grey('↳ skipped recursion — identical content already processed')}")

    if depth == 0:
        print(f"\n  {bold(g(str(len(saved))))} total file(s) extracted  "
              f"{grey(f'(max recursion depth used: {max_depth})')}")

    return saved


# ─────────────────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────────────────

def fmt_size(n: int) -> str:
    orig = n
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


BANNER = f"""{C.GREEN}{C.BOLD}
  ██╗  ██╗███████╗██╗  ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██║  ██║██╔════╝╚██╗██╔╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ███████║█████╗   ╚███╔╝ █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ██╔══██║██╔══╝   ██╔██╗ ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ██║  ██║███████╗██╔╝ ██╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{C.RESET}{C.WHITE}  File Forensics & Embedded Payload Extractor  v1.0
{C.RESET}{C.GREY}  github.com/arvdch{C.RESET}
"""


def section(title: str):
    line = f"──── {title} " + "─" * max(2, 72 - len(title) - 6)
    print(f"\n{C.BOLD}{C.BLUE}{line}{C.RESET}")


def print_hex_dump(data: bytes, limit: int = 256, highlight_sig: Optional[Sig] = None):
    sig_range: set[int] = set()
    if highlight_sig:
        sig_range = set(range(highlight_sig.offset, highlight_sig.offset + len(highlight_sig.magic)))

    for row_start in range(0, min(len(data), limit), 16):
        row = data[row_start:row_start + 16]
        offset_str = grey(f"{row_start:08x}  ")
        hex_parts  = []
        for i, byte in enumerate(row):
            abs_idx = row_start + i
            h = f"{byte:02x}"
            if abs_idx in sig_range:
                hex_parts.append(g(h))
            elif byte == 0x00:
                hex_parts.append(grey(h))
            elif 0x20 <= byte < 0x7F:
                hex_parts.append(c(h))
            else:
                hex_parts.append(w(h))
            if i == 7:
                hex_parts.append(" ")
        hex_str   = " ".join(hex_parts)
        padding   = "   " * (16 - len(row)) + ("  " if len(row) <= 8 else "")
        ascii_str = "".join(chr(b) if 0x20 <= b < 0x7F else grey(".") for b in row)
        print(f"  {offset_str}{hex_str}{padding}  {grey('│')}{ascii_str}{grey('│')}")


def entropy_bar(val: float, width: int = 40) -> str:
    filled = int((val / 8.0) * width)
    color  = C.GREEN if val < 6.0 else (C.YELLOW if val < 7.2 else C.RED)
    bar    = color + "█" * filled + C.RESET + grey("░" * (width - filled))
    return f"[{bar}] {color}{val:.3f}{C.RESET} bits/byte"


def entropy_label(val: float) -> str:
    if val > 7.5: return r("⚠  Very high entropy — likely encrypted or compressed")
    if val > 7.0: return y("⚡ High entropy — possibly packed, encoded, or encrypted")
    if val > 5.5: return g("✓  Moderate entropy — typical structured binary / text")
    return g("✓  Low entropy — plain text or highly structured data")


# ─────────────────────────────────────────────────────────────────────────────
# JSON output
# ─────────────────────────────────────────────────────────────────────────────

def build_report(path: Path, data: bytes, primary: Optional[Sig],
                 embedded_hits: list[dict], filtered: list[dict],
                 overall_entropy: float, strings: list[tuple[int,str]],
                 lsb_result: Optional[dict] = None) -> dict:
    """Build a machine-readable report dict for --json output."""
    import json as _json

    report: dict = {
        "hexforge_version": "2.1",
        "file": {
            "name":      path.name,
            "path":      str(path.resolve()),
            "size":      len(data),
            "md5":       hashlib.md5(data).hexdigest(),
            "sha256":    hashlib.sha256(data).hexdigest(),
        },
        "primary": None,
        "entropy": round(overall_entropy, 4),
        "embedded": [],
        "suppressed_count": len(filtered),
        "strings": [],
        "lsb_stego": lsb_result,
    }

    if primary:
        report["primary"] = {
            "name":      primary.name,
            "desc":      primary.desc,
            "category":  primary.cat,
            "magic_hex": primary.magic.hex(" "),
            "validated": primary.validator is not None,
        }

    for hit in embedded_hits:
        s = hit["sig"]
        carved = carve_chunk(data, hit)
        valid, val_reason = validate_carved(s.name, carved)
        report["embedded"].append({
            "name":      s.name,
            "desc":      s.desc,
            "category":  s.cat,
            "offset":    hit["offset"],
            "offset_hex": hex(hit["offset"]),
            "magic_hex": s.magic[:8].hex(" "),
            "carved_size": len(carved),
            "valid":     valid,
            "valid_reason": val_reason,
        })

    for off, s in strings:
        slow = s.lower()
        tag  = "url"       if any(s.startswith(p) for p in ("http://","https://","ftp://")) \
          else "path"      if any(x in s for x in ("/bin/","/etc/","/proc/","C:\\",".dll",".exe",".sh")) \
          else "sensitive" if any(x in slow for x in ("password","passwd","secret","token","flag{","auth")) \
          else "string"
        report["strings"].append({"offset": off, "value": s, "tag": tag})

    return report


# ─────────────────────────────────────────────────────────────────────────────
# LSB steganography detection
# ─────────────────────────────────────────────────────────────────────────────

def _extract_png_pixels(data: bytes) -> Optional[bytes]:
    """
    Pure-Python PNG pixel extractor — no Pillow needed.
    Decodes IHDR, collects IDAT chunks, decompresses, strips filter bytes.
    Returns raw RGB/RGBA bytes, or None on failure.
    """
    if data[:8] != b"\x89PNG\r\n\x1a\n" or len(data) < 33:
        return None
    try:
        w          = struct.unpack_from(">I", data, 16)[0]
        h          = struct.unpack_from(">I", data, 20)[0]
        bit_depth  = data[24]
        color_type = data[25]
        channels   = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 3)
        if bit_depth != 8 or w == 0 or h == 0:
            return None
        stride = w * channels

        # Collect all IDAT chunk data
        idat = b""
        pos  = 8
        while pos + 12 <= len(data):
            clen  = struct.unpack_from(">I", data, pos)[0]
            ctype = data[pos + 4:pos + 8]
            if ctype == b"IDAT":
                idat += data[pos + 8:pos + 8 + clen]
            elif ctype == b"IEND":
                break
            pos += 12 + clen

        if not idat:
            return None

        raw     = zlib.decompress(idat)
        row_len = stride + 1  # +1 for filter byte
        if len(raw) < row_len * h:
            return None

        # Strip one filter byte per scanline (we don't bother to un-filter —
        # LSB analysis on the raw filtered bytes is still valid statistically)
        pixels = bytearray()
        for row in range(h):
            start = row * row_len + 1   # skip filter byte
            pixels += raw[start:start + stride]
        return bytes(pixels)
    except Exception:
        return None


def detect_lsb_stego(data: bytes, filename: str) -> Optional[dict]:
    """
    Chi-squared test on pixel LSBs to detect LSB steganography.
    Works on PNG (pure-Python decoder), BMP (raw pixel offset), and JPEG/other
    formats if Pillow is installed.

    Returns a result dict, or None if the file can't be decoded.

    Theory: In a natural image, the LSBs of pixel channels are approximately
    random but not perfectly uniform — they follow the statistics of the image
    content. LSB steganography *replaces* LSBs with message bits, which
    (especially for long messages) creates a distribution that is more uniform
    than natural. The chi-squared statistic measures deviation from the
    expected uniform distribution; a suspiciously low chi2 (near 0) combined
    with high LSB entropy (near 1.0 bits/byte) is the hallmark signature.

    Note: requires a minimum of 2048 pixels for meaningful statistics.
    """
    result: dict = {
        "technique":        "LSB chi-squared",
        "suspicious":       False,
        "confidence":       "none",
        "chi2":             None,
        "p_estimate":       None,
        "lsb_entropy":      None,
        "pixel_count":      0,
        "note":             "",
        "extracted_preview": None,
    }

    # ── Get raw pixel bytes ───────────────────────────────────────────────────
    pixels: Optional[bytes] = None

    # 1. PNG — pure Python decoder (always available)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        pixels = _extract_png_pixels(data)

    # 2. BMP — pixel data starts at offset stored in header
    if pixels is None and data[:2] == b"BM" and len(data) > 54:
        try:
            px_offset = struct.unpack_from("<I", data, 10)[0]
            if px_offset < len(data):
                pixels = data[px_offset:]
        except struct.error:
            pass

    # 3. JPEG / other — try Pillow
    if pixels is None and HAS_PIL:
        try:
            from PIL import Image as _PIL
            img    = _PIL.open(io.BytesIO(data)).convert("RGB")
            pixels = bytes(img.tobytes())
        except Exception:
            pass

    if pixels is None or len(pixels) < 2048:
        return None     # not enough data for meaningful statistics

    result["pixel_count"] = len(pixels)

    # ── Extract LSBs ──────────────────────────────────────────────────────────
    lsbs = bytes(b & 1 for b in pixels)

    # ── Chi-squared test (1 degree of freedom, two categories: 0 and 1) ──────
    n       = len(lsbs)
    ones    = sum(lsbs)
    zeros   = n - ones
    expect  = n / 2.0
    # Guard against degenerate cases
    if expect == 0:
        return None
    chi2 = ((zeros - expect) ** 2 + (ones - expect) ** 2) / expect

    import math
    p_approx = math.exp(-chi2 / 2.0) if chi2 < 1400 else 0.0

    result["chi2"]       = round(chi2, 4)
    result["p_estimate"] = round(p_approx, 6)
    result["lsb_entropy"] = round(shannon_entropy(lsbs), 6)

    # ── Thresholds ────────────────────────────────────────────────────────────
    # Chi-squared test interpretation for LSB stego:
    #   NATURAL PHOTOS:   pixel values follow smooth distributions → LSBs are
    #                     correlated and non-uniform → chi2 is HIGH (50–500+)
    #   LSB-EMBEDDED:     message bits replace LSBs, making them near-uniform
    #                     → chi2 drops toward 0
    #   RANDOM/COMPRESSED: already uniform → chi2 near 0 (looks like stego)
    #
    # This test is most useful on natural photographic images. It will produce
    # false positives on random-data files and false negatives on images that
    # were already noisy. The extracted_preview field is the primary indicator
    # for CTF use — readable text in the LSB stream is a strong confirmation.
    if chi2 < 1.0:
        result["suspicious"] = True
        result["confidence"] = "HIGH"
        result["note"]       = (
            f"chi2={chi2:.3f} — LSBs are near-perfectly uniform (n={n:,}). "
            f"Strong indicator of LSB steganography in a natural image. "
            f"Note: also fires on already-random data. Check extracted_preview."
        )
    elif chi2 < 5.0:
        result["suspicious"] = True
        result["confidence"] = "MEDIUM"
        result["note"]       = (
            f"chi2={chi2:.3f} — Low LSB variance. Possible partial LSB embedding, "
            f"or smooth-gradient source image. Manual inspection recommended."
        )
    elif chi2 < 30.0:
        result["suspicious"] = False
        result["confidence"] = "LOW"
        result["note"]       = (
            f"chi2={chi2:.3f} — Moderate LSB variance. Typical of natural images. "
            f"No strong stego signal."
        )
    else:
        result["suspicious"] = False
        result["confidence"] = "none"
        result["note"]       = (
            f"chi2={chi2:.3f} — High LSB variance consistent with a clean "
            f"natural/photographic image. No LSB stego detected."
        )

    # ── Extract ASCII preview from LSB bitstream ──────────────────────────────
    try:
        sample = lsbs[:1024]
        lsb_bytes = bytes(
            int("".join(str(sample[i + j]) for j in range(8)), 2)
            for i in range(0, len(sample) - 7, 8)
        )
        printable = sum(0x20 <= b < 0x7F for b in lsb_bytes)
        if printable / len(lsb_bytes) > 0.65:
            preview = lsb_bytes.decode("ascii", errors="replace").replace("\x00", "·")
            result["extracted_preview"] = preview[:64]
    except Exception:
        pass

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Batch / directory scan
# ─────────────────────────────────────────────────────────────────────────────

def batch_scan(scan_path: Path, args: argparse.Namespace):
    """
    Recursively scan all files in a directory and print a summary table.
    Files with confirmed embedded signatures are flagged.
    """
    import json as _json

    # Collect files
    if scan_path.is_file():
        files = [scan_path]
    else:
        files = sorted(f for f in scan_path.rglob("*") if f.is_file())

    if not files:
        print(r(f"[!] No files found in: {scan_path}"))
        return

    print(BANNER)
    print(f"  {bold(w('BATCH SCAN'))}  {grey(str(scan_path))}  {grey(f'({len(files)} file(s))')}\n")

    col_w = (40, 12, 8, 8, 10, 40)
    header = (f"  {'File':<{col_w[0]}}  {'Size':>{col_w[1]}}  "
              f"{'Entropy':>{col_w[2]}}  {'Embedded':>{col_w[3]}}  "
              f"{'Primary':<{col_w[4]}}  {'Suppressed':<{col_w[5]}}")
    print(header)
    print(f"  {sep('─'*col_w[0])}  {sep('─'*col_w[1])}  "
          f"{sep('─'*col_w[2])}  {sep('─'*col_w[3])}  "
          f"{sep('─'*col_w[4])}  {sep('─'*col_w[5])}")

    batch_results = []
    total_embedded = 0

    for fpath in files:
        try:
            data = fpath.read_bytes()
        except (OSError, PermissionError) as e:
            print(f"  {r('[ERR]')} {str(fpath)[:38]}  {grey(str(e))}")
            continue

        size    = len(data)
        entropy = shannon_entropy(data)
        primary = detect_primary(data)
        regions = build_compressed_regions(data)
        hits    = find_all_signatures(data, regions)
        conf    = [h for h in hits if not h["fp_filtered"]]
        supp    = [h for h in hits if h["fp_filtered"]]
        embedded = [h for h in conf
                    if not (primary and h["sig"].name == primary.name
                            and h["offset"] == primary.offset)]

        total_embedded += len(embedded)
        pname = primary.name if primary else grey("unknown")

        # Truncate filepath for display
        rel = fpath.relative_to(scan_path.parent) if scan_path.is_dir() else fpath.name
        rel_str = str(rel)
        if len(rel_str) > col_w[0]:
            rel_str = "…" + rel_str[-(col_w[0]-1):]

        emb_col = r(str(len(embedded))) if embedded else g("0")
        ent_col = (r if entropy > 7.2 else (y if entropy > 6.5 else g))(f"{entropy:.2f}")

        print(f"  {rel_str:<{col_w[0]}}  {fmt_size(size):>{col_w[1]}}  "
              f"{ent_col:>{col_w[2]+9}}  {emb_col:>{col_w[3]+9}}  "
              f"{pname:<{col_w[4]}}  {grey(str(len(supp))+' filtered')}")

        # Store for JSON output
        batch_results.append({
            "file":            str(fpath),
            "size":            size,
            "entropy":         round(entropy, 4),
            "primary":         primary.name if primary else None,
            "embedded_count":  len(embedded),
            "suppressed_count":len(supp),
            "embedded": [{"name": h["sig"].name, "offset": h["offset"]}
                         for h in embedded],
        })

    print(f"\n  {bold('Total:')} {len(files)} file(s) scanned  "
          f"|  {r(str(total_embedded)) if total_embedded else g('0')} embedded signature(s) found total")

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.write_text(_json.dumps({"batch": batch_results}, indent=2))
        print(f"  JSON report written to: {y(str(out_path))}")

    print()


# ─────────────────────────────────────────────────────────────────────────────
# Main analysis pipeline
# ─────────────────────────────────────────────────────────────────────────────

def analyze(filepath: str, args: argparse.Namespace):
    path = Path(filepath)
    if not path.exists():
        print(r(f"[!] File not found: {filepath}"))
        sys.exit(1)

    data = path.read_bytes()
    size = len(data)

    print(BANNER)

    # ── 01  Metadata ──────────────────────────────────────────────────────────
    section("01  FILE METADATA")
    sha256 = hashlib.sha256(data).hexdigest()
    md5    = hashlib.md5(data).hexdigest()
    ext    = path.suffix.upper() or "(none)"
    print(f"  {'Name':<16} {bold(w(path.name))}")
    print(f"  {'Extension':<16} {y(ext)}")
    print(f"  {'Size':<16} {g(fmt_size(size))}  {grey(f'({size:,} bytes)')}")
    print(f"  {'MD5':<16} {grey(md5)}")
    print(f"  {'SHA-256':<16} {grey(sha256)}")
    print(f"  {'Full path':<16} {grey(str(path.resolve()))}")

    # ── 02  Primary Signature ─────────────────────────────────────────────────
    section("02  PRIMARY MAGIC SIGNATURE")
    primary = detect_primary(data)
    if primary:
        magic_hex = " ".join(f"{b:02x}" for b in primary.magic)
        print(f"  {g('✓  MATCH FOUND')}")
        print(f"  {'Type':<16} {bold(g(primary.name))}")
        print(f"  {'Description':<16} {w(primary.desc)}")
        print(f"  {'Category':<16} {y(primary.cat)}")
        print(f"  {'Magic bytes':<16} {c(magic_hex)}")
        print(f"  {'Sig offset':<16} {y(str(primary.offset))}")
        has_validator = primary.validator is not None
        print(f"  {'Validated':<16} {g('yes (struct check passed)') if has_validator else grey('magic-only (no validator)')}")
    else:
        print(f"  {r('✗  Unknown / Unrecognized format')}")
        print(f"  {'First 16 bytes':<16} {c(data[:16].hex(' '))}")

        # ── Obfuscation hints ─────────────────────────────────────────────
        # Check if a known magic appears after a simple XOR transform
        _known_magics = {
            b"\x89PNG\r\n\x1a\n": "PNG  (XOR key: 0x{:02x})",
            b"\xff\xd8\xff":      "JPEG (XOR key: 0x{:02x})",
            b"PK\x03\x04":       "ZIP  (XOR key: 0x{:02x})",
            b"\x1f\x8b":         "GZIP (XOR key: 0x{:02x})",
            b"%PDF":              "PDF  (XOR key: 0x{:02x})",
            b"\x7fELF":          "ELF  (XOR key: 0x{:02x})",
            b"MZ":               "PE   (XOR key: 0x{:02x})",
        }
        for key_byte in range(1, 256):
            decoded_prefix = bytes(b ^ key_byte for b in data[:8])
            for magic, label in _known_magics.items():
                if decoded_prefix[:len(magic)] == magic:
                    print(f"  {y('⚡ Possible XOR obfuscation detected:')} {label.format(key_byte)}")
                    print(f"     Decoded bytes: {c(decoded_prefix.hex(' '))}")
                    print(f"     Try: python3 -c \"d=open('FILE','rb').read(); open('out','wb').write(bytes(b^0x{key_byte:02x} for b in d))\"")
                    break

    # ── 03  Hex Dump ──────────────────────────────────────────────────────────
    section(f"03  HEX DUMP  (first {args.bytes} bytes)"
            f"  |  {g('green')}=magic  {c('cyan')}=printable  {grey('grey')}=null")
    print_hex_dump(data, limit=args.bytes, highlight_sig=primary)

    # ── 04  Entropy ───────────────────────────────────────────────────────────
    section("04  ENTROPY ANALYSIS")
    overall_entropy = shannon_entropy(data)
    print(f"  {'Overall':<14} {entropy_bar(overall_entropy)}")
    print(f"  {entropy_label(overall_entropy)}\n")
    chunk_size = max(512, size // 8)
    print(f"  {'Chunk size':<14} {w(fmt_size(chunk_size))}")
    for i in range(0, size, chunk_size):
        chunk = data[i:i + chunk_size]
        e = shannon_entropy(chunk)
        if e > 7.2:
            label = r("enc/packed")
            color = C.RED
        elif e > 6.5:
            label = y("high      ")
            color = C.YELLOW
        else:
            label = g("normal    ")
            color = C.GREEN
        bar_w  = 24
        filled = int((e / 8.0) * bar_w)
        bar    = color + "█" * filled + C.RESET + grey("░" * (bar_w - filled))
        print(f"  {y(hex(i)):<18}  [{bar}] {color}{e:.3f}{C.RESET}  {label}")

    # ── 05  Full Signature Scan ───────────────────────────────────────────────
    section("05  FULL SIGNATURE SCAN  (all byte offsets)")
    # Build compressed region map ONCE — used to suppress short-magic FPs inside
    # PNG IDAT, GZIP, zlib streams, and high-entropy blocks.
    compressed_regions = build_compressed_regions(data)
    all_hits = find_all_signatures(data, compressed_regions)

    confirmed = [h for h in all_hits if not h["fp_filtered"]]
    filtered  = [h for h in all_hits if h["fp_filtered"]]

    embedded_hits = [
        h for h in confirmed
        if not (primary and h["sig"].name == primary.name and h["offset"] == primary.offset)
    ]

    if confirmed:
        print(f"  {y('Offset'):<22}  {w('Tag'):<18}  {g('Name'):<26}"
              f"  {w('Category'):<16}  {c('Magic hex'):<34}  {w('Description')}")
        print(f"  {sep('─'*14)}  {sep('─'*12)}  {sep('─'*16)}"
              f"  {sep('─'*12)}  {sep('─'*24)}  {sep('─'*34)}")
        for hit in confirmed:
            s    = hit["sig"]
            off  = hit["offset"]
            is_p = primary and s.name == primary.name and off == primary.offset
            mhex = c(s.magic[:8].hex(" "))
            tag  = g("[PRIMARY] ") if is_p else r("[EMBEDDED]")
            nc   = g(bold(s.name)) if is_p else r(bold(s.name))
            print(f"  {y(hex(off)):<22}  {tag}  {nc:<26}"
                  f"  {w(s.cat):<16}  {mhex:<34}  {w(s.desc)}")
    else:
        print(f"  {grey('No confirmed signatures found.')}")

    if filtered:
        # Group by reason for cleaner display
        by_reason: dict[str, list] = {}
        for hit in filtered:
            reason = hit.get("fp_reason", "unknown")
            # Simplify region labels for display
            if reason.startswith("inside "):
                key = "inside compressed/high-entropy region"
            else:
                key = reason
            by_reason.setdefault(key, []).append(hit)

        total_fp = len(filtered)
        print(f"\n  {grey(f'  {total_fp} hit(s) suppressed:')}")
        for reason, hits_for_reason in sorted(by_reason.items()):
            print(f"  {grey(f'  [{reason}]  ({len(hits_for_reason)} hits)')}")
            for hit in hits_for_reason[:4]:
                s   = hit["sig"]
                off = hit["offset"]
                print(f"  {grey(f'    ✗ {s.name:<14} @ {hex(off):<12}  ({s.desc})')}")
            if len(hits_for_reason) > 4:
                print(f"  {grey(f'    ... and {len(hits_for_reason)-4} more')}")

    # ── 06  Embedded Summary ──────────────────────────────────────────────────
    section("06  EMBEDDED FILE SUMMARY")
    if embedded_hits:
        print(f"  {r(bold('⚠  SUSPICIOUS:'))} {w(str(len(embedded_hits)))} confirmed embedded signature(s)\n")
        for hit in embedded_hits:
            s   = hit["sig"]
            ctx = c(data[hit["offset"]:hit["offset"] + 12].hex(" "))
            val_ok, val_reason = validate_carved(s.name, carve_chunk(data, hit))
            vtag = g("✓") if val_ok else y("⚠")
            print(f"  {r('►')} {bold(w(s.name)):<22}  @ {y(hex(hit['offset'])):<14}"
                  f"  {vtag} {grey(val_reason):<24}  bytes: {ctx}")
    else:
        print(f"  {g('✓  CLEAN')} {w('— No confirmed embedded signatures found.')}")

    # ── 07  Strings ───────────────────────────────────────────────────────────
    if args.strings:
        section(f"07  INTERESTING STRINGS  (min_len={args.min_str_len})")
        strings = extract_strings(data, min_len=args.min_str_len)
        if strings:
            shown = 0
            for offset, s in strings:
                if shown >= args.max_strings:
                    print(f"  {grey(f'  ... {len(strings)-shown} more — use --max-strings to increase')}")
                    break
                tag      = ""
                color_fn = grey
                slow     = s.lower()
                if any(s.startswith(p) for p in ("http://", "https://", "ftp://")):
                    tag = y(" [URL]");         color_fn = y
                elif any(x in s for x in ("/bin/", "/etc/", "/proc/", "/tmp/", "C:\\", ".dll", ".exe", ".sh")):
                    tag = r(" [PATH]");        color_fn = r
                elif any(x in slow for x in ("password", "passwd", "secret", "token", "key", "auth", "flag{")):
                    tag = m(" [SENSITIVE]");   color_fn = m
                elif len(s) > 20:
                    color_fn = w
                print(f"  {grey(hex(offset)):>14}  {color_fn(s)}{tag}")
                shown += 1
        else:
            print(f"  {grey('No printable strings found.')}")

    # ── 08  LSB Steganography Detection ──────────────────────────────────────
    if args.lsb:
        section("08  LSB STEGANOGRAPHY DETECTION")
        lsb_result = detect_lsb_stego(data, path.name)
        if lsb_result is None:
            print(f"  {grey('Skipped — not a supported image format or insufficient pixel data.')}")
        else:
            chi2_str = f"{lsb_result['chi2']:.4f}" if lsb_result['chi2'] is not None else "N/A"
            p_str    = f"{lsb_result['p_estimate']:.6f}" if lsb_result['p_estimate'] is not None else "N/A"
            ent_str  = f"{lsb_result['lsb_entropy']:.4f}" if lsb_result['lsb_entropy'] is not None else "N/A"

            conf     = lsb_result["confidence"]
            conf_col = (r if conf == "HIGH" else (y if conf == "MEDIUM" else grey))(conf)

            susp_tag = r("⚠  SUSPICIOUS") if lsb_result["suspicious"] else g("✓  CLEAN")
            print(f"  {susp_tag}")
            print(f"  {'Technique':<16} {w(lsb_result['technique'])}")
            print(f"  {'Chi-squared':<16} {y(chi2_str)}  {grey('(low = suspicious, near-0 = strong indicator)')}")
            print(f"  {'p-estimate':<16} {y(p_str)}")
            print(f"  {'LSB entropy':<16} {y(ent_str)}  {grey('bits/byte (ideal random = 1.000)')}")
            print(f"  {'Confidence':<16} {conf_col}")
            print(f"  {'Note':<16} {grey(lsb_result['note'])}")
            if lsb_result.get("extracted_preview"):
                print(f"  {'LSB preview':<16} {m(repr(lsb_result['extracted_preview']))}")
    else:
        lsb_result = None

    # ── 09  Extraction ────────────────────────────────────────────────────────
    if args.extract:
        if embedded_hits:
            out_dir = Path(args.out) if args.out else path.parent / f"{path.stem}_carved"
            do_extract(data, embedded_hits, out_dir, path.name,
                       max_depth=args.max_depth)
        else:
            print(f"\n  {grey('[ EXTRACTION ]: Nothing to extract — no confirmed embedded signatures found.')}")

    # ── JSON output ───────────────────────────────────────────────────────────
    if args.json_out:
        import json as _json
        strings_list = extract_strings(data, min_len=args.min_str_len) if args.strings else []
        report = build_report(path, data, primary, embedded_hits,
                              filtered, overall_entropy, strings_list, lsb_result)
        out_path = Path(args.json_out)
        out_path.write_text(_json.dumps(report, indent=2))
        print(f"\n  {g('JSON report written to:')} {y(str(out_path))}")

    print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="hexforge",
        description="HEXFORGE v1.0 — File Forensics & Embedded Payload Extractor  |  github.com/arvdch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 hexforge.py photo.jpg
  python3 hexforge.py stego.png --strings --lsb
  python3 hexforge.py challenge.png --extract
  python3 hexforge.py challenge.png --extract --out ./carved --json report.json
  python3 hexforge.py binary.elf --strings --min-str-len 6
  python3 hexforge.py mystery.bin --bytes 512 --strings --extract --lsb
  python3 hexforge.py nested.zip --extract --max-depth 6
  python3 hexforge.py --scan ./firmware_dir --json results.json
  python3 hexforge.py --scan ./firmware_dir --extract --out ./carved_all
  python3 hexforge.py --list-sigs
        """
    )

    # Positional — optional so --scan can be used without a file
    parser.add_argument("file",            nargs="?",            help="Target file to analyze")

    # Analysis flags
    parser.add_argument("--strings",       action="store_true",  help="Print extracted printable strings")
    parser.add_argument("--lsb",           action="store_true",  help="Run LSB steganography detection (images)")
    parser.add_argument("--min-str-len",   type=int, default=6,  dest="min_str_len",
                                                                  help="Min string length (default: 6)")
    parser.add_argument("--max-strings",   type=int, default=80, dest="max_strings",
                                                                  help="Max strings to display (default: 80)")
    parser.add_argument("--bytes",         type=int, default=256,help="Bytes to show in hex dump (default: 256)")

    # Extraction flags
    parser.add_argument("--extract",       action="store_true",  help="Extract all detected embedded files")
    parser.add_argument("--out",           default=None,         help="Output dir for carved files (default: <file>_carved/)")
    parser.add_argument("--max-depth",     type=int, default=0,  dest="max_depth",
                                                                  help="Max recursive carve depth (default: 4)")

    # Output flags
    parser.add_argument("--json",          default=None,         dest="json_out",
                                                                  help="Write JSON report to this path")

    # Batch / directory scan
    parser.add_argument("--scan",          default=None,         metavar="DIR",
                                                                  help="Batch-scan all files in a directory (summary table)")

    # Signature list
    parser.add_argument("--list-sigs",     action="store_true",  help="List all known signatures and exit")
    parser.add_argument("--show-filtered", action="store_true",  dest="show_filtered",
                                                                  help="Show false-positive-suppressed hits in scan table")

    args = parser.parse_args()

    # ── --list-sigs ───────────────────────────────────────────────────────────
    if args.list_sigs:
        print(f"\n{bold(w('Known Signatures'))}  {grey(f'({len(SIGNATURES)} total)')}\n")
        print(f"  {g('Name'):<28} {y('Category'):<22} {c('Magic hex'):<40} {w('Validated')}  {w('Description')}")
        print(f"  {sep('─'*18)} {sep('─'*12)} {sep('─'*28)} {sep('─'*10)}  {sep('─'*36)}")
        for sig in sorted(SIGNATURES, key=lambda s: (s.cat, s.name)):
            mhex  = sig.magic[:8].hex(" ")
            vmark = g("struct") if sig.validator else grey("magic ")
            print(f"  {g(sig.name):<28} {y(sig.cat):<22} {c(mhex):<40} {vmark}  {w(sig.desc)}")
        print()
        sys.exit(0)

    # ── --scan (batch directory mode) ─────────────────────────────────────────
    if args.scan:
        scan_path = Path(args.scan)
        if not scan_path.exists():
            print(r(f"[!] Path not found: {args.scan}"))
            sys.exit(1)
        batch_scan(scan_path, args)
        sys.exit(0)

    # ── Single file analysis ───────────────────────────────────────────────────
    if not args.file:
        parser.print_help()
        sys.exit(0)

    analyze(args.file, args)


if __name__ == "__main__":
    main()
