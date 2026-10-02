#!/usr/bin/env python3
"""
Decrypt/extract an HSP3 DPM archive (DPMX signature), e.g. data.dpm from
ROCKMEN R2 (HSP3 "hsp3hg" runtime).

Ported directly from spihsp/src/axdpm/undpm32 (crypt.c, main.c, main.h),
the reference Susie-plugin source for the DPM format. Since ROCKMEN R2
loads the archive standalone via `chdpm "data.dpm"` (not embedded in the
.exe), each file's crypt key is stored directly in its DPMFILEDIR entry
in the archive header -- no external key file is required.

Usage:
    python extract_dpm.py data.dpm -o out_dir

Confirmed for ROCKMEN R2 (data.dpm): uses the HSP3.3+ crypt constant/order
(--hsp33 is the default here). Pass --no-hsp33 if targeting an older HSP3.2-
and-below game and output looks garbled.
"""
import argparse
import os
import struct
import sys

DPM_SIGNATURE = b"DPMX"

DPMHED_FMT = "<4sIII"          # sSignature, dwOffsetToDS, nNumberOfFile, dwReserved
DPMHED_SIZE = struct.calcsize(DPMHED_FMT)

DPMFILEDIR_FMT = "<16sIIII"    # sFileName, dwReserved, dwCryptKey, dwOffsetInDS, dwFileSize
DPMFILEDIR_SIZE = struct.calcsize(DPMFILEDIR_FMT)

CRYPT_DPMFILE_KEY_NOCRYPT = 0
CRYPT_DPMFILE_KEY_VER255 = 0x11223344
CRYPT_CRYPT_KEY_VER255 = (0x01 << 8) | 0x55  # MAKEWORD(0x55, 0x01)

CRYPT_EXE_KEY_DEFAULT = (0x55 << 8) | 0xAA   # MAKEWORD(0xAA, 0x55)


def lobyte(w):
    return w & 0xFF


def hibyte(w):
    return (w >> 8) & 0xFF


def loword(dw):
    return dw & 0xFFFF


def hiword(dw):
    return (dw >> 16) & 0xFFFF


def makeword(lo, hi):
    return (lo & 0xFF) | ((hi & 0xFF) << 8)


def makelong(lo_word, hi_word):
    return (lo_word & 0xFFFF) | ((hi_word & 0xFFFF) << 16)


class DpmCrypt:
    def __init__(self, hsp33=False):
        self.hsp33 = hsp33
        if hsp33:
            self.prm1 = 0x5A
            self.prm2 = 0xA5
        else:
            self.prm1 = 0x55
            self.prm2 = 0xAA

    def make_dpm_key(self, dpm_file_key):
        lo_w = loword(dpm_file_key)
        hi_w = hiword(dpm_file_key)
        b1 = ((lobyte(lo_w) + self.prm1) & 0xFF) ^ lobyte(hi_w)
        b2 = ((hibyte(lo_w) + self.prm2) & 0xFF) ^ hibyte(hi_w)
        return makeword(b1, b2)

    def make_crypt_key(self, dpm_key, exe_key, use_exe_key):
        if not use_exe_key:
            exe_key = CRYPT_EXE_KEY_DEFAULT
        k1 = (lobyte(dpm_key) + lobyte(exe_key)) & 0xFF
        k2 = (hibyte(dpm_key) + hibyte(exe_key)) & 0xFF
        return makeword(k1, k2)

    def make_dpm_file_key(self, crypt_key):
        k1 = 0
        k2 = 0
        k3 = ((lobyte(crypt_key) - lobyte(CRYPT_EXE_KEY_DEFAULT)) & 0xFF) ^ ((k1 + self.prm1) & 0xFF)
        k4 = ((hibyte(crypt_key) - hibyte(CRYPT_EXE_KEY_DEFAULT)) & 0xFF) ^ ((k2 + self.prm2) & 0xFF)
        return makelong(makeword(k1, k2), makeword(k3, k4))

    def decrypt(self, data, dpm_file_key, decode_seed=0):
        if dpm_file_key == CRYPT_DPMFILE_KEY_NOCRYPT:
            return bytes(data)

        crypt_key = self.make_crypt_key(self.make_dpm_key(dpm_file_key), 0, False)
        k1 = lobyte(crypt_key)
        k2 = hibyte(crypt_key)

        out = bytearray(len(data))
        by_data = decode_seed & 0xFF
        if self.hsp33:
            for i, b in enumerate(data):
                by_data = (by_data + ((b ^ k1) - k2)) & 0xFF
                out[i] = by_data
        else:
            for i, b in enumerate(data):
                by_data = (by_data + ((b - k2) ^ k1)) & 0xFF
                out[i] = by_data
        return bytes(out)


class DpmFileDir:
    __slots__ = ("filename", "reserved", "crypt_key", "offset_in_ds", "file_size")

    def __init__(self, raw):
        name, reserved, crypt_key, offset_in_ds, file_size = struct.unpack(DPMFILEDIR_FMT, raw)
        self.filename = name.split(b"\x00", 1)[0].decode("cp932", errors="replace")
        self.reserved = reserved
        self.crypt_key = crypt_key
        self.offset_in_ds = offset_in_ds
        self.file_size = file_size


def parse_dpm(buf):
    if len(buf) < DPMHED_SIZE:
        raise ValueError("File too small to be a DPM archive")

    sig, offset_to_ds, num_files, _reserved = struct.unpack(DPMHED_FMT, buf[:DPMHED_SIZE])
    if sig != DPM_SIGNATURE:
        raise ValueError(f"Bad signature: {sig!r} (expected {DPM_SIGNATURE!r})")

    entries = []
    pos = DPMHED_SIZE
    for _ in range(num_files):
        raw = buf[pos:pos + DPMFILEDIR_SIZE]
        if len(raw) < DPMFILEDIR_SIZE:
            raise ValueError("Truncated file directory table")
        entries.append(DpmFileDir(raw))
        pos += DPMFILEDIR_SIZE

    return offset_to_ds, entries


def adjust_crypt_key(entries, crypt, executable=False):
    """Mirrors UnDpmAdjustCryptKey: rewrites keys for older archive versions.
    For a standalone (non-exe) archive using the modern HSP2.6+ layout this
    is a no-op -- each entry's stored dwCryptKey is already the final key.
    """
    encrypted = [e for e in entries if e.crypt_key != CRYPT_DPMFILE_KEY_NOCRYPT]
    if not encrypted:
        return  # HSP2.x, nothing encrypted

    is_old_crypt = all(e.crypt_key == CRYPT_DPMFILE_KEY_VER255 for e in encrypted)
    if is_old_crypt:
        fixed_key = crypt.make_dpm_file_key(CRYPT_CRYPT_KEY_VER255)
        for e in encrypted:
            e.crypt_key = fixed_key
    # else: HSP2.6+, only exe-embedded archives get rewritten; standalone
    # archives (loaded via chdpm) keep their stored per-file key as-is.


MAGIC_EXT = [
    (b"BM", ".bmp"),
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"\xff\xd8\xff", ".jpg"),
    (b"GIF8", ".gif"),
    (b"RIFF", ".wav"),
    (b"OggS", ".ogg"),
    (b"fLaC", ".flac"),
    (b"MThd", ".mid"),
    (b"ID3", ".mp3"),
    (b"\x00\x00\x01\x00", ".ico"),
]


def guess_ext(data):
    for magic, ext in MAGIC_EXT:
        if data.startswith(magic):
            return ext
    printable = sum(1 for b in data[:512] if 9 <= b <= 13 or 32 <= b <= 126)
    if data[:512] and printable / len(data[:512]) > 0.9:
        return ".txt"
    return ".bin"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dpm_file", help="Path to data.dpm")
    ap.add_argument("-o", "--out-dir", default="dpm_extracted", help="Output directory")
    ap.add_argument("--no-hsp33", dest="hsp33", action="store_false",
                     help="Use pre-HSP3.3 crypt constants/order instead of the (default) HSP3.3+ ones")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.set_defaults(hsp33=True)
    args = ap.parse_args()

    with open(args.dpm_file, "rb") as f:
        buf = f.read()

    offset_to_ds, entries = parse_dpm(buf)
    crypt = DpmCrypt(hsp33=args.hsp33)
    adjust_crypt_key(entries, crypt, executable=False)

    os.makedirs(args.out_dir, exist_ok=True)

    used_names = {}
    for idx, e in enumerate(entries, start=1):
        start = offset_to_ds + e.offset_in_ds
        raw = buf[start:start + e.file_size]
        data = crypt.decrypt(raw, e.crypt_key)

        base_name = e.filename or f"file_{idx:04d}"
        if "." not in base_name:
            base_name += guess_ext(data)

        n = used_names.get(base_name, 0)
        used_names[base_name] = n + 1
        out_name = base_name if n == 0 else f"{base_name}.{n}"

        out_path = os.path.join(args.out_dir, out_name)
        with open(out_path, "wb") as out_f:
            out_f.write(data)

        if args.verbose:
            enc = "enc" if e.crypt_key else "raw"
            print(f"[{idx:4d}/{len(entries)}] {out_name:30s} {e.file_size:8d} bytes ({enc}, key=0x{e.crypt_key:08X})")

    print(f"Extracted {len(entries)} files to {args.out_dir}")


if __name__ == "__main__":
    main()
