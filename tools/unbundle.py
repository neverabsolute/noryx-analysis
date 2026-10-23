#!/usr/bin/env python3
"""Extract the files embedded in a .NET single-file (singlefilehost) bundle.

Usage:
    python3 -I unbundle.py <bundle.exe> <output dir> [manifest offset in hex]

Normal .NET single-file executables carry a 32-byte marker (the SHA-256 of the
string ".net core bundle") immediately preceded by the 64-bit file offset of the
bundle manifest. Noryx.exe had that marker stripped, so this script also scans
the tail of the file for a plausible manifest header (major version 6 or 2,
minor 0, a sane file count, and a printable bundle id) and uses the first match.
You can also pass the offset explicitly as the third argument.
"""
import hashlib
import os
import re
import struct
import sys
import zlib

TYPES = {0: "Unknown", 1: "Assembly", 2: "NativeBinary", 3: "DepsJson",
         4: "RuntimeConfigJson", 5: "Symbols"}


def find_manifest(data: bytes) -> int:
    sig = hashlib.sha256(b".net core bundle").digest()
    i = data.find(sig)
    if i > 8:
        return struct.unpack_from("<q", data, i - 8)[0]
    # Marker missing: scan the last 64 MiB for a header-shaped record.
    start = max(0, len(data) - 64 * 1024 * 1024)
    for major in (6, 2, 1):
        pat = re.escape(struct.pack("<ii", major, 0))
        for m in re.finditer(pat, data[start:]):
            off = start + m.start()
            count = struct.unpack_from("<i", data, off + 8)[0]
            n = data[off + 12]
            if 0 < count < 5000 and 10 < n < 80:
                bid = data[off + 13:off + 13 + n]
                if all(32 <= c < 127 for c in bid):
                    return off
    raise SystemExit("bundle manifest not found; pass the offset explicitly")


def main() -> None:
    src, outdir = sys.argv[1], sys.argv[2]
    data = open(src, "rb").read()
    hdr = int(sys.argv[3], 16) if len(sys.argv) > 3 else find_manifest(data)
    print(f"manifest at {hdr:#x}")
    p = hdr

    def rd(fmt):
        nonlocal p
        v = struct.unpack_from(fmt, data, p)
        p += struct.calcsize(fmt)
        return v[0] if len(v) == 1 else v

    def rstr():
        nonlocal p
        n = shift = 0
        while True:
            b = data[p]
            p += 1
            n |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        s = data[p:p + n].decode("utf-8")
        p += n
        return s

    major, minor, count = rd("<i"), rd("<i"), rd("<i")
    bid = rstr()
    print(f"bundle version {major}.{minor}, {count} files, id {bid}")
    if major >= 2:
        rd("<qqqqq")  # deps.json / runtimeconfig offsets+sizes, flags
    entries = []
    for _ in range(count):
        off, size = rd("<q"), rd("<q")
        csize = rd("<q") if major >= 6 else 0
        t = data[p]
        p += 1
        entries.append((off, size, csize, t, rstr()))

    os.makedirs(outdir, exist_ok=True)
    for off, size, csize, t, rel in entries:
        blob = data[off:off + (csize or size)]
        if csize:
            blob = zlib.decompress(blob, -15)
        dst = os.path.join(outdir, rel.replace("\\", "/"))
        os.makedirs(os.path.dirname(dst) or outdir, exist_ok=True)
        with open(dst, "wb") as f:
            f.write(blob)
        print(f"{TYPES.get(t, t):18} {size:>10} {rel}")


if __name__ == "__main__":
    main()
