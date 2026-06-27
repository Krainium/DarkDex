#!/usr/bin/env python3

import sys, struct, zipfile
def package(apk):
    d = zipfile.ZipFile(apk).read("AndroidManifest.xml")
    if d[0:2] != b"\x03\x00": return None
    o = 8
    n   = struct.unpack("<I", d[o+8:o+12])[0]
    fl  = struct.unpack("<I", d[o+16:o+20])[0]
    sst = struct.unpack("<I", d[o+20:o+24])[0]
    utf8 = bool(fl & 0x100)
    offs = struct.unpack("<%dI" % n, d[o+28:o+28+4*n])
    base = o + sst
    def s(i):
        if i is None or i < 0 or i >= n: return None
        p = base + offs[i]
        if utf8:
            cl = d[p]; p += 1
            if cl & 0x80: p += 1
            bl = d[p]; p += 1
            if bl & 0x80: bl = ((bl & 0x7f) << 8) | d[p]; p += 1
            return d[p:p+bl].decode("utf-8", "ignore")
        sl = struct.unpack("<H", d[p:p+2])[0]; p += 2
        if sl & 0x8000: sl = ((sl & 0x7fff) << 16) | struct.unpack("<H", d[p:p+2])[0]; p += 2
        return d[p:p+sl*2].decode("utf-16-le", "ignore")
    spsize = struct.unpack("<I", d[o+4:o+8])[0]
    p = o + spsize
    while p + 8 <= len(d):
        ctype = struct.unpack("<H", d[p:p+2])[0]
        csize = struct.unpack("<I", d[p+4:p+8])[0]
        if ctype == 0x0102:
            name_idx = struct.unpack("<I", d[p+20:p+24])[0]
            if s(name_idx) == "manifest":
                acount = struct.unpack("<H", d[p+28:p+30])[0]
                ab = p + 36
                for a in range(acount):
                    base_a = ab + a*20
                    aname = struct.unpack("<I", d[base_a+4:base_a+8])[0]
                    araw  = struct.unpack("<i", d[base_a+8:base_a+12])[0]
                    if s(aname) == "package":
                        return s(araw)
        p += csize if csize >= 8 else 8
    return None
if __name__ == "__main__":
    pk = package(sys.argv[1])
    print(pk if pk else "")
