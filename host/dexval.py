#!/usr/bin/env python3
# darkdex v2 — dump validator / de-duper / reporter
#
# Snapshot carving, map_list recovery, ART-object walking and the JIT tracer all
# emit dex into one dir, with overlap. This validates each dump against the DEX
# structure, drops invalid/duplicate ones, ranks by class count, and (if baksmali
# is on PATH) smoke-tests that the winners actually disassemble.
#
#   dexval.py <dir> [--baksmali] [--keep-dups]
import sys, os, struct, hashlib, subprocess, shutil, glob

def u4(b,o): return struct.unpack_from("<I", b, o)[0]
def u2(b,o): return struct.unpack_from("<H", b, o)[0]

def parse(b):
    """Return dict of dex facts or None if not a structurally valid dex."""
    if len(b) < 0x70: return None
    magic = b[:8]
    if magic[:4] not in (b"dex\n", b"cdex"): return None
    if u4(b,40) != 0x12345678: return None                 # endian_tag
    fsz = u4(b,32); hsz = u4(b,36)
    if not (0x28 <= hsz <= 0x200): return None
    if not (hsz <= fsz <= len(b)+0x20): return None
    sids = u4(b,56); tids_sz=u4(b,64); tids_off=u4(b,68)
    cdefs = u4(b,96); cdefs_off=u4(b,100)
    if cdefs > 500000 or sids > 4000000: return None       # sanity
    # sample a few class descriptors via type_ids -> string_ids -> string data
    names=[]
    try:
        sids_off=u4(b,60)
        for i in range(min(tids_sz, 4000)):
            didx = u4(b, tids_off + i*4)
            if didx >= sids: continue
            soff = u4(b, sids_off + didx*4)
            # string_data: uleb size then MUTF8; skip uleb
            p=soff
            shift=0; v=0
            while True:
                x=b[p]; p+=1; v|=(x&0x7f)<<shift; shift+=7
                if not (x&0x80): break
            s=b[p:p+64].split(b"\x00")[0]
            if s.startswith(b"L") and s.endswith(b";"):
                names.append(s.decode("latin1"))
    except Exception:
        pass
    return dict(magic=magic[:4].decode("latin1"), fsz=fsz, classes=cdefs,
                strings=sids, types=tids_sz, names=names)

FRAMEWORK = ("Landroid/", "Ljava/", "Ljavax/", "Ldalvik/", "Lorg/apache/",
             "Lorg/json/", "Lcom/android/", "Lsun/", "Lorg/xml", "Ljunit/")
def app_score(info, hint):
    """rank app dex above framework: reward non-framework class descriptors and
    an explicit hint; framework dumps (android.*/java.*) sink to the bottom."""
    if not info: return -1
    names = info["names"]
    if not names: return info["classes"]        # unknown -> fall back to size
    app = sum(1 for n in names if not n.startswith(FRAMEWORK))
    fw  = len(names) - app
    frac = app / max(1, len(names))             # 0=all framework, 1=all app
    s = int(info["classes"] * frac) + app - fw // 4
    if hint:
        s += 500 * sum(1 for n in names if hint in n)
    return s

def main():
    if len(sys.argv) < 2:
        print("usage: dexval.py <dir> [--baksmali] [--keep-dups] [--hint sub]"); return 2
    d=sys.argv[1]
    baksmali = "--baksmali" in sys.argv
    keepdups = "--keep-dups" in sys.argv
    hint=None
    if "--hint" in sys.argv: hint=sys.argv[sys.argv.index("--hint")+1]

    files = sorted(glob.glob(os.path.join(d,"*.dex")) + glob.glob(os.path.join(d,"*.cdex")))
    seen={}; rows=[]; valid=0; invalid=0
    for f in files:
        b=open(f,"rb").read()
        info=parse(b)
        if not info: invalid+=1; continue
        valid+=1
        h=hashlib.sha1(b[0x20:]).hexdigest()   # skip checksum/sig region for dedup
        if not keepdups and h in seen:
            rows.append((f,info,seen[h],"dup")); continue
        seen[h]=f
        rows.append((f,info,None,"ok"))

    uniq=[r for r in rows if r[3]=="ok"]
    uniq.sort(key=lambda r: app_score(r[1],hint), reverse=True)
    print(f"# darkdex dexval — {d}")
    print(f"# {len(files)} files, {valid} valid, {invalid} invalid, {len(uniq)} unique\n")
    print(f"{'classes':>8} {'strings':>8} {'kind':>5}  file  (top app-class samples)")
    for f,info,_,_ in uniq:
        samp=[n for n in info["names"] if hint and hint in n][:3] or info["names"][:2]
        print(f"{info['classes']:8d} {info['strings']:8d} {info['magic']:>5}  {os.path.basename(f)}  {samp}")

    # write a manifest + copy winners to <dir>/best/
    best=os.path.join(d,"best"); os.makedirs(best,exist_ok=True)
    for i,(f,info,_,_) in enumerate(uniq[:12]):
        shutil.copy(f, os.path.join(best,f"best_{i:02d}_{info['classes']}c_{os.path.basename(f)}"))

    if baksmali and uniq:
        bk=shutil.which("baksmali")
        top=uniq[0][0]
        if bk:
            outd=os.path.join(d,"smali_top");
            r=subprocess.run([bk,"d",top,"-o",outd],capture_output=True,text=True)
            n=sum(len(fs) for _,_,fs in os.walk(outd))
            print(f"\n[baksmali] {os.path.basename(top)} -> {outd}  ({n} smali files, rc={r.returncode})")
        else:
            print("\n[baksmali] not on PATH; skipped")
    print(f"\nwinners copied to {best}/")
    return 0

if __name__=="__main__":
    sys.exit(main())
